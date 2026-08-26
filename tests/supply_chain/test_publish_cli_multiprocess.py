"""A6 (Desktop routing): TRUE multiprocess tests for the shared publication CLI.

The desktop build (JS) routes the Electron/get-windows FINAL publication through
``python -m hermes_cli.supply_chain.publish_cli`` — the shared kernel-locked
(fcntl.flock / msvcrt.locking) transaction — instead of a JS O_EXCL file lock.
These tests spawn REAL OS processes of that CLI (not threads) against the REAL
in-repo manifest's ``electron`` component, and prove:

  * fresh-install persistence — the anti-rollback state is created OUTSIDE
    node_modules and the high-water advances (survives the process boundary);
  * a digest MISMATCH fails closed — the target is never published, the
    high-water never advances;
  * a replay/downgrade (state high-water already ABOVE the manifest sequence)
    fails closed — an old publisher cannot overwrite a newer install;
  * cross-process MUTUAL EXCLUSION — two real processes publishing under one
    shared state lock never corrupt the state;
  * a DEAD lock holder is reclaimed by the KERNEL — a killed holder does not
    deadlock the next publisher (the removed JS lock needed a PID-liveness
    heuristic + an inode unlink for this; the kernel lock does not).

No mocks: the CLI, the transaction, and the kernel lock all run for real.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI = "hermes_cli.supply_chain.publish_cli"


def _electron_win_x64_digest() -> str:
    from hermes_cli.supply_chain.manifest import load_manifest

    manifest = load_manifest(REPO_ROOT / "supply-chain" / "manifest.json")
    art = manifest.component("electron").artifact("windows", "x86_64")
    return str(art.digest.value)


def _env() -> dict:
    env = dict(os.environ)
    # Ensure the in-repo package is importable in the child regardless of cwd.
    env["PYTHONPATH"] = os.pathsep.join([str(REPO_ROOT), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    return env


def _stage(tmp_path: Path, name: str = "stage", content: bytes = b"electron-tree") -> Path:
    d = tmp_path / name
    d.mkdir()
    (d / "electron.bin").write_bytes(content)
    return d


def _run_cli(*, staged_dir: Path, target: Path, state: Path, staged_sha256: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            CLI,
            "--component",
            "electron",
            "--platform",
            "windows",
            "--arch",
            "x86_64",
            "--staged-dir",
            str(staged_dir),
            "--staged-sha256",
            staged_sha256,
            "--target",
            str(target),
            "--state",
            str(state),
        ],
        cwd=str(REPO_ROOT),
        env=_env(),
        capture_output=True,
        text=True,
    )


def _verdict(proc: subprocess.CompletedProcess) -> dict:
    line = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()][-1]
    return json.loads(line)


# ── fresh-install persistence (state OUTSIDE node_modules) ──────────────────


def test_fresh_install_publishes_and_persists_state(tmp_path):
    digest = _electron_win_x64_digest()
    state = tmp_path / "supply-chain" / "state.json"
    target = tmp_path / "dist"
    proc = _run_cli(staged_dir=_stage(tmp_path), target=target, state=state, staged_sha256=digest)

    assert proc.returncode == 0, proc.stderr + proc.stdout
    v = _verdict(proc)
    assert v["ok"] and v["published"] and v["committed"]
    # the staged tree is now the live target
    assert (target / "electron.bin").read_bytes() == b"electron-tree"
    # the anti-rollback state was created (outside any node_modules) and advanced
    assert state.exists()
    st = json.loads(state.read_text())
    assert st["components"]["electron"] == "41.10.3"
    assert st["manifest_sequence"] == 1


def test_digest_mismatch_fails_closed(tmp_path):
    state = tmp_path / "state.json"
    target = tmp_path / "dist"
    proc = _run_cli(
        staged_dir=_stage(tmp_path), target=target, state=state, staged_sha256="0" * 64
    )
    assert proc.returncode != 0
    v = _verdict(proc)
    assert v["ok"] is False
    assert not target.exists(), "a wrong-digest publish must never create the target"
    assert not state.exists(), "the high-water must not advance on a failed publish"


def test_replay_downgrade_fails_closed(tmp_path):
    """A stale publisher — the recorded high-water is ABOVE the manifest
    sequence — is refused (an old install cannot overwrite a newer one)."""
    digest = _electron_win_x64_digest()
    state = tmp_path / "state.json"
    # Machine already at sequence 5 (the manifest is sequence 1 → a replay).
    state.write_text(json.dumps({"manifest_sequence": 5, "components": {"electron": "41.10.3"}}))
    target = tmp_path / "dist"

    proc = _run_cli(staged_dir=_stage(tmp_path), target=target, state=state, staged_sha256=digest)
    assert proc.returncode != 0
    v = _verdict(proc)
    assert v["ok"] is False
    assert not target.exists()
    # high-water unchanged
    assert json.loads(state.read_text())["manifest_sequence"] == 5


# ── cross-process mutual exclusion (real processes, one shared state) ────────


def test_two_processes_share_one_state_without_corruption(tmp_path):
    digest = _electron_win_x64_digest()
    state = tmp_path / "state.json"
    p1 = subprocess.Popen(
        [
            sys.executable, "-m", CLI, "--component", "electron", "--platform", "windows",
            "--arch", "x86_64", "--staged-dir", str(_stage(tmp_path, "s1")),
            "--staged-sha256", digest, "--target", str(tmp_path / "d1"), "--state", str(state),
        ],
        cwd=str(REPO_ROOT), env=_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    p2 = subprocess.Popen(
        [
            sys.executable, "-m", CLI, "--component", "electron", "--platform", "windows",
            "--arch", "x86_64", "--staged-dir", str(_stage(tmp_path, "s2")),
            "--staged-sha256", digest, "--target", str(tmp_path / "d2"), "--state", str(state),
        ],
        cwd=str(REPO_ROOT), env=_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    p1.communicate(timeout=60)
    p2.communicate(timeout=60)
    # At least one published; the shared state is well-formed (never a torn write
    # from two processes racing the read-modify-write).
    assert p1.returncode == 0 or p2.returncode == 0
    st = json.loads(state.read_text())
    assert st["manifest_sequence"] == 1
    assert st["components"]["electron"] == "41.10.3"


# ── dead holder reclaimed by the kernel (no stale-file deadlock) ─────────────


def test_dead_lock_holder_is_reclaimed_by_the_kernel(tmp_path):
    digest = _electron_win_x64_digest()
    state = tmp_path / "state.json"
    ready = tmp_path / "holder-ready"

    holder_src = (
        "import sys, time\n"
        "from pathlib import Path\n"
        "from hermes_cli.supply_chain.state import _cross_process_lock\n"
        f"anchor = Path(r'{state}')\n"
        "with _cross_process_lock(anchor):\n"
        f"    Path(r'{ready}').write_text('1')\n"
        "    time.sleep(30)\n"
    )
    holder = subprocess.Popen(
        [sys.executable, "-c", holder_src], cwd=str(REPO_ROOT), env=_env(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while not ready.exists() and time.monotonic() < deadline:
            if holder.poll() is not None:
                out, err = holder.communicate()
                pytest.fail(f"lock holder exited early: {err or out}")
            time.sleep(0.05)
        assert ready.exists(), "the holder never acquired the lock"
        # Kill the holder WHILE it holds the lock. The kernel releases the
        # advisory lock when the process dies; the next publisher must proceed
        # (a stale lock FILE remains on disk but is never a deadlock).
        holder.kill()
        holder.wait(timeout=20)
    finally:
        if holder.poll() is None:
            holder.kill()

    proc = _run_cli(staged_dir=_stage(tmp_path), target=tmp_path / "dist", state=state, staged_sha256=digest)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert _verdict(proc)["published"] is True
    # the lock file is NOT unlinked (kernel-lock semantics) — its presence is fine
    assert (state.parent / (state.name + ".lock")).exists()


def test_unusable_state_location_fails_closed_and_preserves_install(tmp_path):
    """A state path whose parent is not a usable directory makes the transaction
    fail (it cannot take the lock / write the high-water). The publish fails
    CLOSED and the pre-existing install is preserved — a build never ships an
    artifact whose anti-rollback high-water could not be committed."""
    digest = _electron_win_x64_digest()
    # `notadir` is a FILE, so `<notadir>/state.json[.lock]` cannot be created.
    not_a_dir = tmp_path / "notadir"
    not_a_dir.write_text("i am a file")
    state = not_a_dir / "state.json"

    target = tmp_path / "dist"
    target.mkdir()
    (target / "electron.bin").write_bytes(b"OLD-WORKING")

    proc = _run_cli(
        staged_dir=_stage(tmp_path, content=b"NEW-PAYLOAD"),
        target=target,
        state=state,
        staged_sha256=digest,
    )
    assert proc.returncode != 0
    assert _verdict(proc)["ok"] is False
    # the previous working install is intact — the failed publish did not swap it
    assert (target / "electron.bin").read_bytes() == b"OLD-WORKING"
