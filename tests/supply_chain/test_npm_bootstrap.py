"""Trusted, digest-pinned npm CI bootstrap (A3 final).

The workflow bootstrap no longer runs ``npm i -g npm@12.0.2`` (version-exact but
still trusting registry METADATA to resolve the tarball). It runs
``scripts/ci/install-npm-pinned.mjs``, which downloads the EXACT canonical
tarball, follows only bounded redirects to approved hosts, verifies the sha256
over the downloaded bytes BEFORE any install, then installs the LOCAL verified
tarball with ``npm -g --ignore-scripts --offline``.

These tests:
  * validate ``supply-chain/npm-bootstrap.json`` against ``nix/npm-12-0-2.nix``
    (one source of truth: the Nix ``sha256-<base64>`` SRI decodes to the same
    hex; version + url match);
  * drive the REAL Node installer against a local HTTP server: correct bytes ->
    verified + installs the local tgz offline via a stub npm; wrong bytes ->
    rejected with NO install; a redirect to a non-approved host -> rejected with
    NO install; a redirect to an approved host -> ok;
  * assert the scanner rejects a direct global ``npm@`` registry install and the
    workflows use the trusted installer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "scripts" / "ci"))
import check_supply_chain as C  # noqa: E402

_INSTALLER = _REPO / "scripts" / "ci" / "install-npm-pinned.mjs"
_IDENTITY = _REPO / "supply-chain" / "npm-bootstrap.json"
_NIX = _REPO / "nix" / "npm-12-0-2.nix"
_NODE = shutil.which("node")

_GOOD = b"this-is-a-fake-npm-tarball-payload-for-tests\n" * 16
_GOOD_SHA = hashlib.sha256(_GOOD).hexdigest()


def _identity() -> dict:
    return json.loads(_IDENTITY.read_text(encoding="utf-8"))


# ── one source of truth: JSON validated against Nix ─────────────────────────


def test_identity_matches_nix_digest_version_url():
    ident = _identity()
    nix = _NIX.read_text(encoding="utf-8")

    ver = re.search(r'version\s*=\s*"([^"]+)"', nix).group(1)
    assert ident["version"] == ver

    # nix url uses ${version}; json url is the concrete canonical url.
    assert "registry.npmjs.org/npm/-/npm-${version}.tgz" in nix
    assert ident["url"] == f"https://registry.npmjs.org/npm/-/npm-{ver}.tgz"

    sri = re.search(r'hash\s*=\s*"sha256-([^"]+)"', nix).group(1)
    hex_from_nix = base64.b64decode(sri).hex()
    assert hex_from_nix == ident["digest"]["value"].lower()
    assert ident["canonical_hosts"] == ["registry.npmjs.org"]


# ── local fixture server ────────────────────────────────────────────────────


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/good.tgz":
            self.send_response(200)
            self.send_header("Content-Length", str(len(_GOOD)))
            self.end_headers()
            self.wfile.write(_GOOD)
        elif self.path == "/wrong.tgz":
            body = b"WRONG-BYTES"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/redirect-bad":
            self.send_response(302)
            self.send_header("Location", "http://evil.invalid/x.tgz")
            self.end_headers()
        elif self.path == "/redirect-good":
            self.send_response(302)
            self.send_header("Location", "/good.tgz")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):  # silence
        pass


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()


def _stub_npm(tmp_path: Path) -> tuple[Path, Path]:
    """A cross-platform stub npm that records its argv, so tests can assert the
    exact install command without installing anything."""
    argsfile = tmp_path / "npm_args.txt"
    if os.name == "nt":
        stub = tmp_path / "npm.cmd"
        stub.write_text(f'@echo %*> "{argsfile}"\r\n', encoding="ascii")
    else:
        stub = tmp_path / "npm.sh"
        stub.write_text(f'#!/bin/sh\necho "$@" > "{argsfile}"\n', encoding="ascii")
        stub.chmod(0o755)
    return stub, argsfile


def _run_installer(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_NODE, str(_INSTALLER), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


pytestmark = pytest.mark.skipif(_NODE is None, reason="node unavailable")


def test_correct_fixture_verifies_and_installs_local_tgz_offline(server, tmp_path):
    stub, argsfile = _stub_npm(tmp_path)
    r = _run_installer(
        "--url", f"{server}/good.tgz",
        "--sha256", _GOOD_SHA,
        "--host", "127.0.0.1",
        "--npm", str(stub),
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert argsfile.exists(), "installer did not invoke npm on the verified tarball"
    recorded = argsfile.read_text(encoding="utf-8", errors="replace")
    # installs the LOCAL tarball, offline, no lifecycle scripts, globally
    assert "install" in recorded and "-g" in recorded
    assert "--ignore-scripts" in recorded
    assert "--offline" in recorded
    assert ".tgz" in recorded  # a local tarball path, never `npm@<spec>`
    assert "npm@" not in recorded


def test_wrong_bytes_rejected_no_install(server, tmp_path):
    stub, argsfile = _stub_npm(tmp_path)
    r = _run_installer(
        "--url", f"{server}/wrong.tgz",
        "--sha256", _GOOD_SHA,  # expect good, server sends wrong
        "--host", "127.0.0.1",
        "--npm", str(stub),
    )
    assert r.returncode != 0
    assert "sha256 mismatch" in r.stderr.lower()
    assert not argsfile.exists(), "npm must NOT run when the digest mismatches"


def test_redirect_to_unapproved_host_rejected_no_install(server, tmp_path):
    stub, argsfile = _stub_npm(tmp_path)
    r = _run_installer(
        "--url", f"{server}/redirect-bad",
        "--sha256", _GOOD_SHA,
        "--host", "127.0.0.1",
        "--npm", str(stub),
    )
    assert r.returncode != 0
    assert "approved" in r.stderr.lower()
    assert "evil.invalid" in r.stderr
    assert not argsfile.exists()


def test_redirect_to_approved_host_is_followed(server, tmp_path):
    stub, argsfile = _stub_npm(tmp_path)
    r = _run_installer(
        "--url", f"{server}/redirect-good",  # -> /good.tgz (same approved host)
        "--sha256", _GOOD_SHA,
        "--host", "127.0.0.1",
        "--npm", str(stub),
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert argsfile.exists()


def test_verify_only_writes_tarball_and_skips_install(server, tmp_path):
    out = tmp_path / "npm.tgz"
    stub, argsfile = _stub_npm(tmp_path)
    r = _run_installer(
        "--url", f"{server}/good.tgz",
        "--sha256", _GOOD_SHA,
        "--host", "127.0.0.1",
        "--npm", str(stub),
        "--out", str(out),
        "--verify-only",
    )
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert out.read_bytes() == _GOOD
    assert not argsfile.exists(), "verify-only must not install"


def test_scheme_host_policy(tmp_path):
    """https required off-loopback; http allowed only on loopback; unapproved
    host rejected. Exercises the real isApprovedTarget()."""
    harness = tmp_path / "h.mjs"
    harness.write_text(
        "import { isApprovedTarget } from " + json.dumps(_INSTALLER.as_uri()) + "\n"
        "const ok = (u, h) => isApprovedTarget(new URL(u), h)\n"
        "console.log(JSON.stringify({\n"
        '  https_registry: ok("https://registry.npmjs.org/x", ["registry.npmjs.org"]),\n'
        '  http_registry: ok("http://registry.npmjs.org/x", ["registry.npmjs.org"]),\n'
        '  http_loopback: ok("http://127.0.0.1/x", ["127.0.0.1"]),\n'
        '  unapproved: ok("https://evil.invalid/x", ["registry.npmjs.org"]),\n'
        "}))\n",
        encoding="utf-8",
    )
    r = subprocess.run([_NODE, str(harness)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout.strip().splitlines()[-1])
    assert d["https_registry"] is True
    assert d["http_registry"] is False  # https required off-loopback
    assert d["http_loopback"] is True
    assert d["unapproved"] is False


# ── scanner + workflows ─────────────────────────────────────────────────────


def test_scanner_rejects_direct_global_npm_registry_install():
    assert C._npm_command_offenses("npm i -g npm@12.0.2")  # even exact -> flagged
    assert C._npm_command_offenses("npm i -g --ignore-scripts npm@12.0.2")
    assert C._npm_command_offenses("npm install --global npm@12")
    msg = " ".join(C._npm_command_offenses("npm i -g npm@12.0.2"))
    assert "install-npm-pinned.mjs" in msg
    # the trusted installer's own command (LOCAL tarball) is NOT flagged
    assert C._npm_command_offenses(
        "npm install -g --ignore-scripts --offline /tmp/npm-12.0.2.tgz"
    ) == []
    assert C._npm_command_offenses("node scripts/ci/install-npm-pinned.mjs") == []


def test_workflows_use_trusted_installer_not_direct_registry():
    import yaml

    wf_dir = _REPO / ".github" / "workflows"
    findings = C.Findings()
    C.scan_workflow_npm(_REPO, findings)
    assert findings.ok(), "workflow npm findings:\n" + "\n".join(findings.errors)

    saw_bootstrap = False
    for wf in wf_dir.glob("*.yml"):
        for cmd in C._iter_yaml_command_strings(yaml.safe_load(wf.read_text(encoding="utf-8"))):
            assert not re.search(r"\bnpm@\d", cmd), f"{wf.name} still installs npm@ directly: {cmd}"
            if "install-npm-pinned.mjs" in cmd:
                saw_bootstrap = True
    assert saw_bootstrap, "expected a workflow to call the trusted npm installer"
