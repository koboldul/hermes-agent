"""Behavioral tests for the supply-chain hardening of the managed-Node heal.

The pure archive-member validation and digest helpers are covered
host-independently in test_publish.py. Here we assert the *integration*: the
Windows heal path verifies a pinned digest before extraction, rejects a
malicious archive before extraction, and refuses a tree missing its expected
executables — always leaving the live tree intact. These call the real Windows
runtime path, so they are marked windows_only per the repo's host-OS testing
rule; arch is supplied as data via PROCESSOR_ARCHITECTURE.
"""

from __future__ import annotations

import hashlib
import io
import urllib.request
import zipfile

import pytest

import hermes_constants


class _FakeResp:
    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._payload


def _win_root(major: int) -> str:
    return f"node-v{major}.5.1-win-x64"


def _clean_zip(major: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        root = _win_root(major)
        archive.writestr(f"{root}/node.exe", b"fake-node")
        archive.writestr(f"{root}/npm.cmd", "@echo off\r\n")
    return buf.getvalue()


def _node_only_zip(major: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(f"{_win_root(major)}/node.exe", b"fake-node")
    return buf.getvalue()


def _traversal_zip(major: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(f"{_win_root(major)}/../evil.exe", b"pwned")
    return buf.getvalue()


def _stub_env(monkeypatch, home, zip_bytes, sc_config=None):
    major = hermes_constants._HERMES_NODE_TARGET_MAJOR
    zip_name = f"{_win_root(major)}.zip"
    monkeypatch.setenv("PROCESSOR_ARCHITECTURE", "AMD64")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_NODE_TARGET_MAJOR", str(major))
    # Exercise the download/stage/swap mechanics: explicit compatibility opt-in
    # (the secure default disables the mutable nodejs.org download). The Python
    # gate is config-only, so opt in via the scoped allow-list, not an env var.
    if sc_config is not None:
        sc_config["allow_unverified_components"] = ["node"]
    monkeypatch.setattr(hermes_constants, "_managed_node_heal_attempted", False)
    monkeypatch.setattr(hermes_constants, "_managed_node_in_use_notice_printed", False)
    monkeypatch.setattr(hermes_constants, "_managed_node_fail_closed_notice_printed", False)
    monkeypatch.setattr(hermes_constants, "managed_node_tree_in_use", lambda _home=None: False)
    monkeypatch.setattr(hermes_constants, "node_tool_runnable", lambda path: True)

    index_html = f'<a href="./{zip_name}">{zip_name}</a>'.encode()

    def fake_urlopen(url, timeout=0):
        if str(url).endswith(".zip"):
            return _FakeResp(zip_bytes)
        return _FakeResp(index_html)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)


def _seed_live_tree(home):
    live = home / "node"
    live.mkdir(parents=True)
    (live / "node.exe").write_text("old", encoding="utf-8")
    (live / "npm.cmd").write_text("@echo off", encoding="utf-8")
    return live


# --- host-independent: chokepoint wiring ----------------------------------

def test_committed_manifest_pins_no_node_digest_yet():
    """The committed manifest keeps Node transport-trusted (no pinned digest),
    so a compatibility download is unverified today."""
    assert hermes_constants._expected_node_archive_digest("windows", "x64") is None
    assert hermes_constants._expected_node_archive_digest("windows", "arm64") is None


def test_node_download_disabled_by_default(monkeypatch):
    monkeypatch.delenv("HERMES_ALLOW_UNVERIFIED_BOOTSTRAP", raising=False)
    monkeypatch.delenv("HERMES_SUPPLY_CHAIN_ENFORCE", raising=False)
    assert hermes_constants._managed_node_download_allowed() is False


def test_node_download_allowed_only_on_opt_in(sc_config):
    sc_config["allow_unverified_components"] = ["node"]
    assert hermes_constants._managed_node_download_allowed() is True


def test_node_opt_in_is_scoped(sc_config):
    # Allowing an unrelated component must NOT enable the Node download.
    sc_config["allow_unverified_components"] = ["uv"]
    assert hermes_constants._managed_node_download_allowed() is False


@pytest.mark.windows_only
def test_heal_fails_closed_by_default_no_download(tmp_path, monkeypatch):
    monkeypatch.delenv("HERMES_ALLOW_UNVERIFIED_BOOTSTRAP", raising=False)
    monkeypatch.delenv("HERMES_SUPPLY_CHAIN_ENFORCE", raising=False)
    home = tmp_path / "hermes"
    live = _seed_live_tree(home)
    monkeypatch.setenv("PROCESSOR_ARCHITECTURE", "AMD64")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(hermes_constants, "managed_node_tree_in_use", lambda _home=None: False)
    monkeypatch.setattr(hermes_constants, "_managed_node_fail_closed_notice_printed", False)

    def forbidden(url, timeout=0):
        raise AssertionError("no network download may occur under the secure default")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)

    result = hermes_constants._heal_managed_node_windows()
    assert result is False
    assert (live / "node.exe").read_text(encoding="utf-8") == "old"  # untouched


# --- windows runtime integration (compat opt-in exercises mechanics) -------

@pytest.mark.windows_only
def test_digest_mismatch_refuses_extraction_and_preserves_tree(tmp_path, monkeypatch, sc_config):
    home = tmp_path / "hermes"
    live = _seed_live_tree(home)
    zip_bytes = _clean_zip(hermes_constants._HERMES_NODE_TARGET_MAJOR)
    _stub_env(monkeypatch, home, zip_bytes, sc_config)
    monkeypatch.setattr(hermes_constants, "_expected_node_archive_digest", lambda p, a: "0" * 64)

    result = hermes_constants._heal_managed_node_windows()

    assert result is False
    assert (live / "node.exe").read_text(encoding="utf-8") == "old"  # untouched
    assert list(home.glob("node.new-*")) == []
    assert list(home.glob("node.old-*")) == []


@pytest.mark.windows_only
def test_digest_match_allows_heal(tmp_path, monkeypatch, sc_config):
    home = tmp_path / "hermes"
    _seed_live_tree(home)
    zip_bytes = _clean_zip(hermes_constants._HERMES_NODE_TARGET_MAJOR)
    _stub_env(monkeypatch, home, zip_bytes, sc_config)
    digest = hashlib.sha256(zip_bytes).hexdigest()
    monkeypatch.setattr(hermes_constants, "_expected_node_archive_digest", lambda p, a: digest)

    result = hermes_constants._heal_managed_node_windows()

    assert result is True
    assert (home / "node" / "node.exe").read_text(encoding="utf-8") == "fake-node"


@pytest.mark.windows_only
def test_malicious_archive_rejected_before_extraction(tmp_path, monkeypatch, sc_config):
    home = tmp_path / "hermes"
    live = _seed_live_tree(home)
    zip_bytes = _traversal_zip(hermes_constants._HERMES_NODE_TARGET_MAJOR)
    _stub_env(monkeypatch, home, zip_bytes, sc_config)

    result = hermes_constants._heal_managed_node_windows()

    assert result is False
    assert (live / "node.exe").read_text(encoding="utf-8") == "old"
    assert list(home.glob("node.new-*")) == []
    assert list(home.glob("node.old-*")) == []


@pytest.mark.windows_only
def test_missing_npm_cmd_is_rejected(tmp_path, monkeypatch, sc_config):
    home = tmp_path / "hermes"
    live = _seed_live_tree(home)
    zip_bytes = _node_only_zip(hermes_constants._HERMES_NODE_TARGET_MAJOR)
    _stub_env(monkeypatch, home, zip_bytes, sc_config)

    result = hermes_constants._heal_managed_node_windows()

    assert result is False
    assert (live / "node.exe").read_text(encoding="utf-8") == "old"
    assert list(home.glob("node.new-*")) == []
