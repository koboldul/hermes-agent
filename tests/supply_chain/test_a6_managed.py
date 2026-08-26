"""WP4 A6: managed-artifact provenance markers (behavioral).

A managed binary is trusted only with a current marker whose digest matches its
bytes. Unmarked (legacy) or tampered binaries are ignored in favour of an
operator PATH binary, or fail closed.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from hermes_cli.supply_chain.managed import (
    managed_ok,
    marker_path,
    resolve_managed_or_operator,
    verify_marked,
    write_marker,
)


def _make_bin(p: Path, content: bytes = b"#!/bin/sh\necho hi\n") -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


def test_unmarked_managed_binary_is_not_trusted(tmp_path):
    b = _make_bin(tmp_path / "bin" / "uv")
    ok, reason = verify_marked(b, component="uv")
    assert ok is False
    assert "unmarked" in reason
    assert managed_ok(b, component="uv") is False


def test_marked_binary_is_trusted(tmp_path):
    b = _make_bin(tmp_path / "bin" / "uv")
    write_marker(b, component="uv", version="1.2.3", provenance="operator_compat_opt_in")
    assert managed_ok(b, component="uv") is True


def test_tampered_binary_fails_marker(tmp_path):
    b = _make_bin(tmp_path / "bin" / "uv")
    write_marker(b, component="uv", version="1.2.3", provenance="x")
    # Mutate the binary after marking → digest mismatch.
    b.write_bytes(b"#!/bin/sh\necho pwned\n")
    ok, reason = verify_marked(b, component="uv")
    assert ok is False
    assert "digest" in reason.lower()


def test_component_mismatch_rejected(tmp_path):
    b = _make_bin(tmp_path / "bin" / "uv")
    write_marker(b, component="node", version="1", provenance="x")
    assert managed_ok(b, component="uv") is False


def test_corrupt_marker_rejected(tmp_path):
    b = _make_bin(tmp_path / "bin" / "uv")
    marker_path(b).write_text("{not json", encoding="utf-8")
    ok, reason = verify_marked(b, component="uv")
    assert ok is False


def test_resolve_prefers_marked_managed(tmp_path):
    managed = _make_bin(tmp_path / "bin" / "uv")
    write_marker(managed, component="uv", version="1", provenance="x")
    resolved = resolve_managed_or_operator(
        managed, component="uv", operator_probe=lambda: "/usr/bin/uv"
    )
    assert resolved == str(managed)


def test_resolve_falls_back_to_operator_when_unmarked(tmp_path):
    managed = _make_bin(tmp_path / "bin" / "uv")  # no marker
    resolved = resolve_managed_or_operator(
        managed, component="uv", operator_probe=lambda: "/usr/bin/uv"
    )
    assert resolved == "/usr/bin/uv"


def test_resolve_fails_closed_when_unmarked_and_no_operator(tmp_path):
    managed = _make_bin(tmp_path / "bin" / "uv")  # no marker
    resolved = resolve_managed_or_operator(managed, component="uv", operator_probe=lambda: None)
    assert resolved is None


def test_uv_ensure_ignores_unmarked_managed_and_uses_operator(tmp_path, monkeypatch):
    """_ensure_uv_path ignores a legacy unmarked managed uv and uses an operator
    uv in place (A6 wiring)."""
    from hermes_cli import managed_uv

    managed = _make_bin(tmp_path / "bin" / ("uv.exe" if os.name == "nt" else "uv"))
    monkeypatch.setattr(managed_uv, "resolve_uv", lambda: str(managed))
    monkeypatch.setattr(managed_uv, "_probe_operator_uv", lambda: "/opt/uv")

    def forbidden(*a, **k):
        raise AssertionError("must not install when an operator uv is available")

    monkeypatch.setattr(managed_uv, "_install_uv", forbidden)
    assert managed_uv._ensure_uv_path() == "/opt/uv"


def test_uv_ensure_uses_marked_managed(tmp_path, monkeypatch):
    from hermes_cli import managed_uv

    managed = _make_bin(tmp_path / "bin" / ("uv.exe" if os.name == "nt" else "uv"))
    write_marker(managed, component="uv", version="1", provenance="x")
    monkeypatch.setattr(managed_uv, "resolve_uv", lambda: str(managed))

    def forbidden_probe():
        raise AssertionError("a marked managed uv must be used without probing operator")

    monkeypatch.setattr(managed_uv, "_probe_operator_uv", forbidden_probe)
    assert managed_uv._ensure_uv_path() == str(managed)


def test_find_bws_ignores_unmarked_managed_and_uses_system(tmp_path, monkeypatch):
    from agent.secret_sources import bitwarden as bw

    managed = _make_bin(tmp_path / "bin" / bw._platform_binary_name())
    monkeypatch.setattr(bw, "_hermes_bin_dir", lambda: tmp_path / "bin")
    op = str(tmp_path / "op" / "bws")
    monkeypatch.setattr(bw.shutil, "which", lambda n: op)
    # Unmarked managed → ignored → operator PATH used.
    assert Path(bw.find_bws()) == Path(op)
    # Marked managed → used in place.
    write_marker(managed, component="bws", version="1", provenance="x")
    assert bw.find_bws() == managed


def test_find_iron_proxy_ignores_unmarked_managed(tmp_path, monkeypatch):
    from agent.proxy_sources import iron_proxy as ip

    managed = _make_bin(tmp_path / "bin" / ip._platform_binary_name())
    monkeypatch.setattr(ip, "_hermes_bin_dir", lambda: tmp_path / "bin")
    op = str(tmp_path / "op" / "iron-proxy")
    monkeypatch.setattr(ip.shutil, "which", lambda n: op)
    assert Path(ip.find_iron_proxy()) == Path(op)
    write_marker(managed, component="iron-proxy", version="1", provenance="x")
    assert ip.find_iron_proxy() == managed


def test_tirith_ignores_unmarked_managed(tmp_path, monkeypatch):
    import tools.tirith_security as tirith

    bindir = tmp_path / "bin"
    managed = _make_bin(bindir / "tirith")
    monkeypatch.setattr(tirith, "_hermes_bin_dir", lambda: str(bindir))
    assert tirith._managed_tirith_marked(str(managed)) is False
    write_marker(managed, component="tirith", version="1", provenance="x")
    assert tirith._managed_tirith_marked(str(managed)) is True
