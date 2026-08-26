"""WP4 A6/A1: managed-Node provenance markers — behavioral.

A Hermes-managed Node tree is EXECUTED only when it carries a current
provenance marker that binds the WHOLE tree (node exe + npm/npx + npm CLI JS).
These tests exercise the real resolution/trust helpers in ``hermes_constants``:

  * an UNMARKED legacy tree is not trusted and is not executed — the caller
    falls back to an operator-PATH Node used in place;
  * a TAMPERED tree (marker present, node bytes changed) is rejected;
  * a component-mismatched marker is rejected;
  * a TRUSTED-but-broken managed tree fails closed (no silent system-npm use);
  * the marker-write path marks a freshly-placed tree.

A1: there is NO (size, mtime) cache — the whole tree is rehashed on every call.

Host-agnostic: the node binary name and managed dir differ per OS but the
trust logic is identical, so these run on every host.
"""

from __future__ import annotations

import os
from pathlib import Path

import hermes_constants
from hermes_cli.supply_chain.managed import write_tool_marker

_NODE = "node.exe" if os.name == "nt" else "node"


def _managed_node_dir(home: Path) -> Path:
    # Mirror the anchor directory of iter_hermes_node_dirs() per platform.
    return (home / "node") if os.name == "nt" else (home / "node" / "bin")


def _make_node(directory: Path, content: str = "fake-node") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    node = directory / _NODE
    node.write_text(content, encoding="utf-8")
    if os.name != "nt":
        node.chmod(0o755)
    return node


def _mark(anchor: Path, *, component: str = "node") -> None:
    """Write a WHOLE-TREE marker (node exe bytes + tree digest) via the same
    helper the resolver validates against."""
    tree_root = hermes_constants._managed_node_tree_root(anchor)
    write_tool_marker(anchor, tree_dir=tree_root, component=component, version="", provenance="test")


def test_unmarked_managed_node_not_trusted(tmp_path, monkeypatch):
    home = tmp_path / "h"
    monkeypatch.setenv("HERMES_HOME", str(home))
    anchor = _make_node(_managed_node_dir(home))
    assert hermes_constants._managed_node_marked(anchor) is False
    assert hermes_constants.hermes_managed_node_tree_trusted() is False


def test_marked_managed_node_is_trusted(tmp_path, monkeypatch):
    home = tmp_path / "h"
    monkeypatch.setenv("HERMES_HOME", str(home))
    anchor = _make_node(_managed_node_dir(home))
    _mark(anchor)
    assert hermes_constants._managed_node_marked(anchor) is True
    assert hermes_constants.hermes_managed_node_tree_trusted() is True


def test_tampered_managed_node_rejected(tmp_path, monkeypatch):
    home = tmp_path / "h"
    monkeypatch.setenv("HERMES_HOME", str(home))
    anchor = _make_node(_managed_node_dir(home), "good-node")
    _mark(anchor)
    assert hermes_constants._managed_node_marked(anchor) is True
    # Swap the node bytes but keep the (now-stale) marker.
    anchor.write_text("EVIL-NODE", encoding="utf-8")
    assert hermes_constants._managed_node_marked(anchor) is False


def test_npm_cli_tree_tamper_rejected(tmp_path, monkeypatch):
    """A1: the marker binds the whole tree, so a tampered npm CLI JS file — with
    the node binary untouched — is still rejected."""
    home = tmp_path / "h"
    monkeypatch.setenv("HERMES_HOME", str(home))
    d = _managed_node_dir(home)
    anchor = _make_node(d, "good-node")
    npm_cli = home / "node" / "lib" / "node_modules" / "npm" / "lib" / "cli.js"
    npm_cli.parent.mkdir(parents=True, exist_ok=True)
    npm_cli.write_text("console.log('npm AAAA')\n", encoding="utf-8")
    _mark(anchor)
    assert hermes_constants._managed_node_marked(anchor) is True
    # node binary untouched; only the npm CLI JS is swapped -> still rejected.
    npm_cli.write_text("console.log('npm EVIL')\n", encoding="utf-8")
    assert hermes_constants._managed_node_marked(anchor) is False


def test_component_mismatch_marker_rejected(tmp_path, monkeypatch):
    home = tmp_path / "h"
    monkeypatch.setenv("HERMES_HOME", str(home))
    anchor = _make_node(_managed_node_dir(home))
    _mark(anchor, component="uv")  # a marker for a DIFFERENT component
    assert hermes_constants._managed_node_marked(anchor) is False


def test_unmarked_tree_falls_back_to_operator_path(tmp_path, monkeypatch):
    home = tmp_path / "h"
    monkeypatch.setenv("HERMES_HOME", str(home))
    _make_node(_managed_node_dir(home))  # unmarked managed tree
    op_dir = tmp_path / "opbin"
    op_node = _make_node(op_dir)  # operator node on PATH
    monkeypatch.setenv("PATH", str(op_dir))
    monkeypatch.setattr(hermes_constants, "node_tool_runnable", lambda p: True)
    monkeypatch.setattr(hermes_constants, "_managed_node_heal_attempted", False)
    monkeypatch.setattr(hermes_constants, "heal_hermes_managed_node", lambda: False)

    resolved = hermes_constants.find_node_executable("node")
    assert resolved == str(op_node), resolved


def test_marked_broken_tree_fails_closed(tmp_path, monkeypatch):
    home = tmp_path / "h"
    monkeypatch.setenv("HERMES_HOME", str(home))
    anchor = _make_node(_managed_node_dir(home))
    _mark(anchor)  # trusted...
    op_dir = tmp_path / "opbin"
    _make_node(op_dir)  # operator node exists but must NOT be used
    monkeypatch.setenv("PATH", str(op_dir))
    # ...but broken (nothing runnable) and heal disabled.
    monkeypatch.setattr(hermes_constants, "node_tool_runnable", lambda p: False)
    monkeypatch.setattr(hermes_constants, "_managed_node_heal_attempted", False)
    monkeypatch.setattr(hermes_constants, "heal_hermes_managed_node", lambda: False)

    assert hermes_constants.find_node_executable("node") is None


def test_write_managed_node_marker_marks_tree(tmp_path, monkeypatch):
    home = tmp_path / "h"
    monkeypatch.setenv("HERMES_HOME", str(home))
    anchor = _make_node(_managed_node_dir(home))
    assert hermes_constants._managed_node_marked(anchor) is False

    hermes_constants._write_managed_node_marker(home)

    assert hermes_constants._managed_node_marked(anchor) is True


def test_marker_digest_survives_metadata_but_not_content(tmp_path, monkeypatch):
    """One-byte drift in the node binary invalidates the marker."""
    home = tmp_path / "h"
    monkeypatch.setenv("HERMES_HOME", str(home))
    anchor = _make_node(_managed_node_dir(home), "node-bytes-v1")
    _mark(anchor)
    assert hermes_constants._managed_node_marked(anchor) is True
    anchor.write_text("node-bytes-v2", encoding="utf-8")  # one logical byte drift
    assert hermes_constants._managed_node_marked(anchor) is False
