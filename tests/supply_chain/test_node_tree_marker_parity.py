"""A1: the standalone node_tree_marker.py must be byte-for-byte compatible with
the in-tree managed.py whole-tree marker — a marker either writes is accepted by
the other, and their tree-digest/verdict never drift. This is what lets the
shell/PS installers enforce the SAME contract the Python resolver validates
(including in pre-clone curl mode), without two implementations diverging.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hermes_cli.supply_chain import managed as M

_REPO = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO / "scripts" / "ci" / "node_tree_marker.py"


def _load_standalone():
    spec = importlib.util.spec_from_file_location("node_tree_marker", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


S = _load_standalone()


def _node_tree(home: Path):
    root = home / "node"
    bind = root / "bin"
    npmlib = root / "lib" / "node_modules" / "npm" / "lib"
    bind.mkdir(parents=True)
    npmlib.mkdir(parents=True)
    node = bind / ("node.exe" if os.name == "nt" else "node")
    node.write_text("NODE-AAAA\n", encoding="utf-8")
    (bind / "npm").write_text("NPM-AAAA\n", encoding="utf-8")
    (bind / "npx").write_text("NPX-AAAA\n", encoding="utf-8")
    (npmlib / "cli.js").write_text("console.log('AAAA')\n", encoding="utf-8")
    return root, node


def test_tree_digest_matches_managed(tmp_path):
    root, _ = _node_tree(tmp_path / "h")
    assert S.compute_tree_digest(root) == M.compute_tree_digest(root)


def test_managed_marker_accepted_by_standalone(tmp_path):
    home = tmp_path / "h"
    root, node = _node_tree(home)
    M.write_tool_marker(node, tree_dir=root, component="node", version="v1", provenance="test")
    assert S.tool_marker_ok(node, root, "node") is True
    assert S.verify_node_home(home) is True


def test_standalone_marker_accepted_by_managed(tmp_path):
    home = tmp_path / "h"
    root, node = _node_tree(home)
    S.write_tool_marker(node, root, component="node", version="v1", provenance="test")
    assert M.tool_marker_ok(node, tree_dir=root, component="node") is True


def test_tamper_rejected_by_both(tmp_path):
    home = tmp_path / "h"
    root, node = _node_tree(home)
    M.write_tool_marker(node, tree_dir=root, component="node", version="v1", provenance="test")
    # tamper an npm CLI file (node exe untouched)
    (root / "lib" / "node_modules" / "npm" / "lib" / "cli.js").write_text("EVIL\n", encoding="utf-8")
    assert S.tool_marker_ok(node, root, "node") is False
    assert M.tool_marker_ok(node, tree_dir=root, component="node") is False


def test_cli_write_then_verify_roundtrip(tmp_path):
    home = tmp_path / "h"
    _node_tree(home)
    w = subprocess.run(
        [sys.executable, str(_SCRIPT), "--home", str(home), "--write", "--version", "v1"],
        capture_output=True, text=True,
    )
    assert w.returncode == 0, w.stderr
    v = subprocess.run(
        [sys.executable, str(_SCRIPT), "--home", str(home), "--verify"],
        capture_output=True, text=True,
    )
    assert v.returncode == 0, v.stderr
    # the in-tree resolver also trusts the CLI-written marker
    import hermes_constants as hc
    for d in (home / "node" / "bin", home / "node"):
        anchor = hc._managed_node_anchor(d)
        if anchor is not None:
            assert hc._managed_node_marked(anchor) is True
            break


def test_cli_verify_fails_closed_on_unmarked(tmp_path):
    home = tmp_path / "h"
    _node_tree(home)  # no marker written
    v = subprocess.run(
        [sys.executable, str(_SCRIPT), "--home", str(home), "--verify"],
        capture_output=True, text=True,
    )
    assert v.returncode == 1
    assert "fail closed" in v.stderr


def test_cli_verify_fails_closed_after_tamper(tmp_path):
    home = tmp_path / "h"
    root, _ = _node_tree(home)
    subprocess.run([sys.executable, str(_SCRIPT), "--home", str(home), "--write"], check=True)
    (root / "bin" / "npm").write_text("EVIL-NPM\n", encoding="utf-8")
    v = subprocess.run(
        [sys.executable, str(_SCRIPT), "--home", str(home), "--verify"],
        capture_output=True, text=True,
    )
    assert v.returncode == 1
