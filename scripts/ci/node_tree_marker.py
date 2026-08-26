#!/usr/bin/env python3
"""Standalone stdlib verifier/writer for a Hermes-managed Node tree's
WHOLE-TREE provenance marker (A1).

Replicates ``hermes_cli/supply_chain/managed.py::{compute_tree_digest,
write_tool_marker, tool_marker_ok}`` using ONLY the standard library so the
shell / PowerShell installers can enforce and create the SAME whole-tree marker
contract the Python resolver validates — the node executable's bytes AND a
deterministic digest over the whole ``<home>/node`` tree (node + npm/npx
wrappers + npm CLI JS). It has NO ``hermes_cli`` dependency, so it works in
pre-clone ``curl | sh`` mode where the package is not importable.

A behavioral parity test
(``tests/supply_chain/test_node_tree_marker_parity.py``) asserts a marker this
writes is accepted by the in-tree ``tool_marker_ok`` and vice-versa, so the two
implementations can never drift.

Usage:
  python scripts/ci/node_tree_marker.py --home <HERMES_HOME> --verify
      exit 0 iff the managed node tree carries a current whole-tree marker.
  python scripts/ci/node_tree_marker.py --home <HERMES_HOME> --write \
      [--version <v>] [--provenance <p>]
      (re)write the whole-tree marker for the managed node tree; exit 0 on
      success.

Fail closed: any error / missing tree / digest mismatch is exit 1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

MARKER_SUFFIX = ".provenance.json"
QUARANTINE_SUBDIR = ".sc-quarantine"
_MARKER_SCHEMA = 1
_COMPONENT = "node"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_tree_digest(tree_dir) -> str:
    """Byte-for-byte identical to managed.py::compute_tree_digest."""
    tree = Path(tree_dir)
    if not tree.is_dir():
        return "sha256:absent"
    h = hashlib.sha256()
    for p in sorted(tree.rglob("*"), key=lambda x: x.relative_to(tree).as_posix()):
        relpath = p.relative_to(tree)
        if p.name.endswith(MARKER_SUFFIX) or QUARANTINE_SUBDIR in relpath.parts:
            continue
        rel = relpath.as_posix().encode("utf-8")
        try:
            if p.is_symlink():
                h.update(b"L\0"); h.update(rel); h.update(b"\0")
                h.update(str(os.readlink(p)).encode("utf-8", "surrogatepass")); h.update(b"\0")
            elif p.is_file():
                h.update(b"F\0"); h.update(rel); h.update(b"\0")
                h.update(_sha256_file(p).encode()); h.update(b"\0")
            elif p.is_dir():
                h.update(b"D\0"); h.update(rel); h.update(b"\0")
        except OSError:
            h.update(b"?\0"); h.update(rel); h.update(b"\0")
    return "sha256:" + h.hexdigest()


def _marker_path(binary: Path) -> Path:
    return binary.with_name(binary.name + MARKER_SUFFIX)


def tool_marker_ok(anchor: Path, tree_dir, component: str = _COMPONENT) -> bool:
    """Byte-for-byte identical verdict to managed.py::tool_marker_ok."""
    anchor = Path(anchor)
    if not anchor.exists():
        return False
    mp = _marker_path(anchor)
    if not mp.exists():
        return False
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    recorded = str(((data or {}).get("digest") or {}).get("value") or "")
    if not recorded:
        return False
    try:
        actual = _sha256_file(anchor)
    except OSError:
        return False
    if actual.lower() != recorded.lower():
        return False
    if component is not None and str(data.get("component")) != str(component):
        return False
    recorded_tree = str(((data or {}).get("tool_tree") or {}).get("digest") or "")
    if not recorded_tree:
        return False
    return compute_tree_digest(tree_dir) == recorded_tree


def write_tool_marker(anchor: Path, tree_dir, *, component: str, version: str, provenance: str) -> Path:
    """Atomic whole-tree marker write matching managed.py::write_tool_marker."""
    anchor = Path(anchor)
    payload = {
        "schema": _MARKER_SCHEMA,
        "component": str(component),
        "version": str(version),
        "digest": {"algorithm": "sha256", "value": _sha256_file(anchor)},
        "tool_tree": {"path": str(tree_dir), "digest": compute_tree_digest(tree_dir)},
        "provenance": str(provenance),
        "marked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    target = _marker_path(anchor)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, target)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return target


def _node_anchor(directory: Path):
    for name in ("node.exe", "node"):
        cand = Path(directory) / name
        if cand.is_file():
            return cand
    return None


def _node_dirs(home: Path):
    root = Path(home)
    return [d for d in (root / "node", root / "node" / "bin") if d.is_dir()]


def _tree_root(anchor: Path) -> Path:
    d = anchor.parent
    return d.parent if d.name == "bin" else d


def verify_node_home(home) -> bool:
    for directory in _node_dirs(Path(home)):
        anchor = _node_anchor(directory)
        if anchor is not None and tool_marker_ok(anchor, _tree_root(anchor), _COMPONENT):
            return True
    return False


def write_node_home(home, *, version: str, provenance: str) -> bool:
    wrote = False
    seen: set = set()
    for directory in _node_dirs(Path(home)):
        anchor = _node_anchor(directory)
        if anchor is None:
            continue
        tree_root = _tree_root(anchor)
        if str(tree_root) in seen:
            continue
        seen.add(str(tree_root))
        try:
            write_tool_marker(anchor, tree_root, component=_COMPONENT, version=version, provenance=provenance)
            wrote = True
        except OSError:
            pass
    return wrote


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Verify/write a Hermes-managed Node tree whole-tree provenance marker (A1).")
    p.add_argument("--home", required=True, help="HERMES_HOME whose <home>/node tree to verify/mark")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify", action="store_true", help="exit 0 iff the whole-tree marker verifies")
    mode.add_argument("--write", action="store_true", help="(re)write the whole-tree marker")
    p.add_argument("--version", default="", help="node version to record (write mode)")
    p.add_argument("--provenance", default="operator_compat_opt_in", help="provenance label (write mode)")
    args = p.parse_args(argv)

    try:
        if args.verify:
            ok = verify_node_home(args.home)
            if not ok:
                sys.stderr.write(
                    "node_tree_marker: managed node tree has no valid whole-tree "
                    "provenance marker (fail closed)\n"
                )
            return 0 if ok else 1
        # write
        ok = write_node_home(args.home, version=args.version, provenance=args.provenance)
        if not ok:
            sys.stderr.write("node_tree_marker: no managed node tree found to mark\n")
        return 0 if ok else 1
    except Exception as exc:  # fail closed
        sys.stderr.write(f"node_tree_marker: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
