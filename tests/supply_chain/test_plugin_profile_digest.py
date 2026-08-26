"""WP4 item 4: plugin/profile whole-bundle digest recording + mutation detection.

Behavioral — exercises the real digest helper and the profile manifest
serialization; no network, no git.
"""

from __future__ import annotations

from pathlib import Path

from hermes_cli.plugins_cmd import plugin_bundle_digest


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_plugin_bundle_digest_deterministic_and_order_independent(tmp_path):
    a = tmp_path / "a"
    _write(a, "plugin.yaml", "name: x\n")
    _write(a, "lib/mod.py", "print(1)\n")
    b = tmp_path / "b"
    _write(b, "lib/mod.py", "print(1)\n")
    _write(b, "plugin.yaml", "name: x\n")
    assert plugin_bundle_digest(a) == plugin_bundle_digest(b)


def test_plugin_bundle_digest_mutation_sensitive(tmp_path):
    a = tmp_path / "a"
    _write(a, "plugin.yaml", "name: x\n")
    _write(a, "lib/mod.py", "print(1)\n")
    d1 = plugin_bundle_digest(a)
    _write(a, "lib/mod.py", "print(2)\n")  # one-byte change
    assert plugin_bundle_digest(a) != d1


def test_plugin_bundle_digest_excludes_git_and_pycache(tmp_path):
    a = tmp_path / "a"
    _write(a, "plugin.yaml", "name: x\n")
    d1 = plugin_bundle_digest(a)
    # Adding .git / __pycache__ / .pyc noise must NOT change the content digest.
    _write(a, ".git/config", "[core]\n")
    _write(a, "__pycache__/mod.cpython-312.pyc", "bytecode\n")
    _write(a, "lib/__pycache__/x.pyc", "b\n")
    assert plugin_bundle_digest(a) == d1


def test_profile_manifest_roundtrips_bundle_sha256():
    from hermes_cli.profile_distribution import DistributionManifest

    m = DistributionManifest(name="demo", bundle_sha256="a" * 64, source="https://x/y#" + "b" * 40)
    d = m.to_dict()
    assert d["bundle_sha256"] == "a" * 64
    back = DistributionManifest.from_dict(d)
    assert back.bundle_sha256 == "a" * 64
    assert back.source == "https://x/y#" + "b" * 40


def test_profile_manifest_omits_empty_bundle_sha256():
    from hermes_cli.profile_distribution import DistributionManifest

    m = DistributionManifest(name="demo")
    assert "bundle_sha256" not in m.to_dict()


def test_install_metadata_write_read_roundtrip(tmp_path, monkeypatch):
    """_write_install_metadata persists a record that _read_install_metadata
    reads back intact (including bundle_sha256)."""
    from hermes_cli import plugins_cmd

    meta_path = tmp_path / "installed.json"
    monkeypatch.setattr(plugins_cmd, "_install_metadata_path", lambda: meta_path)
    record = {"demo": {"pinned": True, "revision": "b" * 40, "bundle_sha256": "a" * 64, "source": "x"}}
    plugins_cmd._write_install_metadata(record)
    back = plugins_cmd._read_install_metadata()
    assert back["demo"]["bundle_sha256"] == "a" * 64
    assert back["demo"]["revision"] == "b" * 40
