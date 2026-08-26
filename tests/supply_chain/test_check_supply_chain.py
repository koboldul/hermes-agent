"""Behavioral tests for scripts/ci/check_supply_chain.py.

Exercises the real check functions: the committed tree passes; tampered
manifests fail on each invariant; an unclassified mutable fetch fails.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from conftest import make_component, make_digest, make_manifest, make_artifact

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_checker():
    path = _REPO_ROOT / "scripts" / "ci" / "check_supply_chain.py"
    spec = importlib.util.spec_from_file_location("check_supply_chain", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECK = _load_checker()


def _manifest_obj(data: dict):
    from hermes_cli.supply_chain.manifest import ReleaseManifest

    return ReleaseManifest.from_dict(data)


def test_committed_tree_passes():
    findings = CHECK.run(_REPO_ROOT, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert findings.ok(), "\n".join(findings.errors)


def test_expired_manifest_flagged():
    manifest = _manifest_obj(make_manifest(expires_at="2026-06-01T00:00:00Z"))
    findings = CHECK.Findings()
    CHECK.check_manifest(manifest, findings, now=datetime(2026, 8, 1, tzinfo=timezone.utc))
    assert any("expired" in e for e in findings.errors)


def test_non_canonical_host_flagged():
    comp = make_component(
        artifacts=[make_artifact(url="https://evil.example.com/uv.tar.gz")]
    )
    manifest = _manifest_obj(make_manifest(components=[comp]))
    findings = CHECK.Findings()
    CHECK.check_manifest(manifest, findings, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert any("non-canonical URL host" in e for e in findings.errors)


def test_release_verified_without_anchor_flagged():
    comp = make_component(
        trust_class="release_verified",
        version="1.2.3",
        artifacts=[make_artifact(digest=make_digest(value=None, status="unavailable"))],
    )
    manifest = _manifest_obj(make_manifest(components=[comp]))
    findings = CHECK.Findings()
    CHECK.check_manifest(manifest, findings, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert any("needs a digest or provenance" in e for e in findings.errors)


def test_release_verified_non_semver_flagged():
    comp = make_component(trust_class="release_verified", version="pending-pin")
    manifest = _manifest_obj(make_manifest(components=[comp]))
    findings = CHECK.Findings()
    CHECK.check_manifest(manifest, findings, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert any("exact version" in e for e in findings.errors)


def test_unanchored_transport_needs_blocker_and_guidance():
    comp = make_component(
        trust_class="transport_trusted",
        artifacts=[make_artifact(digest=make_digest(value=None, status="unavailable"))],
    )
    manifest = _manifest_obj(make_manifest(components=[comp]))
    findings = CHECK.Findings()
    CHECK.check_manifest(manifest, findings, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert any("blocker and operator_guidance" in e for e in findings.errors)


def test_wrong_signer_flagged():
    data = make_manifest()
    data["manifest"]["signer"]["repository"] = "attacker/hermes-agent"
    manifest = _manifest_obj(data)
    findings = CHECK.Findings()
    CHECK.check_manifest(manifest, findings, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert any("signer repository" in e for e in findings.errors)


def _write_min_supply_chain(root: Path):
    (root / "supply-chain").mkdir(parents=True, exist_ok=True)
    (root / "supply-chain" / "manifest.json").write_text(
        json.dumps(make_manifest()), encoding="utf-8"
    )
    (root / "supply-chain" / "ledger.json").write_text(
        json.dumps({"schema_version": 1, "paths": []}), encoding="utf-8"
    )


def test_unclassified_mutable_fetch_fails(tmp_path):
    _write_min_supply_chain(tmp_path)
    prod = tmp_path / "installer.sh"
    prod.write_text("curl -LsSf https://astral.sh/uv/install.sh | sh\n", encoding="utf-8")
    findings = CHECK.run(tmp_path, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert any("unclassified mutable fetch" in e for e in findings.errors)


def test_ledgered_mutable_fetch_passes(tmp_path):
    _write_min_supply_chain(tmp_path)
    prod = tmp_path / "installer.sh"
    prod.write_text("curl -LsSf https://astral.sh/uv/install.sh | sh\n", encoding="utf-8")
    negtest = tmp_path / "tests" / "t.py"
    negtest.parent.mkdir(parents=True, exist_ok=True)
    negtest.write_text("def test_x():\n    assert True\n", encoding="utf-8")
    ledger = {
        "schema_version": 1,
        "paths": [
            {
                "id": "installer",
                "description": "d",
                "source": "installer.sh",
                "trust_owner": "transport_trusted",
                "activation_point": "a",
                "negative_test": "tests/t.py",
                "platforms": ["linux"],
                "migration_state": "pending",
                "blocker": "b",
            }
        ],
    }
    (tmp_path / "supply-chain" / "ledger.json").write_text(json.dumps(ledger), encoding="utf-8")
    findings = CHECK.run(tmp_path, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert not any("unclassified mutable fetch" in e for e in findings.errors)


def _item6_case(tmp_path, rel, content):
    _write_min_supply_chain(tmp_path)
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return CHECK.run(tmp_path, now=datetime(2026, 9, 1, tzinfo=timezone.utc))


@pytest.mark.parametrize("rel,content", [
    ("apps/desktop/scripts/x.mjs", "import { rebuild } from '@electron/rebuild'\n"),
    ("apps/desktop/scripts/y.mjs", "const g = require('@electron/get')\n"),
    ("apps/desktop/scripts/z.mjs", "spawnSync('prebuild-install', [])\n"),
    ("nix/x.nix", 'url = "https://artifacts.electronjs.org/headers/dist/v1/node.tar.gz";\n'),
    ("tools/x.sh", "npx playwright install chromium\n"),
    ("tools/x.py", 'URL = "https://example.com/tool-linux-x64.tar.gz"\n'),
    ("tools/x.mjs", "execFileSync('git', ['clone', 'https://github.com/a/b'])\n"),
    ("tools/y.sh", "git clone https://github.com/a/b dest\n"),
    ("tools/z.ts", "spawn('npx', ['some-remote-tool'])\n"),
])
def test_scanner_flags_omitted_native_browser_extension_paths(tmp_path, rel, content):
    findings = _item6_case(tmp_path, rel, content)
    assert any("unclassified mutable fetch" in e for e in findings.errors), (rel, findings.errors)


@pytest.mark.parametrize("rel,content", [
    ("tools/a.py", "# git clone https://github.com/a/b is documented here\n"),
    ("tools/b.mjs", "// runs @electron/get under the hood\n"),
    ("tools/c.mjs", "execFileSync('git', ['rev-parse', 'HEAD'])\n"),
    ("tools/d.sh", 'git clone --quiet "$REPO_ROOT" sandbox\n'),
    ("tools/e.py", 'npm = find_node_executable("npm")\n'),
    ("tools/f.py", 'hint = "npx playwright install chromium"\n'),
    ("tools/g.py", "x = 'prebuild-install'\n"),
])
def test_scanner_ignores_prose_and_local_ops(tmp_path, rel, content):
    findings = _item6_case(tmp_path, rel, content)
    assert not any("unclassified mutable fetch" in e for e in findings.errors), (rel, findings.errors)


def test_scanner_skips_python_docstring_examples(tmp_path):
    content = 'def f():\n    """Usage: git clone https://github.com/a/b then build."""\n    return 1\n'
    findings = _item6_case(tmp_path, "tools/docy.py", content)
    assert not any("unclassified mutable fetch" in e for e in findings.errors), findings.errors


def test_missing_negative_test_file_flagged(tmp_path):
    _write_min_supply_chain(tmp_path)
    (tmp_path / "installer.sh").write_text("echo hi\n", encoding="utf-8")
    ledger = {
        "schema_version": 1,
        "paths": [
            {
                "id": "installer",
                "description": "d",
                "source": "installer.sh",
                "trust_owner": "transport_trusted",
                "activation_point": "a",
                "negative_test": "tests/does_not_exist.py",
                "platforms": ["linux"],
                "migration_state": "pending",
                "blocker": "b",
            }
        ],
    }
    (tmp_path / "supply-chain" / "ledger.json").write_text(json.dumps(ledger), encoding="utf-8")
    findings = CHECK.run(tmp_path, now=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert any("negative_test file missing" in e for e in findings.errors)
