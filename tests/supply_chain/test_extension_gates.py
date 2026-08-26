"""Behavioral fail-closed tests for extension activation gates (skills, plugins,
profile distributions). Config-driven opt-in — no environment variables."""

from __future__ import annotations

import pytest


def _set_config(monkeypatch, cfg):
    from hermes_cli.supply_chain import gate

    monkeypatch.setattr(gate, "_sc_config", lambda: cfg)


# --- scoped consent (config-only) -----------------------------------------

def test_compat_opt_in_is_scoped(monkeypatch):
    from hermes_cli.supply_chain.gate import compat_opt_in

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": ["uv"]})
    assert compat_opt_in("uv") is True
    assert compat_opt_in("plugins") is False  # allowing uv never enables plugins


def test_compat_opt_in_wildcard_and_broad(monkeypatch):
    from hermes_cli.supply_chain.gate import compat_opt_in

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": ["*"]})
    assert compat_opt_in("anything") is True
    # enforce:false alone must NOT authorize any installer (scoped-consent rule).
    _set_config(monkeypatch, {"enforce": False})
    assert compat_opt_in("anything") is False
    _set_config(monkeypatch, {"enforce": False, "allow_unverified_components": ["uv"]})
    assert compat_opt_in("uv") is True
    assert compat_opt_in("node") is False


def test_enforce_default_true_when_config_empty(monkeypatch):
    from hermes_cli.supply_chain.gate import compat_opt_in, enforce_enabled

    _set_config(monkeypatch, {})
    assert enforce_enabled() is True
    assert compat_opt_in("uv") is False


# --- skills activation -----------------------------------------------------

def test_skill_whole_bundle_digest_deterministic():
    from tools.skills_hub import SkillBundle, _whole_bundle_digest

    b1 = SkillBundle(name="s", files={"a": "x", "b": b"y"}, source="github", identifier="o/r", trust_level="community")
    b2 = SkillBundle(name="s", files={"b": b"y", "a": "x"}, source="github", identifier="o/r", trust_level="community")
    assert _whole_bundle_digest(b1) == _whole_bundle_digest(b2)
    b3 = SkillBundle(name="s", files={"a": "z"}, source="github", identifier="o/r", trust_level="community")
    assert _whole_bundle_digest(b3) != _whole_bundle_digest(b1)


def test_skill_exact_identity_rejects_self_declared(monkeypatch):
    """A self-declared semver or bundle-claimed SHA is NOT an exact identity —
    only a transport-resolved commit key counts."""
    from tools.skills_hub import SkillBundle, bundle_exact_identity

    mutable = SkillBundle(name="s", files={}, source="github", identifier="o/r", trust_level="c", metadata={"ref": "main"})
    assert bundle_exact_identity(mutable) is None
    # Attacker-controlled content claiming a version must be rejected.
    fake_semver = SkillBundle(name="s", files={}, source="clawhub", identifier="x", trust_level="c", metadata={"version": "1.2.3"})
    assert bundle_exact_identity(fake_semver) is None
    # A bundle-declared generic 'commit'/'sha' is self-declarable → rejected.
    fake_commit = SkillBundle(name="s", files={}, source="github", identifier="o/r", trust_level="c", metadata={"commit": "a" * 40, "sha": "b" * 40})
    assert bundle_exact_identity(fake_commit) is None
    # Only the transport-set resolved_commit key is accepted.
    transport = SkillBundle(name="s", files={}, source="github", identifier="o/r", trust_level="c", metadata={"resolved_commit": "c" * 40})
    assert bundle_exact_identity(transport) == "c" * 40


def test_malicious_mutable_source_with_fake_semver_fails_closed(monkeypatch, tmp_path):
    """A mutable source that self-declares version: 1.2.3 must NOT activate."""
    import tools.skills_hub as sh
    from tools.skills_hub import SkillBundle, install_from_quarantine
    from types import SimpleNamespace

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    qroot = sh._quarantine_dir()
    qdir = qroot / "evil"
    qdir.mkdir(parents=True)
    (qdir / "SKILL.md").write_text("---\nname: evil\nversion: 1.2.3\n---\n", encoding="utf-8")
    bundle = SkillBundle(
        name="evil", files={"SKILL.md": "---\nname: evil\nversion: 1.2.3\n---\n"},
        source="clawhub", identifier="evil", trust_level="community",
        metadata={"version": "1.2.3"},  # attacker-controlled self-claim
    )
    scan = SimpleNamespace(verdict="clean", scan_provenance=None)
    # Even with the operator "accepting", a fake semver is not an identity.
    with pytest.raises(ValueError) as exc:
        install_from_quarantine(qdir, "evil", "", bundle, scan, activation_accepted=True)
    assert "identity" in str(exc.value).lower()


def test_first_party_local_activates_without_network_identity(monkeypatch, tmp_path):
    """A bundle read from the installed tree (first_party_local) is trusted."""
    import tools.skills_hub as sh
    from tools.skills_hub import SkillBundle, install_from_quarantine
    from types import SimpleNamespace

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    qroot = sh._quarantine_dir()
    qdir = qroot / "localsk"
    qdir.mkdir(parents=True)
    (qdir / "SKILL.md").write_text("---\nname: localsk\n---\n", encoding="utf-8")
    bundle = SkillBundle(
        name="localsk", files={"SKILL.md": "---\nname: localsk\n---\n"},
        source="official", identifier="official/localsk", trust_level="builtin",
        metadata={"first_party_local": True},
    )
    scan = SimpleNamespace(verdict="clean", scan_provenance=None)
    installed = install_from_quarantine(qdir, "localsk", "", bundle, scan)
    assert installed.exists()


def test_transport_commit_plus_acceptance_activates(monkeypatch, tmp_path):
    import tools.skills_hub as sh
    from tools.skills_hub import SkillBundle, install_from_quarantine
    from types import SimpleNamespace

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    qroot = sh._quarantine_dir()
    qdir = qroot / "pinned"
    qdir.mkdir(parents=True)
    (qdir / "SKILL.md").write_text("---\nname: pinned\n---\n", encoding="utf-8")
    bundle = SkillBundle(
        name="pinned", files={"SKILL.md": "---\nname: pinned\n---\n"},
        source="official", identifier="official/pinned", trust_level="builtin",
        metadata={"resolved_commit": "a" * 40},
    )
    scan = SimpleNamespace(verdict="clean", scan_provenance=None)
    installed = install_from_quarantine(qdir, "pinned", "", bundle, scan, activation_accepted=True)
    assert installed.exists()


def test_expected_digest_plus_identity_activates_noninteractive(monkeypatch, tmp_path):
    import tools.skills_hub as sh
    from tools.skills_hub import SkillBundle, install_from_quarantine, _whole_bundle_digest
    from types import SimpleNamespace

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    qroot = sh._quarantine_dir()
    qdir = qroot / "dig"
    qdir.mkdir(parents=True)
    (qdir / "SKILL.md").write_text("---\nname: dig\n---\n", encoding="utf-8")
    bundle = SkillBundle(
        name="dig", files={"SKILL.md": "---\nname: dig\n---\n"},
        source="github", identifier="o/r", trust_level="community",
        metadata={"resolved_commit": "b" * 40},
    )
    expected = _whole_bundle_digest(bundle)
    scan = SimpleNamespace(verdict="clean", scan_provenance=None)
    # No interactive acceptance, no break-glass: only an expected digest + identity.
    installed = install_from_quarantine(
        qdir, "dig", "", bundle, scan, expected_bundle_digest=expected
    )
    assert installed.exists()


def test_skill_activation_fails_closed_for_mutable(monkeypatch, tmp_path):
    import tools.skills_hub as sh
    from tools.skills_hub import SkillBundle, install_from_quarantine
    from types import SimpleNamespace

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    qroot = sh._quarantine_dir()
    qdir = qroot / "demo"
    qdir.mkdir(parents=True)
    (qdir / "SKILL.md").write_text("# demo\n", encoding="utf-8")
    bundle = SkillBundle(
        name="demo", files={"SKILL.md": "# demo\n"}, source="github",
        identifier="o/r", trust_level="community", metadata={"ref": "main"},
    )
    # The gate fires before scan_result is used, so a dummy is fine.
    scan = SimpleNamespace(verdict="clean", scan_provenance=None)
    with pytest.raises(ValueError) as exc:
        install_from_quarantine(qdir, "demo", "", bundle, scan)
    assert "mutable" in str(exc.value).lower() or "identity" in str(exc.value).lower()


# --- profile distribution #ref --------------------------------------------

def test_profile_split_ref():
    from hermes_cli.profile_distribution import _split_git_ref

    assert _split_git_ref("https://github.com/a/b") == ("https://github.com/a/b", None)
    assert _split_git_ref("https://github.com/a/b#" + "a" * 40) == ("https://github.com/a/b", "a" * 40)


def test_profile_mutable_clone_fails_closed(monkeypatch, tmp_path):
    from hermes_cli import profile_distribution as pd

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})

    def forbidden(*a, **k):
        raise AssertionError("git must not run for a fail-closed profile clone")

    monkeypatch.setattr(pd.subprocess, "run", forbidden)
    with pytest.raises(pd.DistributionError):
        pd._git_clone("https://github.com/example/profile", tmp_path / "d")


def test_profile_pinned_sha_passes_gate(monkeypatch, tmp_path):
    from hermes_cli import profile_distribution as pd

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    calls = {"n": 0}

    def fake_run(args, **k):
        calls["n"] += 1
        from types import SimpleNamespace

        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"") if "rev-parse" not in args else SimpleNamespace(returncode=0, stdout="a" * 40, stderr="")

    # rev-parse needs text stdout; make a smarter stub
    def smart_run(args, **k):
        from types import SimpleNamespace

        calls["n"] += 1
        if "rev-parse" in args:
            return SimpleNamespace(returncode=0, stdout="b" * 40, stderr="")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(pd.subprocess, "run", smart_run)
    # A pinned SHA must pass the gate (no compat opt-in needed) and clone.
    resolved = pd._git_clone("https://github.com/example/profile#" + "a" * 40, tmp_path / "d")
    assert resolved == "b" * 40
    assert calls["n"] >= 1
