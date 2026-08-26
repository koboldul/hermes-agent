"""Behavioral tests for the secure-by-default uv bootstrap gate.

Assert that, with no explicit opt-in, the mutable Astral installer never runs:
Hermes prefers an operator-managed uv and otherwise fails closed. The legacy
installer runs only when the operator explicitly opts in.
"""

from __future__ import annotations

import pytest

from hermes_cli import managed_uv
from hermes_cli.supply_chain import current_arch, current_platform, get_verifier
from hermes_cli.supply_chain.errors import FailClosed
from hermes_cli.supply_chain.gate import enforce_enabled
from hermes_cli.supply_chain.verifier import Decision


@pytest.fixture(autouse=True)
def _clean_posture(monkeypatch):
    # The removed env vars have no effect on the config-only gate; delete them
    # defensively so no ambient value can interfere with these tests.
    monkeypatch.delenv("HERMES_SUPPLY_CHAIN_ENFORCE", raising=False)
    monkeypatch.delenv("HERMES_ALLOW_UNVERIFIED_BOOTSTRAP", raising=False)


def test_enforce_is_secure_by_default():
    assert enforce_enabled() is True


def test_uv_plan_fail_closed_under_enforce():
    plan = get_verifier().plan("uv", platform="linux", arch="x86_64", enforce=True)
    assert plan.decision is Decision.FAIL_CLOSED
    assert plan.guidance


def test_uv_plan_transport_compat_only_when_opted_in():
    plan = get_verifier().plan("uv", platform="linux", arch="x86_64", enforce=False)
    assert plan.decision is Decision.TRANSPORT_COMPAT
    assert not plan.release_verified


def test_install_uv_fails_closed_by_default_and_never_runs_installer(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("the mutable uv installer must not run by default")

    monkeypatch.setattr(managed_uv, "_install_uv_posix", forbidden)
    monkeypatch.setattr(managed_uv, "_install_uv_windows", forbidden)

    with pytest.raises(FailClosed) as exc:
        managed_uv._install_uv(tmp_path / "bin" / "uv")
    assert "uv" in str(exc.value)
    message = exc.value.operator_message().lower()
    assert "install" in message and "supply-chain" in message  # actionable guidance


def test_install_uv_runs_only_on_explicit_opt_in(tmp_path, monkeypatch, sc_config):
    sc_config["allow_unverified_components"] = ["uv"]  # scoped opt-in for uv only
    calls = {"n": 0}
    monkeypatch.setattr(managed_uv, "_install_uv_posix", lambda env: calls.__setitem__("n", calls["n"] + 1))
    monkeypatch.setattr(managed_uv, "_install_uv_windows", lambda env: calls.__setitem__("n", calls["n"] + 1))

    managed_uv._install_uv(tmp_path / "bin" / "uv")  # no raise

    assert calls["n"] == 1


def test_ensure_uv_prefers_operator_managed_uv(monkeypatch):
    monkeypatch.setattr(managed_uv, "resolve_uv", lambda: None)
    monkeypatch.setattr(managed_uv, "_probe_operator_uv", lambda: "/usr/bin/uv")

    def forbidden(*args, **kwargs):
        raise AssertionError("installer must not run when operator uv exists")

    monkeypatch.setattr(managed_uv, "_install_uv", forbidden)
    assert managed_uv._ensure_uv_path() == "/usr/bin/uv"


def test_ensure_uv_fails_closed_returns_none_without_operator(tmp_path, monkeypatch):
    monkeypatch.setattr(managed_uv, "resolve_uv", lambda: None)
    monkeypatch.setattr(managed_uv, "_probe_operator_uv", lambda: None)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    def forbidden(*args, **kwargs):
        raise AssertionError("installer must not run by default")

    monkeypatch.setattr(managed_uv, "_install_uv_posix", forbidden)
    monkeypatch.setattr(managed_uv, "_install_uv_windows", forbidden)

    assert managed_uv._ensure_uv_path() is None  # fail closed, graceful


def test_scoped_opt_in_does_not_leak_to_other_components(sc_config):
    # Allowing uv must not enable any unrelated mutable installer.
    from hermes_cli.supply_chain.gate import compat_opt_in

    sc_config["allow_unverified_components"] = ["uv"]
    assert compat_opt_in("uv") is True
    assert compat_opt_in("node") is False
    assert compat_opt_in("cua-driver") is False


def test_enforce_posture_follows_config(sc_config):
    sc_config["enforce"] = False
    assert managed_uv._supply_chain_enforce() is False
    sc_config["enforce"] = True
    assert managed_uv._supply_chain_enforce() is True


def test_uv_self_update_skipped_by_default(monkeypatch, sc_config):
    """`hermes update` must NOT run `uv self update` under the secure default —
    no network swap of the uv binary; the existing managed uv is preserved."""
    monkeypatch.setattr(managed_uv, "resolve_uv", lambda: "/usr/bin/uv")
    monkeypatch.setattr(managed_uv, "repair_vulnerable_runtime",
                        lambda *a, **k: managed_uv.RuntimeRepairResult("not-applicable"))
    monkeypatch.setattr(managed_uv, "_uv_self_update_is_fresh", lambda *a, **k: False)

    def forbidden(cmd, *a, **k):
        if isinstance(cmd, (list, tuple)) and "self" in cmd and "update" in cmd:
            raise AssertionError("uv self update must not run under the secure default")
        raise AssertionError(f"no subprocess expected: {cmd}")

    monkeypatch.setattr(managed_uv.subprocess, "run", forbidden)
    assert managed_uv.update_managed_uv() == "/usr/bin/uv"  # old install preserved


def test_uv_self_update_runs_only_on_opt_in(monkeypatch, sc_config):
    sc_config["allow_unverified_components"] = ["uv"]
    monkeypatch.setattr(managed_uv, "resolve_uv", lambda: "/usr/bin/uv")
    monkeypatch.setattr(managed_uv, "repair_vulnerable_runtime",
                        lambda *a, **k: managed_uv.RuntimeRepairResult("not-applicable"))
    monkeypatch.setattr(managed_uv, "_uv_self_update_is_fresh", lambda *a, **k: False)
    monkeypatch.setattr(managed_uv, "_touch_uv_self_update_stamp", lambda: None)
    reached = {"run": False}

    def fake_run(cmd, *a, **k):
        reached["run"] = True
        from types import SimpleNamespace
        return SimpleNamespace(returncode=0, stdout="uv 1.2.3", stderr="")

    monkeypatch.setattr(managed_uv.subprocess, "run", fake_run)
    managed_uv.update_managed_uv()
    assert reached["run"] is True


def test_current_host_identity_resolves():
    assert current_platform() in {"linux", "macos", "windows", None}
    assert current_arch() in {"x86_64", "aarch64", "x86", "armv7", None}
