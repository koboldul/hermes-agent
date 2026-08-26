"""Behavioral fail-closed tests for binary/runtime installers gated in WP4:
iron-proxy, bws, Android psutil, managed Python. Config-driven — no env vars."""

from __future__ import annotations

import pytest


def _set_config(monkeypatch, cfg):
    from hermes_cli.supply_chain import gate

    monkeypatch.setattr(gate, "_sc_config", lambda: cfg)


def test_iron_proxy_install_fails_closed_by_default(monkeypatch, tmp_path):
    from agent.proxy_sources import iron_proxy as ip

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    monkeypatch.setattr(ip, "_hermes_bin_dir", lambda: tmp_path)

    def forbidden(*a, **k):
        raise AssertionError("iron-proxy must not download under the secure default")

    monkeypatch.setattr(ip, "_http_download", forbidden)
    with pytest.raises(RuntimeError) as exc:
        ip.install_iron_proxy(force=True)
    assert "iron-proxy" in str(exc.value)


def test_iron_proxy_install_allowed_when_scoped(monkeypatch, tmp_path):
    from agent.proxy_sources import iron_proxy as ip

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": ["iron-proxy"]})
    monkeypatch.setattr(ip, "_hermes_bin_dir", lambda: tmp_path)

    def fake_download(url, dest):
        raise OSError("stop after the gate (download reached)")

    monkeypatch.setattr(ip, "_http_download", fake_download)
    # When allowed, the gate must NOT block. It then reaches the download (OSError)
    # or, on a platform without a published binary, a non-gate RuntimeError.
    with pytest.raises((OSError, RuntimeError)) as exc:
        ip.install_iron_proxy(force=True)
    assert "disabled by default" not in str(exc.value)


def test_bws_install_fails_closed_by_default(monkeypatch, tmp_path):
    from agent.secret_sources import bitwarden as bw

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    monkeypatch.setattr(bw, "_hermes_bin_dir", lambda: tmp_path)

    def forbidden(*a, **k):
        raise AssertionError("bws must not download under the secure default")

    monkeypatch.setattr(bw, "_http_download", forbidden)
    with pytest.raises(RuntimeError) as exc:
        bw.install_bws(force=True)
    assert "bws" in str(exc.value)


def test_bws_install_scoped_allows_only_bws(monkeypatch, tmp_path):
    from agent.secret_sources import bitwarden as bw

    # Allowing iron-proxy must NOT enable bws (scoped consent).
    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": ["iron-proxy"]})
    monkeypatch.setattr(bw, "_hermes_bin_dir", lambda: tmp_path)

    def forbidden(*a, **k):
        raise AssertionError("bws must not download when only iron-proxy is allowed")

    monkeypatch.setattr(bw, "_http_download", forbidden)
    with pytest.raises(RuntimeError):
        bw.install_bws(force=True)


def test_android_psutil_main_fails_closed_by_default(monkeypatch):
    import importlib.util
    from pathlib import Path

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    repo = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "install_psutil_android", repo / "scripts" / "install_psutil_android.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def forbidden(*a, **k):
        raise AssertionError("psutil sdist must not download under the secure default")

    monkeypatch.setattr(mod.urllib.request, "urlretrieve", forbidden)
    monkeypatch.setattr("sys.argv", ["install_psutil_android.py"])
    assert mod.main() == 1


def test_managed_python_disabled_by_default(monkeypatch):
    from hermes_cli.supply_chain.gate import compat_opt_in

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    assert compat_opt_in("managed-python") is False
    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": ["managed-python"]})
    assert compat_opt_in("managed-python") is True


# --- Chromium / Agent Browser auto-install --------------------------------

def test_chromium_autoinstall_fails_closed_by_default(monkeypatch):
    """The ~170MB Chromium/agent-browser binary download must not run under the
    secure default — no subprocess, previous state untouched."""
    import tools.browser_tool as bt

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    monkeypatch.setattr(bt, "_chromium_autoinstall_attempted", False, raising=False)
    monkeypatch.setattr(bt, "_running_in_docker", lambda: False)

    def forbidden(*a, **k):
        raise AssertionError(
            "Chromium/agent-browser must not auto-install under the secure default"
        )

    monkeypatch.setattr(bt.subprocess, "run", forbidden)
    assert bt._maybe_autoinstall_chromium() is False


def test_chromium_autoinstall_opens_only_when_lazy_scoped(monkeypatch):
    """With lazy installs explicitly allowed, the gate no longer blocks and the
    install subprocess is reached (intercepted here)."""
    import tools.browser_tool as bt

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": ["lazy-deps"]})
    monkeypatch.setattr(bt, "_chromium_autoinstall_attempted", False, raising=False)
    monkeypatch.setattr(bt, "_running_in_docker", lambda: False)
    monkeypatch.setattr(bt, "_find_agent_browser", lambda: "/usr/bin/agent-browser")
    monkeypatch.setattr(bt, "_is_npx_agent_browser_sentinel", lambda c: False)
    monkeypatch.delenv("HERMES_DISABLE_LAZY_INSTALLS", raising=False)
    reached = {"run": False}

    def fake_run(*a, **k):
        reached["run"] = True
        raise OSError("stop after the gate (install subprocess reached)")

    monkeypatch.setattr(bt.subprocess, "run", fake_run)
    bt._maybe_autoinstall_chromium()
    assert reached["run"] is True


def test_chromium_autoinstall_scoped_consent_does_not_leak(monkeypatch):
    """Allowing an unrelated component must NOT enable the Chromium download."""
    import tools.browser_tool as bt

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": ["uv"]})
    monkeypatch.setattr(bt, "_chromium_autoinstall_attempted", False, raising=False)
    monkeypatch.setattr(bt, "_running_in_docker", lambda: False)

    def forbidden(*a, **k):
        raise AssertionError("uv opt-in must not enable Chromium auto-install")

    monkeypatch.setattr(bt.subprocess, "run", forbidden)
    assert bt._maybe_autoinstall_chromium() is False


# --- feature / memory-provider / setup-hook pip installs ------------------

def test_feature_pip_install_fails_closed_by_default(monkeypatch):
    """The shared _pip_install chokepoint (neutts/whisper/piper/ddgs/langfuse/
    modal/daytona/qrcode/memory-provider deps) must not shell pip under the
    secure default — clean non-zero result, no subprocess."""
    from hermes_cli import tools_config

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})

    def forbidden(*a, **k):
        raise AssertionError("feature pip install must not run under the secure default")

    monkeypatch.setattr(tools_config.subprocess, "run", forbidden)
    result = tools_config._pip_install(["some-unpinned-pkg"])
    assert result.returncode == 1
    assert "disabled by default" in result.stderr


def test_feature_pip_install_opens_only_when_scoped(monkeypatch):
    """With feature-pip explicitly allowed, the gate no longer blocks and the
    pip ladder is reached (intercepted here)."""
    from types import SimpleNamespace

    import hermes_cli.managed_uv as managed_uv
    from hermes_cli import tools_config

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": ["feature-pip"]})
    monkeypatch.setattr(managed_uv, "ensure_uv", lambda: None)  # force the pip tier
    reached = {"run": False}

    def fake_run(cmd, **k):
        reached["run"] = True
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tools_config.subprocess, "run", fake_run)
    tools_config._pip_install(["some-pkg"])
    assert reached["run"] is True


def test_feature_pip_scoped_consent_does_not_leak(monkeypatch):
    """Allowing lazy-deps must NOT enable feature-pip installs (scoped)."""
    from hermes_cli import tools_config

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": ["lazy-deps"]})

    def forbidden(*a, **k):
        raise AssertionError("lazy-deps opt-in must not enable feature pip installs")

    monkeypatch.setattr(tools_config.subprocess, "run", forbidden)
    result = tools_config._pip_install(["some-pkg"])
    assert result.returncode == 1


# --- Termux update-time installers (psutil sdist, uv pip fallback) --------

def test_android_psutil_update_compat_fails_closed(monkeypatch):
    """The update-time Termux psutil sdist download must fail closed by default —
    no urlretrieve, no build."""
    import urllib.request

    from hermes_cli import update_cmd

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})

    def forbidden(*a, **k):
        raise AssertionError("psutil sdist must not download under the secure default")

    monkeypatch.setattr(urllib.request, "urlretrieve", forbidden)
    with pytest.raises(RuntimeError) as exc:
        update_cmd._install_psutil_android_compat(["pip"])
    assert "disabled by default" in str(exc.value)


def test_termux_uv_pip_fallback_skipped_by_default(monkeypatch):
    """The Termux 'pip install uv' wheel fallback must be skipped by default;
    an operator uv on PATH is still used in place (tested by returning None here
    when neither is present)."""
    from pathlib import Path
    from types import SimpleNamespace

    import hermes_cli.managed_uv as managed_uv
    from hermes_cli import update_cmd

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    monkeypatch.setattr(managed_uv, "resolve_uv", lambda: None)
    monkeypatch.setattr(
        update_cmd, "_m", lambda: SimpleNamespace(_is_termux_env=lambda: True, PROJECT_ROOT=Path("."))
    )
    monkeypatch.setattr(update_cmd.shutil, "which", lambda name: None)

    def forbidden(*a, **k):
        raise AssertionError("pip install uv must not run under the secure default")

    monkeypatch.setattr(update_cmd.subprocess, "run", forbidden)
    assert update_cmd._ensure_uv_for_termux(["pip"]) is None


# --- wake-word model payload ----------------------------------------------

def test_wake_word_model_download_fails_closed(monkeypatch, tmp_path):
    """The sherpa KWS model archive download+extract must fail closed by
    default — no urlretrieve."""
    import urllib.request

    import tools.wake_word as ww

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})

    def forbidden(*a, **k):
        raise AssertionError("wake-word model must not download under the secure default")

    monkeypatch.setattr(urllib.request, "urlretrieve", forbidden)
    with pytest.raises(RuntimeError) as exc:
        ww._ensure_sherpa_model(root=tmp_path)
    assert "disabled by default" in str(exc.value)


def test_wake_word_cached_model_used_in_place(monkeypatch, tmp_path):
    """An already-present model is used in place (operator-managed), with no
    gate and no download — old install preserved."""
    import urllib.request

    import tools.wake_word as ww

    _set_config(monkeypatch, {"enforce": True, "allow_unverified_components": []})
    target = tmp_path / ww._SHERPA_KWS_MODEL_DIR
    target.mkdir(parents=True)
    (target / "tokens.txt").write_text("x", encoding="utf-8")

    def forbidden(*a, **k):
        raise AssertionError("a cached model must be used in place, never re-downloaded")

    monkeypatch.setattr(urllib.request, "urlretrieve", forbidden)
    assert ww._ensure_sherpa_model(root=tmp_path) == target
