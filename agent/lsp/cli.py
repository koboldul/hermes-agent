"""``hermes lsp`` CLI subcommand.

Subcommands:

- ``status`` — show service state, configured servers, install status.
- ``install <server_id>`` — eagerly install one server's binary.
- ``install-all`` — try to install every server with a known recipe.
- ``restart`` — tear down running clients so the next edit re-spawns.
- ``which <server_id>`` — print the resolved binary path for one server.
- ``list`` — print the registry of supported servers.

The handlers are kept here (rather than in
``hermes_cli/main.py``) so the LSP module ships self-contained.
"""
from __future__ import annotations

import argparse
import sys


def register_subparser(subparsers: argparse._SubParsersAction) -> None:
    """Wire the ``hermes lsp`` subcommand tree into the main argparse."""
    parser = subparsers.add_parser(
        "lsp",
        help="Language Server Protocol management",
        description=(
            "Manage the LSP layer that powers post-write semantic "
            "diagnostics in write_file/patch."
        ),
    )
    sub = parser.add_subparsers(dest="lsp_command")

    sub_status = sub.add_parser("status", help="Show LSP service status")
    sub_status.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON"
    )

    sub_list = sub.add_parser("list", help="List supported language servers")
    sub_list.add_argument(
        "--installed-only",
        action="store_true",
        help="Only show servers whose binary is currently available",
    )

    sub_install = sub.add_parser("install", help="Install a server binary")
    sub_install.add_argument("server", help="Server id (e.g. pyright, gopls)")

    sub_install_all = sub.add_parser(
        "install-all",
        help="Install every server with a known auto-install recipe",
    )
    sub_install_all.add_argument(
        "--include-manual",
        action="store_true",
        help="Even attempt servers marked manual-install (best effort)",
    )

    sub.add_parser(
        "restart",
        help="Tear down running LSP clients (next edit re-spawns)",
    )

    sub_which = sub.add_parser("which", help="Print binary path for a server")
    sub_which.add_argument("server", help="Server id")

    sub_enable = sub.add_parser(
        "enable-auto-install",
        help="Record affirmative consent to auto-install the pinned LSP bundle",
    )
    sub_enable.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt (non-interactive consent)",
    )

    sub.add_parser(
        "disable-auto-install",
        help="Revoke auto-install consent (return to manual)",
    )

    sub.add_parser(
        "setup",
        help="Interactive LSP install-strategy setup",
    )

    sub_approve = sub.add_parser(
        "approve",
        help="Re-approve an exact operator binary path (bound to its digest)",
    )
    sub_approve.add_argument("server", help="Server id")
    sub_approve.add_argument(
        "--path", help="Absolute path to the operator-owned binary (single-binary servers)"
    )
    sub_approve.add_argument(
        "--host",
        help="Compound server: absolute path to the host interpreter (e.g. pwsh)",
    )
    sub_approve.add_argument(
        "--script",
        help="Compound server: absolute path to the bootstrap script "
        "(e.g. Start-EditorServices.ps1)",
    )

    parser.set_defaults(func=run_lsp_command)


def run_lsp_command(args: argparse.Namespace) -> int:
    """Top-level dispatcher for ``hermes lsp <subcommand>``."""
    sub = getattr(args, "lsp_command", None) or "status"
    try:
        if sub == "status":
            return _cmd_status(getattr(args, "json", False))
        if sub == "list":
            return _cmd_list(getattr(args, "installed_only", False))
        if sub == "install":
            return _cmd_install(args.server)
        if sub == "install-all":
            return _cmd_install_all(getattr(args, "include_manual", False))
        if sub == "restart":
            return _cmd_restart()
        if sub == "which":
            return _cmd_which(args.server)
        if sub == "enable-auto-install":
            return _cmd_enable_auto(getattr(args, "yes", False))
        if sub == "disable-auto-install":
            return _cmd_disable_auto()
        if sub == "setup":
            return _cmd_setup()
        if sub == "approve":
            return _cmd_approve(
                args.server,
                getattr(args, "path", None),
                host=getattr(args, "host", None),
                script=getattr(args, "script", None),
            )
        sys.stderr.write(f"unknown lsp subcommand: {sub}\n")
        return 2
    except KeyboardInterrupt:
        return 130


def _cmd_status(emit_json: bool) -> int:
    from agent.lsp import get_service
    from agent.lsp.servers import SERVERS
    from agent.lsp.install import detect_status

    svc = get_service()
    service_active = svc is not None
    info = svc.get_status() if svc is not None else {"enabled": False}
    strat = _strategy_state()

    if emit_json:
        import json
        payload = {
            "service": info,
            "strategy": strat,
            "registry": [
                dict(
                    {
                        "server_id": s.server_id,
                        "extensions": list(s.extensions),
                        "description": s.description,
                        "binary_status": detect_status(_recipe_pkg_for(s.server_id)),
                    },
                    **_server_resolution(s.server_id),
                )
                for s in SERVERS
            ],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0

    out = []
    out.append("LSP Service")
    out.append("===========")
    out.append(f"  enabled:           {info.get('enabled', False)}")
    out.append(f"  configured:        {strat['configured']}")
    out.append(f"  effective:         {strat['effective']}")
    out.append(
        f"  auto-install:      {'enabled' if strat['effective'] == 'auto' else 'disabled'}"
        f" (consent v{strat['consent_version']}"
        f"{'' if strat['consent_satisfied'] else ' — not recorded'}"
        f", policy v{strat['policy_version']})"
    )
    if strat["configured"] == "auto" and not strat["consent_satisfied"]:
        out.append(
            "    → run `hermes lsp enable-auto-install` to record affirmative "
            "consent for the current policy version"
        )
    elif strat["effective"] != "auto":
        out.append(
            "    → `hermes lsp enable-auto-install` installs the pinned, reviewed "
            "LSP bundle automatically on first use"
        )
    if service_active:
        out.append(f"  wait_mode:         {info.get('wait_mode')}")
        out.append(f"  wait_timeout:      {info.get('wait_timeout')}s")
        clients = info.get("clients") or []
        if clients:
            out.append(f"  active clients:    {len(clients)}")
            for c in clients:
                out.append(
                    f"    - {c['server_id']:20s} state={c['state']:10s} root={c['workspace_root']}"
                )
        else:
            out.append("  active clients:    none")
        broken = info.get("broken") or []
        if broken:
            out.append(f"  broken pairs:      {len(broken)}")
            for b in broken:
                out.append(f"    - {b}")
        disabled = info.get("disabled_servers") or []
        if disabled:
            out.append(f"  disabled in cfg:   {', '.join(disabled)}")

    # Surface backend-tool gaps that aren't visible in the registry table:
    # some servers spawn fine but emit no diagnostics without a sidecar
    # binary (bash-language-server -> shellcheck).
    backend_warnings = _backend_warnings()
    if backend_warnings:
        out.append("")
        out.append("Backend warnings")
        out.append("================")
        for line in backend_warnings:
            out.append(f"  ! {line}")
    out.append("")
    out.append("Registered Servers")
    out.append("==================")
    for s in SERVERS:
        pkg = _recipe_pkg_for(s.server_id)
        status = detect_status(pkg)
        marker = {
            "installed": "✓",
            "missing": "·",
            "manual-only": "?",
            "unverified": "!",
        }.get(status, " ")
        res = _server_resolution(s.server_id)
        ext_summary = ", ".join(list(s.extensions)[:4])
        if len(s.extensions) > 4:
            ext_summary += f", … (+{len(s.extensions) - 4})"
        out.append(
            f"  {marker} {s.server_id:24s} [{status:11s}] "
            f"src={res['source']:12s} "
            f"ver={res['installed_version'] or '-'}/{res['expected_version'] or '-'} "
            f"integ={res['integrity']}"
        )
        if ext_summary:
            out.append(f"      ext: {ext_summary}")
        if res["remediation"]:
            out.append(f"      → {res['remediation']}")
    sys.stdout.write("\n".join(out) + "\n")
    return 0


def _strategy_state() -> dict:
    """Return configured vs effective strategy and consent state."""
    from agent.lsp.consent import (
        CONSENT_KEY,
        CONSENT_POLICY_VERSION,
        configured_strategy,
        consent_satisfied,
        effective_install_strategy,
    )

    lsp_cfg: dict = {}
    try:
        from hermes_cli.config import load_config_readonly

        cfg = load_config_readonly()
        raw = (cfg.get("lsp") or {}) if isinstance(cfg, dict) else {}
        if isinstance(raw, dict):
            lsp_cfg = raw
    except Exception:
        lsp_cfg = {}
    return {
        "configured": configured_strategy(lsp_cfg),
        "effective": effective_install_strategy(lsp_cfg),
        "consent_version": lsp_cfg.get(CONSENT_KEY),
        "consent_satisfied": consent_satisfied(lsp_cfg),
        "policy_version": CONSENT_POLICY_VERSION,
    }


def _server_resolution(server_id: str) -> dict:
    """Resolve source, versions, integrity, remediation (strategy-aware).

    Reflects the execution policy: under effective ``auto`` an operator ``PATH``
    binary is reported as ``path-ignored`` because the resolver will not launch
    it (SEC-AUDIT-002 Alert 2) — only a verified managed / re-approved /
    locked-install binary runs.
    """
    from agent.lsp import manifest as _manifest
    from agent.lsp import provenance as _provenance
    from agent.lsp.install import _path_binary, _unverified_managed_present

    effective = _strategy_state()["effective"]
    pkg = _recipe_pkg_for(server_id)

    # Compound servers (host + bootstrap script) report the compound state.
    if pkg in _COMPOUND_SERVERS:
        integ = _provenance.integrity_state_for(pkg)
        resolved = _provenance.verify_compound_reapproved(pkg)
        res = {
            "source": "none",
            "path": None,
            "installed_version": None,
            "expected_version": None,
            "integrity": integ,
            "remediation": None,
        }
        if resolved:
            res["source"] = "reapproved"
            res["path"] = resolved.get("host")
            return res
        if effective == "auto":
            res["source"] = "path-ignored" if integ in {"mutated"} else "none"
            res["remediation"] = (
                "compound server; under auto approve BOTH components with "
                f"`hermes lsp approve {server_id} --host <pwsh> "
                "--script <Start-EditorServices.ps1>` (any mutation revokes it)"
            )
        else:
            res["remediation"] = (
                "manual mode resolves the host from PATH and the PSES bundle "
                "from config/PSES_BUNDLE_PATH/HERMES_HOME"
            )
        return res

    recipe = _manifest.get_recipe(pkg)
    marker_key = recipe.server_id if recipe is not None else pkg
    res = {
        "source": "none",
        "path": None,
        "installed_version": None,
        "expected_version": recipe.version if recipe else None,
        "integrity": _provenance.integrity_state(recipe) if recipe else "none",
        "remediation": None,
    }
    # Verified managed / re-approved marker (trusted in both modes).
    managed = (
        _provenance.verify_managed(recipe)
        if recipe is not None
        else _provenance.verify_reapproved(marker_key)
    )
    if managed:
        marker = _provenance.read_marker(marker_key) or {}
        res["source"] = "reapproved" if marker.get("source") == "reapproved" else "managed"
        res["path"] = managed
        res["installed_version"] = marker.get("version") or (recipe.version if recipe else None)
        return res
    on_path = _path_binary(recipe.bin if recipe is not None else server_id)
    if on_path:
        res["path"] = on_path
        if effective == "auto":
            res["source"] = "path-ignored"
            res["remediation"] = (
                "on PATH, but effective auto never launches arbitrary PATH; "
                f"re-approve it with `hermes lsp approve {server_id} --path {on_path}` "
                "or use manual mode"
            )
        else:
            res["source"] = "PATH"
        return res
    if recipe is None:
        return res
    if _unverified_managed_present(recipe):
        res["source"] = "unverified"
        res["remediation"] = (
            f"unverified managed binary — run `hermes lsp install {server_id}` "
            f"to reinstall from the locked manifest, or "
            f"`hermes lsp approve {server_id} --path <path>` to re-approve it"
        )
        return res
    if recipe.ecosystem == "manual":
        res["remediation"] = f"install {recipe.bin} manually and ensure it is on PATH"
    elif recipe.auto_installable:
        res["remediation"] = (
            f"run `hermes lsp install {server_id}`, or enable auto-install "
            f"with `hermes lsp enable-auto-install`"
        )
    else:
        res["remediation"] = (
            f"no committed lock graph yet — install {recipe.bin} manually and "
            f"ensure it is on PATH"
        )
    return res


def _cmd_list(installed_only: bool) -> int:
    from agent.lsp.servers import SERVERS
    from agent.lsp.install import detect_status

    for s in SERVERS:
        pkg = _recipe_pkg_for(s.server_id)
        status = detect_status(pkg)
        if installed_only and status != "installed":
            continue
        sys.stdout.write(
            f"{s.server_id:24s} [{status:11s}] {','.join(s.extensions)}\n"
        )
    return 0


def _cmd_install(server_id: str) -> int:
    from agent.lsp import manifest as _manifest
    from agent.lsp.install import resolve_binary, detect_status
    pkg = _recipe_pkg_for(server_id)
    pre_status = detect_status(pkg)
    if pre_status == "installed":
        sys.stdout.write(f"{server_id} already installed\n")
        return 0
    recipe = _manifest.get_recipe(pkg)
    if recipe is not None and recipe.ecosystem == "manual":
        sys.stderr.write(
            f"{server_id}: this server requires a manual install. See documentation.\n"
        )
        return 1
    if recipe is not None and not recipe.auto_installable:
        sys.stderr.write(
            f"{server_id}: no committed immutable lock graph for this server yet; "
            f"install {recipe.bin} manually and ensure it is on PATH.\n"
        )
        return 1
    sys.stdout.write(
        f"installing {server_id} (pkg={pkg}, version="
        f"{recipe.version if recipe else '?'}) from the pinned lock graph ...\n"
    )
    sys.stdout.flush()
    # Explicit operator install performs the immutable install regardless of
    # the background consent gate (the operator is acting deliberately).
    bin_path = resolve_binary(pkg, "auto")
    if bin_path is None:
        sys.stderr.write(f"{server_id}: install failed (see logs).\n")
        return 1
    sys.stdout.write(f"installed: {bin_path}\n")
    return 0


def _cmd_install_all(include_manual: bool) -> int:
    from agent.lsp.servers import SERVERS
    from agent.lsp import manifest as _manifest
    from agent.lsp.install import resolve_binary, detect_status

    rc = 0
    for s in SERVERS:
        pkg = _recipe_pkg_for(s.server_id)
        recipe = _manifest.get_recipe(pkg)
        if recipe is None:
            continue
        if recipe.ecosystem == "manual":
            if not include_manual:
                continue
            sys.stdout.write(f"  {s.server_id:24s} manual-install only, skipping\n")
            continue
        if not recipe.auto_installable:
            sys.stdout.write(
                f"  {s.server_id:24s} no committed lock graph, manual only\n"
            )
            continue
        if detect_status(pkg) == "installed":
            sys.stdout.write(f"  {s.server_id:24s} already installed\n")
            continue
        sys.stdout.write(f"  installing {s.server_id} (pkg={pkg}) ... ")
        sys.stdout.flush()
        path = resolve_binary(pkg, "auto")
        if path:
            sys.stdout.write(f"ok ({path})\n")
        else:
            sys.stdout.write("FAILED\n")
            rc = 1
    return rc


def _cmd_restart() -> int:
    from agent.lsp import shutdown_service

    shutdown_service()
    sys.stdout.write("LSP service shut down. Next edit will respawn clients.\n")
    return 0


def _cmd_which(server_id: str) -> int:
    res = _server_resolution(server_id)
    if res["source"] == "none":
        sys.stderr.write(f"{server_id}: not installed\n")
        if res["remediation"]:
            sys.stderr.write(f"  {res['remediation']}\n")
        return 1
    if res["source"] in {"unverified", "path-ignored"}:
        if res["source"] == "unverified":
            sys.stderr.write(
                f"{server_id}: an unverified managed binary exists but will not "
                f"be executed.\n"
            )
        else:
            sys.stderr.write(
                f"{server_id}: {res['path']} is on PATH but effective auto will "
                f"NOT launch it.\n"
            )
        if res["remediation"]:
            sys.stderr.write(f"  {res['remediation']}\n")
        return 1
    version = res["installed_version"] or "unknown"
    sys.stdout.write(f"{res['path']}\n")
    sys.stderr.write(f"  source={res['source']} version={version} integrity={res['integrity']}\n")
    return 0


def _cmd_enable_auto(assume_yes: bool) -> int:
    from agent.lsp.consent import CONSENT_POLICY_VERSION, record_consent

    sys.stdout.write(
        "Enabling LSP auto-install.\n"
        "\n"
        "Hermes will automatically install the pinned, reviewed LSP server\n"
        "bundle (exact versions, committed immutable lock graphs, verified\n"
        "integrity) into <HERMES_HOME>/lsp/ on first use in a supported\n"
        "workspace.\n"
        "\n"
        "Trust boundary:\n"
        "  • Installers and language servers run with a purpose-specific,\n"
        "    scrubbed environment — no provider keys, gateway tokens, cloud/\n"
        "    registry/CI credentials, or agent sockets are visible to them.\n"
        "  • Environment isolation protects process-visible credentials only.\n"
        "    A language server still has this user's filesystem and network\n"
        "    authority unless the whole process is separately isolated.\n"
        "  • Auto-install contacts the public package registries "
        "(registry.npmjs.org, proxy.golang.org) to fetch the pinned graph.\n"
        f"\nThis records consent for install policy version {CONSENT_POLICY_VERSION}.\n"
    )
    if not assume_yes and sys.stdin is not None and sys.stdin.isatty():
        try:
            reply = input("Enable auto-install now? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            reply = ""
        if reply not in {"y", "yes"}:
            sys.stdout.write("Left install strategy unchanged (manual).\n")
            return 1
    try:
        record_consent()
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"failed to record consent: {e}\n")
        return 1
    sys.stdout.write(
        f"✓ Recorded auto-install consent (policy v{CONSENT_POLICY_VERSION}); "
        "install_strategy set to 'auto'.\n"
    )
    return 0


def _cmd_disable_auto() -> int:
    from agent.lsp.consent import revoke_consent

    try:
        revoke_consent()
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"failed to update config: {e}\n")
        return 1
    sys.stdout.write(
        "✓ Auto-install disabled; install_strategy set to 'manual' and consent "
        "cleared. Existing installed servers are unaffected.\n"
    )
    return 0


def _cmd_setup() -> int:
    state = _strategy_state()
    sys.stdout.write(
        "LSP install-strategy setup\n"
        "==========================\n"
        f"  configured: {state['configured']}\n"
        f"  effective:  {state['effective']}\n\n"
    )
    if not (sys.stdin is not None and sys.stdin.isatty()):
        sys.stdout.write(
            "Non-interactive. Use `hermes lsp enable-auto-install` to allow "
            "automatic installation of the pinned reviewed bundle, or "
            "`hermes lsp disable-auto-install` to stay on manual (the secure "
            "default).\n"
        )
        return 0
    try:
        reply = input(
            "Enable automatic install of the pinned, reviewed LSP bundle? [y/N] "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        reply = ""
    if reply in {"y", "yes"}:
        return _cmd_enable_auto(assume_yes=True)
    return _cmd_disable_auto()


# Servers whose runtime trust is COMPOUND (multiple digest-bound artifacts).
_COMPOUND_SERVERS = {"powershell"}


def _cmd_approve(server_id: str, path, *, host=None, script=None) -> int:
    import os
    from agent.lsp import provenance as _provenance

    marker_key = _recipe_pkg_for(server_id)
    is_compound = marker_key in _COMPOUND_SERVERS or host is not None or script is not None

    if is_compound:
        if not host or not script:
            sys.stderr.write(
                f"approve: {server_id} is a compound server; both --host and "
                f"--script are required (e.g. --host <pwsh> "
                f"--script <Start-EditorServices.ps1>)\n"
            )
            return 1
        components = {"host": host, "script": script}
        resolved: dict = {}
        for name, p in components.items():
            ap = os.path.abspath(os.path.expanduser(p))
            if not os.path.exists(ap):
                sys.stderr.write(f"approve: {name}: no such file: {ap}\n")
                return 1
            resolved[name] = ap
        # The host must be executable; the script is read by the host.
        if not os.access(resolved["host"], os.X_OK):
            sys.stderr.write(f"approve: host not executable: {resolved['host']}\n")
            return 1
        try:
            marker = _provenance.record_compound_reapproval(marker_key, resolved)
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"approve failed: {e}\n")
            return 1
        sys.stdout.write(f"✓ Re-approved compound server {server_id}:\n")
        for name, meta in marker["components"].items():
            sys.stdout.write(f"    {name}: {meta['path']}\n      digest {meta['digest']}\n")
        sys.stdout.write(
            "  (auto mode launches this server only while EVERY component's "
            "digest matches; any mutation revokes it)\n"
        )
        return 0

    if not path:
        sys.stderr.write(f"approve: --path is required for {server_id}\n")
        return 1
    abspath = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(abspath):
        sys.stderr.write(f"approve: no such file: {abspath}\n")
        return 1
    if not os.access(abspath, os.X_OK):
        sys.stderr.write(f"approve: not executable: {abspath}\n")
        return 1
    # Key the marker by the manifest package so the strategy-aware resolver
    # (which looks it up by recipe/pkg) finds it.
    try:
        marker = _provenance.record_reapproval(marker_key, abspath)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"approve failed: {e}\n")
        return 1
    sys.stdout.write(
        f"✓ Re-approved {server_id} at {abspath}\n"
        f"  bound to digest {marker['bin_digest']}\n"
        f"  (this exact binary will be rejected if it is modified, and is the\n"
        f"   only PATH-style binary auto mode will launch for this server)\n"
    )
    return 0


def _recipe_pkg_for(server_id: str) -> str:
    """Map a registry ``server_id`` to its install-recipe package key."""
    # The mapping lives here (not in install.py) because it's a CLI
    # convenience layer.  Most server_ids are also their own recipe
    # key, but a few differ (e.g. ``vue-language-server`` →
    # ``@vue/language-server``).
    aliases = {
        "vue-language-server": "@vue/language-server",
        "astro-language-server": "@astrojs/language-server",
        "dockerfile-ls": "dockerfile-language-server-nodejs",
        "typescript": "typescript-language-server",
    }
    return aliases.get(server_id, server_id)


def _backend_warnings() -> list:
    """Return human-readable notes about LSP backend tools that are missing
    in a way that won't surface elsewhere.

    Some language servers ship as thin wrappers around an external CLI for
    actual diagnostics — they spawn cleanly but never emit any errors when
    the sidecar binary isn't on PATH.  bash-language-server / shellcheck
    is the load-bearing example.

    Returned strings are short, actionable, and include the install
    suggestion across common platforms.
    """
    import shutil as _shutil
    from agent.lsp.install import _existing_binary
    notes: list = []
    bash_installed = _existing_binary("bash-language-server") is not None
    if bash_installed and _shutil.which("shellcheck") is None:
        notes.append(
            "bash-language-server is installed but shellcheck is missing — "
            "diagnostics will be empty (apt: shellcheck, brew: shellcheck, "
            "scoop: shellcheck)."
        )
    return notes
