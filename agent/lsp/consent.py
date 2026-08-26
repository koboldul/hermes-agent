"""Versioned, affirmative consent gate for LSP auto-installation.

SEC-AUDIT-002 changed the *effective* default of ``lsp.install_strategy`` from
``auto`` to ``manual`` and requires affirmative, versioned operator consent
before Hermes will automatically install a language server.

The contract:

* ``install_strategy: auto`` is honoured **only** when
  ``lsp.auto_install_consent_version`` matches :data:`CONSENT_POLICY_VERSION`.
* Any ``auto`` value without a matching consent marker is treated as implicit
  default materialisation — not operator consent — and downgraded to effective
  ``manual``.  No missing config path may reconstruct ``auto``.
* Bumping :data:`CONSENT_POLICY_VERSION` (because the install trust boundary
  changed) invalidates every previously recorded consent until the operator
  re-affirms via ``hermes lsp enable-auto-install`` / ``hermes lsp setup``.

This module owns the single source of truth for that computation so the
manager, server context, installer, and CLI never re-derive ``auto`` from a raw
config value.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("agent.lsp.consent")

#: Consent policy version.  Bump whenever the auto-install trust boundary
#: changes (new ecosystem, changed environment allowlist, changed publication
#: verification).  Recorded consent below this value is stale and ignored.
CONSENT_POLICY_VERSION = 1

CONSENT_KEY = "auto_install_consent_version"
STRATEGY_KEY = "install_strategy"

_VALID_STRATEGIES = {"auto", "manual", "off"}


def _coerce_version(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def configured_strategy(lsp_cfg: Optional[Dict[str, Any]]) -> str:
    """Return the *configured* strategy string (before the consent gate)."""
    cfg = lsp_cfg if isinstance(lsp_cfg, dict) else {}
    raw = str(cfg.get(STRATEGY_KEY, "manual")).strip().lower()
    return raw if raw in _VALID_STRATEGIES else "manual"


def consent_satisfied(lsp_cfg: Optional[Dict[str, Any]]) -> bool:
    """True when recorded consent matches the current policy version."""
    cfg = lsp_cfg if isinstance(lsp_cfg, dict) else {}
    return _coerce_version(cfg.get(CONSENT_KEY)) == CONSENT_POLICY_VERSION


def effective_install_strategy(lsp_cfg: Optional[Dict[str, Any]]) -> str:
    """Return the effective strategy: ``"auto"`` or ``"manual"``.

    ``auto`` is returned **only** when the configured strategy is ``auto`` and
    versioned consent is satisfied.  ``off`` and unknown values collapse to
    ``manual``.  This is the one function every runtime path must use; nothing
    else may reconstruct ``auto``.
    """
    configured = configured_strategy(lsp_cfg)
    if configured == "auto" and consent_satisfied(lsp_cfg):
        return "auto"
    return "manual"


def effective_strategy_from_config(cfg: Optional[Dict[str, Any]]) -> str:
    """Convenience wrapper: read the ``lsp`` section out of a full config."""
    lsp_cfg = (cfg or {}).get("lsp") if isinstance(cfg, dict) else None
    return effective_install_strategy(lsp_cfg if isinstance(lsp_cfg, dict) else {})


def record_consent() -> None:
    """Persist affirmative consent: set ``auto`` + current consent version."""
    from hermes_cli.config import read_raw_config, save_config

    config = read_raw_config() or {}
    lsp = config.get("lsp")
    if not isinstance(lsp, dict):
        lsp = {}
    lsp[STRATEGY_KEY] = "auto"
    lsp[CONSENT_KEY] = CONSENT_POLICY_VERSION
    config["lsp"] = lsp
    # Full-document replacement (config already holds every on-disk section);
    # merge_existing would deep-merge the on-disk copy back in and could
    # resurrect a key a future revoke removed.
    save_config(config)
    logger.info("Recorded LSP auto-install consent (policy v%d)", CONSENT_POLICY_VERSION)


def revoke_consent() -> None:
    """Return to effective manual: set ``manual`` + clear the consent marker."""
    from hermes_cli.config import read_raw_config, save_config

    config = read_raw_config() or {}
    lsp = config.get("lsp")
    if not isinstance(lsp, dict):
        lsp = {}
    lsp[STRATEGY_KEY] = "manual"
    lsp.pop(CONSENT_KEY, None)
    config["lsp"] = lsp
    # Full-document replacement so the popped consent key is not resurrected
    # by a deep-merge of the on-disk file.
    save_config(config)
    logger.info("Revoked LSP auto-install consent")


__all__ = [
    "CONSENT_POLICY_VERSION",
    "CONSENT_KEY",
    "STRATEGY_KEY",
    "configured_strategy",
    "consent_satisfied",
    "effective_install_strategy",
    "effective_strategy_from_config",
    "record_consent",
    "revoke_consent",
]
