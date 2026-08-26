"""Central fail-closed gate for Hermes-managed install/update/repair paths.

Secure by default. When the release manifest cannot anchor a component to an
exact digest or an independent provenance identity, the mutable auto-install
route does **not** run. The gate instead:

1. prefers an existing **operator-managed** executable (used in place, never
   copied into managed storage or relabelled release-verified), and
2. otherwise **fails closed** with actionable operator guidance — no network,
   no execution, no extraction.

Running the legacy transport-trusted installer is possible only as an explicit,
visibly-labelled operator opt-in — a scoped
``security.supply_chain.allow_unverified_components: ["<id>"]`` entry (or
``enforce: false`` for a broad opt-out); pre-config shell/PowerShell installers
use the ``--allow-unverified-bootstrap`` CLI flag. It never writes a
release-verified marker.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from .errors import FailClosed
from .manifest import Artifact
from .verifier import Decision, SupplyChainVerifier

_DEFAULT_GUIDANCE = (
    "Install this component with your OS/version manager (it will be used in "
    "place), or explicitly allow it in config: security.supply_chain."
    "allow_unverified_components: [\"<component>\"] (or enforce: false for a "
    "broad opt-out). Pre-config installers accept --allow-unverified-bootstrap. "
    "See docs/security/supply-chain-migration.md."
)


class GateAction(str, Enum):
    PROCEED = "proceed"            # release-verified: download → verify → publish
    USE_OPERATOR = "use_operator"  # existing operator-managed executable; use in place
    RUN_COMPAT = "run_compat"      # explicit opt-in: run legacy mutable installer, labelled
    FAIL_CLOSED = "fail_closed"    # abort before any network/execution/extraction


@dataclass
class GateResult:
    action: GateAction
    component: str
    reason: str
    artifact: Optional[Artifact] = None
    operator_path: Optional[str] = None
    guidance: Optional[str] = None

    @property
    def release_verified(self) -> bool:
        return self.action is GateAction.PROCEED

    def raise_if_failed(self) -> "GateResult":
        if self.action is GateAction.FAIL_CLOSED:
            raise FailClosed(
                f"{self.component}: {self.reason}",
                component=self.component,
                reason=self.reason,
                guidance=self.guidance or _DEFAULT_GUIDANCE,
            )
        return self


def _sc_config() -> dict:
    """Return the ``security.supply_chain`` config dict (empty on any error)."""
    try:
        from hermes_cli.config import load_config_readonly

        return (load_config_readonly().get("security", {}) or {}).get("supply_chain", {}) or {}
    except Exception:
        return {}


def enforce_enabled() -> bool:
    """Master supply-chain posture. **Secure by default (True).**

    Controlled ONLY by ``security.supply_chain.enforce`` in config.yaml — there
    is no environment-variable user interface. An unreadable config fails closed
    (enforce stays True). Pre-config shell/PowerShell installers use the
    ``--allow-unverified-bootstrap`` CLI flag instead.
    """
    return bool(_sc_config().get("enforce", True))


def _allow_unverified_components() -> set[str]:
    raw = _sc_config().get("allow_unverified_components", []) or []
    return {str(c).strip().lower() for c in raw}


def compat_opt_in(component: str | None = None) -> bool:
    """True only when *this* component's unverified installer is explicitly
    allowed. **Scoped** — allowing one component/manager never enables unrelated
    auto-downloads, and lowering the global ``enforce`` posture NEVER authorizes
    an installer on its own.

    Authorization (config only) requires an explicit per-component allow-list
    entry:
      * ``security.supply_chain.allow_unverified_components: ["uv", ...]`` —
        per-component allow-list; the sentinel ``"*"`` is an explicit
        allow-all (discouraged, but a deliberate list choice).

    ``security.supply_chain.enforce: false`` does NOT authorize anything here.
    It may lower the *verifier's* enforcement posture (see ``enforce_enabled``),
    but a component still fails closed unless it is named in the allow-list.
    This prevents a single global switch from silently re-enabling every mutable
    installer at once.
    """
    allowed = _allow_unverified_components()
    if "*" in allowed:
        return True
    return component is not None and str(component).strip().lower() in allowed


def guard_install(
    component: str,
    *,
    platform: str | None,
    arch: str | None,
    operator_probe: Callable[[], Optional[str]] | None = None,
    verifier: SupplyChainVerifier | None = None,
    enforce: bool | None = None,
    guidance: str | None = None,
) -> GateResult:
    """Decide what a managed installer path may do for *component*.

    ``operator_probe`` returns the path of an existing operator-managed
    executable, or ``None``. It is consulted for every non-release-verified
    outcome so an already-installed tool is preferred over both failing closed
    and running the mutable installer.
    """
    if verifier is None:
        from . import get_verifier

        verifier = get_verifier()
    if enforce is None:
        # Scoped: this component's mutable installer is enforced unless THIS
        # component was explicitly allowed. Allowing one never enables others.
        enforce = not compat_opt_in(component)

    guidance = guidance or _DEFAULT_GUIDANCE

    try:
        plan = verifier.plan(component, platform=platform, arch=arch, enforce=enforce)
    except Exception as exc:  # manifest/verifier failure
        operator = operator_probe() if operator_probe else None
        if operator:
            return GateResult(
                GateAction.USE_OPERATOR, component,
                f"verifier unavailable ({exc}); using operator-managed executable",
                operator_path=operator,
            )
        if enforce:
            return GateResult(
                GateAction.FAIL_CLOSED, component,
                f"verifier unavailable: {exc}", guidance=guidance,
            )
        return GateResult(
            GateAction.RUN_COMPAT, component,
            f"verifier unavailable ({exc}); explicit compatibility opt-in",
        )

    if plan.decision is Decision.PROCEED:
        # A6: guard_install is PLAN-ONLY. PROCEED means plan() verified the
        # compiled-in trust root (for a downloaded manifest) + freshness and the
        # artifact carries a digest/provenance anchor. It DOES NOT commit any
        # state here: the anti-rollback high-water mark is advanced only AFTER a
        # successful atomic publish, inside publish_release_verified() — committing
        # before the caller's download/verify/publish would advance the mark for
        # an install that may still fail. The caller MUST route the fetch through
        # publish_release_verified() / publish_component(), which re-verifies the
        # trust root + rechecks the high-water UNDER the lock and commits after
        # the swap. See hermes_cli/supply_chain/publish_cli.py (the real sink).
        return GateResult(
            GateAction.PROCEED, component, plan.reason, artifact=plan.artifact
        )

    operator = operator_probe() if operator_probe else None
    if operator:
        return GateResult(
            GateAction.USE_OPERATOR, component,
            "existing operator-managed executable used in place",
            operator_path=operator, artifact=plan.artifact,
        )

    if plan.decision is Decision.TRANSPORT_COMPAT:
        # Reached only when the operator explicitly lowered enforce.
        return GateResult(
            GateAction.RUN_COMPAT, component, plan.reason,
            artifact=plan.artifact, guidance=plan.guidance,
        )

    # OPERATOR_MANAGED without an executable, or FAIL_CLOSED.
    return GateResult(
        GateAction.FAIL_CLOSED, component, plan.reason,
        guidance=plan.guidance or guidance,
    )
