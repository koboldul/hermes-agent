"""Typed errors for the supply-chain verification subsystem.

Every failure mode a consumer must distinguish has its own class so callers can
choose the right action: abort silently, print operator guidance, or fall back
to an explicitly-labelled compatibility path. ``FailClosed`` is the one that
carries human-actionable guidance because it is the failure an operator is
expected to resolve (install via an OS package, populate a committed digest,
etc.).
"""

from __future__ import annotations


class SupplyChainError(Exception):
    """Base class for every supply-chain verification failure."""


class ManifestError(SupplyChainError):
    """The release manifest is malformed, expired, replayed, or downgraded.

    Raised before any download/execution — a bad manifest must never reach the
    artifact-fetch stage.
    """


class TrustRootError(SupplyChainError):
    """A downloaded manifest or artifact did not chain to the trust anchor.

    Same-channel checksums, keys, and signatures produce this error: they are
    metadata, not proof of authenticity.
    """


class StateCorruptError(SupplyChainError):
    """The persisted anti-rollback state is unreadable/corrupt.

    Fails closed rather than silently resetting the high-water mark to zero
    (which would re-open replay/downgrade). Requires explicit recovery.
    """


class VerificationError(SupplyChainError):
    """A staged artifact failed digest or archive-member validation.

    Raised strictly *before* extraction or execution so a mutated archive is
    rejected without ever running.
    """


class FailClosed(SupplyChainError):
    """No release-verified artifact could be produced; abort with guidance.

    This is the mandated terminal state when an exact digest/anchor is
    unavailable. It never silently downloads or executes a mutable response.
    """

    def __init__(
        self,
        message: str,
        *,
        component: str | None = None,
        version: str | None = None,
        reason: str | None = None,
        guidance: str | None = None,
    ) -> None:
        super().__init__(message)
        self.component = component
        self.version = version
        self.reason = reason
        self.guidance = guidance

    def operator_message(self) -> str:
        """Return a multi-line, non-sensitive message for an operator."""
        lines = [str(self)]
        if self.component:
            ident = self.component
            if self.version:
                ident = f"{self.component} {self.version}"
            lines.append(f"  component: {ident}")
        if self.reason:
            lines.append(f"  reason: {self.reason}")
        if self.guidance:
            lines.append(f"  next step: {self.guidance}")
        return "\n".join(lines)
