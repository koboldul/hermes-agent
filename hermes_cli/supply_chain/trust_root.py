"""Compiled-in supply-chain trust root (WP4 A9).

The accepted signer identity — issuer, repository, workflow, and the certificate
identity regexp — is a CONSTANT in this reviewed source file. It is NEVER read
from a downloaded manifest: an attacker who can serve a manifest could otherwise
declare their own signer and have the verifier "verify" the attestation against
the attacker's identity. Trust is therefore anchored here, in code, and a
downloaded manifest's self-declared signer must EQUAL this before it is trusted.
"""

from __future__ import annotations

from dataclasses import dataclass

# The one pinned release identity. Mirrors supply-chain/manifest.json's signer
# block, but THIS copy is the authority for a downloaded manifest.
TRUSTED_ISSUER = "https://token.actions.githubusercontent.com"
TRUSTED_REPOSITORY = "NousResearch/hermes-agent"
TRUSTED_WORKFLOW = ".github/workflows/release-attest.yml"
TRUSTED_IDENTITY_REGEXP = (
    r"^https://github\.com/NousResearch/hermes-agent/"
    r"\.github/workflows/release-attest\.yml@refs/tags/v"
)


@dataclass(frozen=True)
class TrustedSigner:
    """A minimal signer identity for ``gh attestation verify`` — the compiled-in
    values, not anything a manifest declared."""

    issuer: str = TRUSTED_ISSUER
    repository: str = TRUSTED_REPOSITORY
    workflow: str = TRUSTED_WORKFLOW
    identity_regexp: str = TRUSTED_IDENTITY_REGEXP


TRUSTED_SIGNER = TrustedSigner()


def signer_matches_trust_root(signer) -> bool:
    """True only when a manifest's declared signer EXACTLY equals the compiled-in
    trust root. A downloaded manifest whose signer differs is rejected before any
    attestation check — its self-declared identity is not authority."""
    try:
        return (
            str(signer.issuer) == TRUSTED_ISSUER
            and str(signer.repository) == TRUSTED_REPOSITORY
            and str(signer.workflow) == TRUSTED_WORKFLOW
            and str(signer.identity_regexp) == TRUSTED_IDENTITY_REGEXP
        )
    except AttributeError:
        return False
