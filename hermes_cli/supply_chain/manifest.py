"""Release-manifest schema, parsing, and structural validation.

The manifest is the repository-owned, reviewable record of exactly which
bootstrap artifact every Hermes-managed path is allowed to fetch. It is
consumed two ways:

* **In-tree / installed** — read from the committed source tree. It is trusted
  because it is reviewed code (the pre-established anchor). The verifier still
  enforces freshness, sequence, floors, and revocation.
* **Fresh download** — a manifest pulled over the network must first have its
  attestation verified against the pinned release-workflow identity (see
  :mod:`hermes_cli.supply_chain.verifier`) before any field is trusted.

A digest may be *present* (bytes can be verified) or *unavailable* (no reviewed
digest exists yet). ``unavailable`` never silently downgrades to "download
anyway" — the verifier fails closed. A component may instead (or additionally)
carry an independent ``provenance`` identity (Sigstore keyless OIDC), which is a
real trust anchor even when a byte digest has not been committed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .errors import ManifestError

SCHEMA_VERSION = 1

# Trust classes (see docs/security/supply-chain-trust-root.md).
TRUST_RELEASE_VERIFIED = "release_verified"
TRUST_OPERATOR_MANAGED = "operator_managed"
TRUST_TRANSPORT_TRUSTED = "transport_trusted"
TRUST_FIRST_PARTY_GIT = "first_party_git"
TRUST_CLASSES = (
    TRUST_RELEASE_VERIFIED,
    TRUST_OPERATOR_MANAGED,
    TRUST_TRANSPORT_TRUSTED,
    TRUST_FIRST_PARTY_GIT,
)

DIGEST_PRESENT = "present"
DIGEST_UNAVAILABLE = "unavailable"
DIGEST_ALGORITHMS = ("sha256", "sha384", "sha512")

# Canonical hosts an artifact URL may point at. A URL outside this set is a
# manifest error — it forces review before a new download origin is trusted.
CANONICAL_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "nodejs.org",
        "astral.sh",
        "files.pythonhosted.org",
        "pypi.org",
        "registry.npmjs.org",
        "playwright.azureedge.net",
        "playwright.download.prss.microsoft.com",
    }
)


def _require(obj: dict, key: str, where: str) -> Any:
    if key not in obj:
        raise ManifestError(f"{where}: missing required key '{key}'")
    return obj[key]


def _parse_ts(value: str, where: str) -> datetime:
    text = (value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ManifestError(f"{where}: invalid timestamp '{value}'") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class Signer:
    """The release-manifest signing identity (Sigstore keyless OIDC)."""

    type: str
    issuer: str
    identity_regexp: str
    repository: str
    workflow: str
    fingerprint_publication: str

    @classmethod
    def from_dict(cls, data: dict) -> "Signer":
        where = "signer"
        return cls(
            type=str(_require(data, "type", where)),
            issuer=str(_require(data, "issuer", where)),
            identity_regexp=str(_require(data, "identity_regexp", where)),
            repository=str(_require(data, "repository", where)),
            workflow=str(_require(data, "workflow", where)),
            fingerprint_publication=str(
                _require(data, "fingerprint_publication", where)
            ),
        )


@dataclass(frozen=True)
class Provenance:
    """An independent upstream Sigstore identity for an artifact/component."""

    type: str
    issuer: str
    identity_regexp: str

    @classmethod
    def from_dict(cls, data: dict) -> "Provenance":
        where = "provenance"
        return cls(
            type=str(_require(data, "type", where)),
            issuer=str(_require(data, "issuer", where)),
            identity_regexp=str(_require(data, "identity_regexp", where)),
        )


@dataclass(frozen=True)
class Digest:
    algorithm: str
    value: str | None
    status: str

    @property
    def present(self) -> bool:
        return self.status == DIGEST_PRESENT and bool(self.value)

    @classmethod
    def from_dict(cls, data: dict) -> "Digest":
        where = "digest"
        algorithm = str(_require(data, "algorithm", where)).lower()
        if algorithm not in DIGEST_ALGORITHMS:
            raise ManifestError(f"{where}: unsupported algorithm '{algorithm}'")
        status = str(data.get("status", DIGEST_PRESENT)).lower()
        if status not in (DIGEST_PRESENT, DIGEST_UNAVAILABLE):
            raise ManifestError(f"{where}: invalid status '{status}'")
        value = data.get("value")
        if status == DIGEST_PRESENT:
            if not isinstance(value, str) or not value:
                raise ManifestError(f"{where}: present digest needs a value")
            _validate_hex_digest(algorithm, value)
        return cls(algorithm=algorithm, value=value, status=status)


_DIGEST_HEX_LEN = {"sha256": 64, "sha384": 96, "sha512": 128}


def _validate_hex_digest(algorithm: str, value: str) -> None:
    expected = _DIGEST_HEX_LEN[algorithm]
    if len(value) != expected or any(c not in "0123456789abcdef" for c in value):
        raise ManifestError(
            f"digest: '{algorithm}' value must be {expected} lowercase hex chars"
        )


@dataclass(frozen=True)
class Artifact:
    platform: str
    arch: str
    url: str
    digest: Digest
    members: tuple[str, ...] = ()
    # A10 provenance split: ``digest`` authenticates the URL BYTES (the archive
    # fetched from ``url`` — a .zip/.tar.gz/.tgz). ``member_digests`` pins the
    # digest of an EXTRACTED member (a file listed in ``members``). A download
    # verifier checks ``digest`` against the downloaded archive bytes; a stager
    # that consumes an already-extracted file checks the member digest. The two
    # are NOT interchangeable — a member digest must never be accepted as the
    # archive digest, or vice versa.
    member_digests: tuple[tuple[str, Digest], ...] = ()
    provenance: Provenance | None = None
    blocker: str | None = None
    operator_guidance: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Artifact":
        where = "artifact"
        prov = data.get("provenance")
        members = tuple(str(m) for m in data.get("members", ()))
        raw_member_digests = data.get("member_digests", {}) or {}
        if not isinstance(raw_member_digests, dict):
            raise ManifestError(f"{where}: member_digests must be a path->digest mapping")
        member_digests = tuple(
            (str(key), Digest.from_dict(value)) for key, value in raw_member_digests.items()
        )
        # Every member digest MUST name a listed member — a digest for an
        # unlisted path is a manifest error (it pins bytes nothing extracts).
        member_set = set(members)
        for key, _ in member_digests:
            if key not in member_set:
                raise ManifestError(
                    f"{where}: member_digest key '{key}' is not listed in members {members!r}"
                )
        return cls(
            platform=str(_require(data, "platform", where)),
            arch=str(_require(data, "arch", where)),
            url=str(_require(data, "url", where)),
            digest=Digest.from_dict(_require(data, "digest", where)),
            members=members,
            member_digests=member_digests,
            provenance=Provenance.from_dict(prov) if prov else None,
            blocker=data.get("blocker"),
            operator_guidance=data.get("operator_guidance"),
        )

    def member_digest(self, path: str) -> Digest | None:
        """The pinned digest of an extracted member, or None when not pinned."""
        for key, digest in self.member_digests:
            if key == path:
                return digest
        return None

    @property
    def has_anchor(self) -> bool:
        """True when bytes chain to a real anchor (digest OR provenance)."""
        return self.digest.present or self.provenance is not None


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    trust_class: str
    security_floor: str | None
    review_date: str | None
    eol: str | None
    artifacts: tuple[Artifact, ...]

    @classmethod
    def from_dict(cls, data: dict) -> "Component":
        where = f"component '{data.get('name', '?')}'"
        trust_class = str(_require(data, "trust_class", where))
        if trust_class not in TRUST_CLASSES:
            raise ManifestError(f"{where}: unknown trust_class '{trust_class}'")
        artifacts = tuple(
            Artifact.from_dict(a) for a in _require(data, "artifacts", where)
        )
        _reject_duplicate_platforms(artifacts, where)
        return cls(
            name=str(_require(data, "name", where)),
            version=str(_require(data, "version", where)),
            trust_class=trust_class,
            security_floor=data.get("security_floor"),
            review_date=data.get("review_date"),
            eol=data.get("eol"),
            artifacts=artifacts,
        )

    def artifact(self, platform: str, arch: str) -> Artifact | None:
        for art in self.artifacts:
            if art.platform == platform and art.arch == arch:
                return art
        return None


def _reject_duplicate_platforms(artifacts: Iterable[Artifact], where: str) -> None:
    seen: set[tuple[str, str]] = set()
    for art in artifacts:
        key = (art.platform, art.arch)
        if key in seen:
            raise ManifestError(f"{where}: duplicate platform/arch {key}")
        seen.add(key)


@dataclass(frozen=True)
class Revocation:
    component: str
    version: str | None
    max_sequence: int | None
    reason: str

    @classmethod
    def from_dict(cls, data: dict) -> "Revocation":
        where = "revocation"
        return cls(
            component=str(_require(data, "component", where)),
            version=data.get("version"),
            max_sequence=data.get("max_sequence"),
            reason=str(data.get("reason", "")),
        )

    def matches(self, component: str, version: str) -> bool:
        if self.component != component:
            return False
        if self.version is not None:
            return self.version == version
        return True


@dataclass
class ManifestMeta:
    schema_version: int
    sequence: int
    min_sequence: int
    issued_at: datetime
    expires_at: datetime
    signer: Signer
    revocations: tuple[Revocation, ...] = ()

    @classmethod
    def from_dict(cls, data: dict) -> "ManifestMeta":
        where = "manifest"
        schema_version = int(_require(data, "schema_version", where))
        if schema_version != SCHEMA_VERSION:
            raise ManifestError(
                f"{where}: unsupported schema_version {schema_version} "
                f"(expected {SCHEMA_VERSION})"
            )
        sequence = int(_require(data, "sequence", where))
        min_sequence = int(_require(data, "min_sequence", where))
        if sequence < min_sequence:
            raise ManifestError(
                f"{where}: sequence {sequence} below min_sequence {min_sequence}"
            )
        issued_at = _parse_ts(_require(data, "issued_at", where), "issued_at")
        expires_at = _parse_ts(_require(data, "expires_at", where), "expires_at")
        if expires_at <= issued_at:
            raise ManifestError(f"{where}: expires_at must be after issued_at")
        return cls(
            schema_version=schema_version,
            sequence=sequence,
            min_sequence=min_sequence,
            issued_at=issued_at,
            expires_at=expires_at,
            signer=Signer.from_dict(_require(data, "signer", where)),
            revocations=tuple(
                Revocation.from_dict(r) for r in data.get("revocations", ())
            ),
        )


@dataclass
class ReleaseManifest:
    meta: ManifestMeta
    components: tuple[Component, ...]
    source_path: Path | None = field(default=None, compare=False)

    @classmethod
    def from_dict(cls, data: dict, *, source_path: Path | None = None) -> "ReleaseManifest":
        manifest = data.get("manifest")
        if not isinstance(manifest, dict):
            raise ManifestError("top-level 'manifest' object is required")
        components_raw = data.get("components")
        if not isinstance(components_raw, list):
            raise ManifestError("top-level 'components' array is required")
        components = tuple(Component.from_dict(c) for c in components_raw)
        _reject_duplicate_components(components)
        return cls(
            meta=ManifestMeta.from_dict(manifest),
            components=components,
            source_path=source_path,
        )

    def component(self, name: str) -> Component | None:
        for comp in self.components:
            if comp.name == name:
                return comp
        return None

    def is_revoked(self, component: str, version: str) -> Revocation | None:
        for rev in self.meta.revocations:
            if rev.matches(component, version):
                if rev.max_sequence is None or self.meta.sequence <= rev.max_sequence:
                    return rev
        return None

    def iter_artifacts(self) -> Iterable[tuple[Component, Artifact]]:
        for comp in self.components:
            for art in comp.artifacts:
                yield comp, art


def _reject_duplicate_components(components: Iterable[Component]) -> None:
    seen: set[str] = set()
    for comp in components:
        if comp.name in seen:
            raise ManifestError(f"duplicate component '{comp.name}'")
        seen.add(comp.name)


def load_manifest(path: str | Path) -> ReleaseManifest:
    """Parse and structurally validate the manifest at *path*."""
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifest is not valid JSON: {exc}") from exc
    return ReleaseManifest.from_dict(raw, source_path=path)
