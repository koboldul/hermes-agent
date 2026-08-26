"""Machine-readable closure ledger.

Every audited download/execution path in the product is recorded here with its
trust owner, the manifest component it resolves to, the central verifier, the
activation point in code, a negative test, supported platforms, and its
migration state. CI (:mod:`scripts.ci.check_supply_chain`) fails when a
production installer path performs a mutable executable fetch that is not
represented in this ledger, so the ledger is the authoritative inventory of the
supply-chain surface rather than documentation that drifts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .errors import ManifestError

LEDGER_SCHEMA_VERSION = 1

MIGRATION_STATES = (
    "migrated",        # fetch routed through the verifier, byte/provenance anchored
    "chokepoint",      # verifier is consulted; anchor pending (fails closed under enforce)
    "operator_managed",  # external manager owns integrity; used in place, labelled
    "first_party_git",   # git checkout trust boundary (records resolved commit)
    "explicitly_disabled",  # automatic mutable route removed; operator-managed or explicit opt-in only
    "pending",         # audited, not yet migrated; carries an exact blocker
)

TRUST_OWNERS = (
    "release_verified",
    "operator_managed",
    "transport_trusted",
    "first_party_git",
)

_REQUIRED = (
    "id",
    "description",
    "source",
    "trust_owner",
    "activation_point",
    "negative_test",
    "platforms",
    "migration_state",
)


@dataclass(frozen=True)
class LedgerPath:
    id: str
    description: str
    source: str
    trust_owner: str
    activation_point: str
    negative_test: str
    platforms: tuple[str, ...]
    migration_state: str
    component: str | None = None
    verifier: str | None = None
    blocker: str | None = None
    mutable_fetch: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "LedgerPath":
        for key in _REQUIRED:
            if key not in data:
                raise ManifestError(f"ledger path missing '{key}': {data.get('id', '?')}")
        trust_owner = str(data["trust_owner"])
        if trust_owner not in TRUST_OWNERS:
            raise ManifestError(f"ledger path {data['id']}: bad trust_owner {trust_owner}")
        migration_state = str(data["migration_state"])
        if migration_state not in MIGRATION_STATES:
            raise ManifestError(
                f"ledger path {data['id']}: bad migration_state {migration_state}"
            )
        if migration_state == "pending" and not data.get("blocker"):
            raise ManifestError(f"ledger path {data['id']}: pending needs a blocker")
        return cls(
            id=str(data["id"]),
            description=str(data["description"]),
            source=str(data["source"]),
            trust_owner=trust_owner,
            activation_point=str(data["activation_point"]),
            negative_test=str(data["negative_test"]),
            platforms=tuple(str(p) for p in data["platforms"]),
            migration_state=migration_state,
            component=data.get("component"),
            verifier=data.get("verifier"),
            blocker=data.get("blocker"),
            mutable_fetch=bool(data.get("mutable_fetch", False)),
        )


@dataclass
class Ledger:
    schema_version: int
    paths: tuple[LedgerPath, ...]

    @classmethod
    def from_dict(cls, data: dict) -> "Ledger":
        version = int(data.get("schema_version", 0))
        if version != LEDGER_SCHEMA_VERSION:
            raise ManifestError(
                f"ledger schema_version {version} != {LEDGER_SCHEMA_VERSION}"
            )
        paths_raw = data.get("paths")
        if not isinstance(paths_raw, list):
            raise ManifestError("ledger 'paths' array is required")
        paths = tuple(LedgerPath.from_dict(p) for p in paths_raw)
        _reject_duplicate_ids(paths)
        return cls(schema_version=version, paths=paths)

    def sources(self) -> set[str]:
        return {p.source for p in self.paths}

    def covers(self, path: str) -> bool:
        """True when *path* is a ledgered source (exact or directory prefix)."""
        norm = path.replace("\\", "/")
        for entry in self.paths:
            src = entry.source.replace("\\", "/")
            if norm == src:
                return True
            if src.endswith("/") and norm.startswith(src):
                return True
        return False


def _reject_duplicate_ids(paths: Iterable[LedgerPath]) -> None:
    seen: set[str] = set()
    for entry in paths:
        if entry.id in seen:
            raise ManifestError(f"duplicate ledger path id '{entry.id}'")
        seen.add(entry.id)


def load_ledger(path: str | Path) -> Ledger:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ManifestError(f"ledger not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"ledger is not valid JSON: {exc}") from exc
    return Ledger.from_dict(raw)
