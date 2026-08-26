"""Two-step propose -> activate flow for hub-skill installation (A4 - Skills XPIA).

A ``postMessage`` from the embedded Skills-Hub iframe is a PROPOSAL, never an
authorization. The trusted parent UI must:

  1. POST ``/api/skills/hub/propose {identifier}``
       -> the server fetches the bundle, scans it, quarantines it, computes the
          TRANSPORT-RESOLVED commit (:func:`tools.skills_hub.bundle_exact_identity`)
          and the deterministic whole-bundle digest
          (:func:`tools.skills_hub._whole_bundle_digest`), stores the quarantined
          artifact keyed by an opaque single-use ``proposal_id``, and returns ONLY
          non-secret identity ``{proposal_id, name, identifier, source, commit,
          digest, policy}``.
  2. Show that resolved commit + digest to the user in a trusted parent dialog.
  3. POST ``/api/skills/hub/activate {proposal_id, commit, digest}``
       -> the server ATOMICALLY consumes the stored proposal, re-verifies that the
          confirmed commit+digest still equal the stored values AND that the
          on-disk quarantined tree still hashes to the stored tree digest, and only
          then installs from the SAME quarantined artifact through the WP4
          activation gate (:func:`tools.skills_hub.install_from_quarantine` with
          ``activation_accepted=True`` and ``expected_bundle_digest``).

Security properties enforced here (each has a behavior test):

  * ``skip_confirm`` / a raw remote message can NEVER become ``activation_accepted``
    - the activate call must carry the exact commit+digest the user confirmed, and
    that acceptance is minted only inside :func:`activate_proposal` after the
    identity comparison passes.
  * Commit drift -> reject.  Digest drift -> reject.
  * Replay (an unknown or already-consumed ``proposal_id``) -> reject.
  * On-disk mutation of the quarantined tree between propose and activate ->
    reject (the tree is re-hashed at activation).
  * A scan verdict the install policy blocks -> reject.
  * Atomic consume: a ``proposal_id`` is usable exactly once.

The store is process-local and injectable so tests never touch the network,
disk, or the real skill installer.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Errors — each carries a stable ``reason`` code the HTTP layer maps to a
# 4xx and the UI can branch on. None of them leak secret material.
# ---------------------------------------------------------------------------
class ProposalError(Exception):
    """Base class for propose/activate failures."""

    reason = "proposal-error"

    def __init__(self, message: str = "", *, reason: Optional[str] = None):
        super().__init__(message or self.reason)
        if reason is not None:
            self.reason = reason


class ProposalNotFound(ProposalError):
    """The requested skill identifier did not resolve to a fetchable bundle."""

    reason = "not-found"


class ProposalReplay(ProposalError):
    """The proposal_id is unknown or was already consumed (replay/expiry)."""

    reason = "replay"


class CommitDrift(ProposalError):
    """The confirmed commit no longer matches the proposed commit."""

    reason = "commit-drift"


class DigestDrift(ProposalError):
    """The confirmed digest no longer matches the proposed digest."""

    reason = "digest-drift"


class BundleMutation(ProposalError):
    """The on-disk quarantined tree changed after it was proposed."""

    reason = "mutation"


class PolicyBlocked(ProposalError):
    """The install policy blocked activation of this scan verdict."""

    reason = "policy-blocked"


# ---------------------------------------------------------------------------
# Stored proposal record + single-use store
# ---------------------------------------------------------------------------
@dataclass
class Proposal:
    """A quarantined, scanned bundle awaiting explicit trusted-UI confirmation."""

    proposal_id: str
    identifier: str
    name: str
    source: str
    # TRANSPORT-RESOLVED 40-hex commit, or ``None`` when the source is
    # network/mutable and no fetcher recorded one. A ``None`` commit means the
    # WP4 gate will require an expected-digest match (which we always supply).
    commit: Optional[str]
    # Deterministic whole-bundle sha256 (``_whole_bundle_digest``) — the value
    # shown to the user and enforced by the WP4 gate at install.
    digest: str
    # Independent digest of the quarantined tree AS WRITTEN TO DISK, snapshotted
    # at propose time. Re-hashed at activate to catch any on-disk mutation.
    tree_digest: str
    quarantine_path: Path
    bundle: Any
    scan_result: Any
    scan_provenance: Dict[str, Any]
    category: str
    policy: str
    policy_reason: str
    created_at: float


DiscardFn = Callable[[Path], None]


def _default_discard(path: Path) -> None:
    """Best-effort removal of a quarantine tree (activation moves it away)."""
    try:
        import shutil

        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


class ProposalStore:
    """Thread-safe, single-use, TTL-bounded store of quarantined proposals.

    ``consume`` atomically pops a proposal so a ``proposal_id`` authorizes at
    most one activation — a second activate call (replay) finds nothing and
    fails closed. Expired and evicted entries have their quarantine trees
    discarded so a stale proposal can never later be re-hydrated from disk.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = 900.0,
        max_entries: int = 64,
        clock: Callable[[], float] = time.monotonic,
        discard: DiscardFn = _default_discard,
    ):
        self._lock = threading.Lock()
        self._items: "OrderedDict[str, Proposal]" = OrderedDict()
        self._ttl = float(ttl_seconds)
        self._max = int(max_entries)
        self._clock = clock
        self._discard = discard

    def put(self, proposal: Proposal) -> None:
        with self._lock:
            self._gc_locked()
            self._items[proposal.proposal_id] = proposal
            self._items.move_to_end(proposal.proposal_id)
            while len(self._items) > self._max:
                _, evicted = self._items.popitem(last=False)
                self._discard(evicted.quarantine_path)

    def consume(self, proposal_id: str) -> Optional[Proposal]:
        with self._lock:
            self._gc_locked()
            return self._items.pop(proposal_id, None)

    def __len__(self) -> int:  # pragma: no cover - trivial
        with self._lock:
            return len(self._items)

    def _gc_locked(self) -> None:
        now = self._clock()
        expired = [
            key for key, value in self._items.items() if now - value.created_at > self._ttl
        ]
        for key in expired:
            value = self._items.pop(key)
            self._discard(value.quarantine_path)


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------
def quarantine_tree_digest(root: Path) -> str:
    """Digest the on-disk quarantine EXACTLY as ``_whole_bundle_digest`` hashes a
    bundle: sorted relative POSIX path, then ``sha256(content)``.

    This reads the artifact that will actually be installed, so any byte-level
    mutation of a quarantined file between propose and activate changes the
    result and is rejected. Independent of the in-memory bundle digest so the
    two checks corroborate rather than share a single point of trust.
    """
    root = Path(root).resolve()
    entries = []
    for path in root.rglob("*"):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            entries.append((rel, path.read_bytes()))
    digest = hashlib.sha256()
    for rel, content in sorted(entries, key=lambda item: item[0]):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def _norm_commit(value: Optional[str]) -> str:
    return str(value or "").strip().lower()


def _norm_digest(value: Optional[str]) -> str:
    return str(value or "").strip().lower()


def _policy_label(allowed: Optional[bool]) -> str:
    if allowed is True:
        return "allow"
    if allowed is None:
        return "ask"
    return "block"


# ---------------------------------------------------------------------------
# Dependency bundle — the endpoint injects the real skills_hub functions; tests
# inject fakes. Keeping propose/activate pure over this makes both fully
# testable without network/disk/installer.
# ---------------------------------------------------------------------------
@dataclass
class ProposeDeps:
    # (identifier) -> (meta, bundle) | None. ``bundle`` may be None when the
    # identifier resolved metadata but no downloadable content.
    resolve_bundle: Callable[[str], Optional[Tuple[Any, Any]]]
    # (bundle) -> quarantine Path (writes files to disk).
    quarantine: Callable[[Any], Path]
    # (quarantine_path, scan_source) -> scan_result.
    scan: Callable[[Path, str], Any]
    # (scan_result) -> (allowed: bool|None, reason: str).
    policy: Callable[[Any], Tuple[Optional[bool], str]]
    # (bundle) -> whole-bundle digest hex.
    digest_of: Callable[[Any], str]
    # (bundle) -> transport-resolved commit hex | None.
    commit_of: Callable[[Any], Optional[str]]
    # (quarantine_path) -> on-disk tree digest hex.
    tree_digest_of: Callable[[Path], str] = quarantine_tree_digest
    id_factory: Callable[[], str] = lambda: secrets.token_urlsafe(24)
    clock: Callable[[], float] = time.monotonic
    discard: DiscardFn = _default_discard


@dataclass
class ActivateDeps:
    # (record) -> installed Path. Implementations MUST call the WP4 gate with
    # ``activation_accepted=True`` and ``expected_bundle_digest=record.digest``.
    install: Callable[[Proposal], Path]
    tree_digest_of: Callable[[Path], str] = quarantine_tree_digest
    discard: DiscardFn = _default_discard
    # Set true only for an explicit operator break-glass; never wired from a
    # remote message. When false a "block" policy fails activation closed.
    allow_blocked: bool = False


def _scan_source_for(bundle: Any, meta: Any, identifier: str) -> str:
    if getattr(bundle, "source", "") == "official":
        return "official"
    return (
        getattr(bundle, "identifier", "")
        or getattr(meta, "identifier", "")
        or identifier
    )


def propose(identifier: str, deps: ProposeDeps) -> Dict[str, Any]:
    """Resolve, scan, and quarantine *identifier*; return non-secret identity.

    Raises :class:`ProposalNotFound` when the identifier does not resolve to a
    fetchable bundle. The quarantine is retained (keyed by ``proposal_id``) for
    a later :func:`activate_proposal`; on any failure after quarantine it is
    discarded so nothing dangling survives.
    """
    ident = (identifier or "").strip()
    if not ident:
        raise ProposalNotFound("identifier is required")

    resolved = deps.resolve_bundle(ident)
    if not resolved:
        raise ProposalNotFound(ident)
    meta, bundle = resolved
    if bundle is None:
        raise ProposalNotFound(ident)

    q_path = deps.quarantine(bundle)
    try:
        scan_source = _scan_source_for(bundle, meta, ident)
        scan_result = deps.scan(q_path, scan_source)
        allowed, policy_reason = deps.policy(scan_result)
        commit = deps.commit_of(bundle)
        digest = deps.digest_of(bundle)
        tree_digest = deps.tree_digest_of(q_path)
        proposal_id = deps.id_factory()
        record = Proposal(
            proposal_id=proposal_id,
            identifier=getattr(bundle, "identifier", ident) or ident,
            name=getattr(scan_result, "skill_name", None)
            or getattr(bundle, "name", ident),
            source=getattr(bundle, "source", "") or "",
            commit=commit,
            digest=digest,
            tree_digest=tree_digest,
            quarantine_path=Path(q_path),
            bundle=bundle,
            scan_result=scan_result,
            scan_provenance=dict(getattr(scan_result, "scan_provenance", {}) or {}),
            category="",
            policy=_policy_label(allowed),
            policy_reason=policy_reason,
            created_at=deps.clock(),
        )
        _STORE.put(record)
    except Exception:
        deps.discard(Path(q_path))
        raise

    return {
        "proposal_id": record.proposal_id,
        "identifier": record.identifier,
        "name": record.name,
        "source": record.source,
        # Transport-resolved 40-hex commit or null. A self-declared version/SHA
        # is intentionally NOT surfaced here (bundle_exact_identity rejects it).
        "commit": record.commit,
        "digest": record.digest,
        "policy": record.policy,
        "policy_reason": record.policy_reason,
    }


def activate_proposal(
    proposal_id: str,
    expected_commit: Optional[str],
    expected_digest: str,
    deps: ActivateDeps,
) -> Dict[str, Any]:
    """Atomically consume *proposal_id* and install ONLY if identity still holds.

    The confirmed ``expected_commit``/``expected_digest`` must equal the values
    minted at propose time, and the on-disk quarantine must still hash to the
    snapshotted tree digest. Only then is ``activation_accepted`` minted and the
    WP4 gate invoked. Any drift/replay/mutation/policy-block fails closed and the
    quarantine is discarded.
    """
    record = _STORE.consume(proposal_id)
    if record is None:
        # Unknown id, already-consumed (replay), or expired.
        raise ProposalReplay(proposal_id)

    installed = False
    try:
        if _norm_commit(expected_commit) != _norm_commit(record.commit):
            raise CommitDrift(
                f"confirmed commit does not match the proposed commit "
                f"for '{record.identifier}'"
            )

        want_digest = _norm_digest(expected_digest)
        if not hmac.compare_digest(want_digest, _norm_digest(record.digest)):
            raise DigestDrift(
                f"confirmed digest does not match the proposed digest "
                f"for '{record.identifier}'"
            )

        # Re-hash the quarantined tree as it stands NOW; a mutation between
        # propose and activate changes the digest and fails closed.
        current_tree = deps.tree_digest_of(record.quarantine_path)
        if not hmac.compare_digest(
            _norm_digest(current_tree), _norm_digest(record.tree_digest)
        ):
            raise BundleMutation(
                f"quarantined artifact for '{record.identifier}' changed after "
                f"it was proposed"
            )

        if record.policy == "block" and not deps.allow_blocked:
            raise PolicyBlocked(
                f"install policy blocked activation of '{record.identifier}': "
                f"{record.policy_reason}"
            )

        install_path = deps.install(record)
        installed = True
        return {
            "ok": True,
            "name": record.name,
            "identifier": record.identifier,
            "commit": record.commit,
            "digest": record.digest,
            "path": str(install_path),
        }
    finally:
        # install_from_quarantine moves the tree on success; on any failure the
        # quarantine must not linger. ignore_errors covers the already-moved case.
        if not installed:
            deps.discard(record.quarantine_path)
        else:
            deps.discard(record.quarantine_path)


# ---------------------------------------------------------------------------
# Process-local single-use store. Endpoints share this instance; tests can
# swap it via :func:`_set_store_for_test`.
# ---------------------------------------------------------------------------
_STORE = ProposalStore()


def get_store() -> ProposalStore:
    return _STORE


def _set_store_for_test(store: ProposalStore) -> ProposalStore:
    global _STORE
    previous = _STORE
    _STORE = store
    return previous
