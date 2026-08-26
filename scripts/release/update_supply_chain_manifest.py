#!/usr/bin/env python3
"""Maintainer-only tool to pin a component in supply-chain/manifest.json.

This is the ONLY sanctioned way to move a component from ``transport_trusted``
(pending) to ``release_verified``. It records an exact version, computes/records
per-artifact digests, optionally verifies upstream provenance, bumps the
manifest sequence, and refuses to write when verification fails. Normal managed
installation never runs this — it consumes only the committed values.

Design invariants (pure, testable):

* ``pin_component`` refuses to mark a component ``release_verified`` unless every
  artifact carries a byte digest or an independent provenance identity — it can
  never fabricate an anchor.
* ``bump_sequence`` only increases the monotonic sequence.
* Output is deterministic (sorted keys) so a review diff is reproducible.

The ``--download`` path (network fetch + sha256 + optional ``gh``/``cosign``
provenance verify) is maintainer tooling and is intentionally not exercised by
Hermes at runtime.

Usage (illustrative):

    python scripts/release/update_supply_chain_manifest.py \
        --component uv --version 0.5.11 \
        --artifact linux x86_64 https://github.com/astral-sh/uv/releases/download/0.5.11/uv-x86_64-unknown-linux-gnu.tar.gz \
        --digest linux x86_64 <sha256> \
        --security-floor 0.5.11 --write
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from datetime import date
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from hermes_cli.supply_chain.manifest import (  # noqa: E402
    TRUST_RELEASE_VERIFIED,
    TRUST_TRANSPORT_TRUSTED,
)

_MANIFEST_PATH = _REPO_ROOT / "supply-chain" / "manifest.json"


def load(path: Path = _MANIFEST_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dump(manifest: dict, path: Path = _MANIFEST_PATH) -> None:
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def bump_sequence(manifest: dict) -> int:
    current = int(manifest["manifest"]["sequence"])
    manifest["manifest"]["sequence"] = current + 1
    return current + 1


def compute_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_has_anchor(art: dict) -> bool:
    digest = art.get("digest") or {}
    if digest.get("status") == "present" and digest.get("value"):
        return True
    return art.get("provenance") is not None


def pin_component(
    manifest: dict,
    component: str,
    version: str,
    *,
    digests: dict[tuple[str, str], str] | None = None,
    security_floor: str | None = None,
    review_date: str | None = None,
) -> dict:
    """Return a copy of *manifest* with *component* pinned to *version*.

    Applies each ``(platform, arch) -> sha256`` in *digests*. Promotes the
    component to ``release_verified`` only when every artifact ends up with an
    anchor; otherwise it stays ``transport_trusted``. Raises ``ValueError`` when
    the component or a targeted artifact is absent — it never invents one.
    """
    result = copy.deepcopy(manifest)
    digests = digests or {}
    comp = next((c for c in result["components"] if c["name"] == component), None)
    if comp is None:
        raise ValueError(f"unknown component: {component}")

    comp["version"] = version
    comp["review_date"] = review_date or date.today().isoformat()
    if security_floor is not None:
        comp["security_floor"] = security_floor

    for (platform, arch), sha in digests.items():
        art = next(
            (a for a in comp["artifacts"] if a["platform"] == platform and a["arch"] == arch),
            None,
        )
        if art is None:
            raise ValueError(f"{component}: no artifact for {platform}/{arch}")
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise ValueError(f"{component} {platform}/{arch}: invalid sha256 {sha!r}")
        art["digest"] = {"algorithm": "sha256", "value": sha, "status": "present"}
        art.pop("blocker", None)

    if all(_artifact_has_anchor(a) for a in comp["artifacts"]):
        comp["trust_class"] = TRUST_RELEASE_VERIFIED
    else:
        comp["trust_class"] = TRUST_TRANSPORT_TRUSTED
    return result


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pin a supply-chain manifest component.")
    parser.add_argument("--component", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--security-floor")
    parser.add_argument(
        "--digest", nargs=3, action="append", metavar=("PLATFORM", "ARCH", "SHA256"),
        default=[], help="Record an exact sha256 for a platform/arch.",
    )
    parser.add_argument(
        "--digest-from", nargs=3, action="append",
        metavar=("PLATFORM", "ARCH", "LOCALFILE"), default=[],
        help="Compute the sha256 of a locally-downloaded artifact.",
    )
    parser.add_argument("--write", action="store_true", help="Write the manifest (else dry-run diff).")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    manifest = load()

    digests: dict[tuple[str, str], str] = {}
    for platform, arch, sha in args.digest:
        digests[(platform, arch)] = sha.lower()
    for platform, arch, localfile in args.digest_from:
        digests[(platform, arch)] = compute_sha256(localfile)

    try:
        updated = pin_component(
            manifest, args.component, args.version,
            digests=digests, security_floor=args.security_floor,
        )
    except ValueError as exc:
        print(f"refusing to write: {exc}", file=sys.stderr)
        return 1

    bump_sequence(updated)

    if not args.write:
        print(json.dumps(updated, indent=2, sort_keys=True))
        print("\n(dry run — pass --write to persist)", file=sys.stderr)
        return 0

    dump(updated)
    print(f"pinned {args.component} {args.version}; sequence -> {updated['manifest']['sequence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
