#!/usr/bin/env python3
"""Release-publish supply-chain gate (WP4 items 1 & 7).

Behavioral: parses the real release/publish workflow and manifest and fails
closed if the release path could ship or push an unverified executable payload.
It asserts *properties of the resolved workflow*, never source-text formatting.

Checks
------
1. docker.yml ``publish`` job must NOT pass ``ALLOW_UNVERIFIED_BROWSER=1`` in any
   build step — that would bake the unverified Playwright browser payload into a
   pushed release image. The ``build`` job (load-only, never pushed) may use it
   as an explicit CI-test compatibility path.
2. The ``publish`` push step must emit an SBOM and max-mode provenance
   attestation and push by digest, so the attestation is tied to the exact
   published digest.
3. docker.yml ``publish`` must BUILD THE RELEASE IMAGE EXACTLY ONCE into a
   content-addressed, push-by-digest quarantine, then AUDIT that exact pushed
   digest (its apt closure) BEFORE it is tagged — never a separately-built
   ``:audit``/``:test`` image, never a rebuild. The apt-closure audit must not
   swallow failures (no ``|| true`` / "skipped" / continue-on-error), must diff
   a reviewed baseline, and a **missing** reviewed baseline must ERROR (exit 1),
   not warn/record. The audit must reference the pushed digest
   (``steps.<push>.outputs.digest``) and run AFTER the push.
4. The reviewed apt-closure baselines (``supply-chain/apt-closure-{amd64,arm64}.txt``)
   must exist. Absent them the release path is intentionally fail-closed: there
   is no reviewed package set to diff the built image against, so publish must
   not proceed until a maintainer seeds them from a real build.
5. docker.yml ``merge`` (tag/promote) must depend on ``publish`` and tag the
   EXACT pushed digests via ``imagetools`` — it must NOT build/rebuild, so the
   tagged image is the exact digest that was audited (B4 exact-artifact
   invariant).
6. release-attest.yml must validate the manifest (run check_supply_chain) and
   attest the manifest subject before any release is trusted.
7. The manifest itself must be coherent and contain no ``release_verified``
   component that lacks a digest/provenance anchor (delegated to
   check_supply_chain, imported here so a single call gates both).

Exit 0 clean, 1 on any finding.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCKER_WF = _REPO_ROOT / ".github" / "workflows" / "docker.yml"
_ATTEST_WF = _REPO_ROOT / ".github" / "workflows" / "release-attest.yml"
_DOCKERFILE = _REPO_ROOT / "Dockerfile"
_RELEASE_IMAGE = _REPO_ROOT / "supply-chain" / "release-image.json"
_ATTEST_REQUIREMENTS = (
    _REPO_ROOT / "scripts" / "ci" / "requirements-release-attest.txt"
)
# The reviewed apt-closure baselines the pre-push audit diffs the built image
# against. Absent, release publish is intentionally fail-closed (no reviewed
# package set to compare). A maintainer seeds these from a real CI build.
_APT_CLOSURE_BASELINES = [
    _REPO_ROOT / "supply-chain" / "apt-closure-amd64.txt",
    _REPO_ROOT / "supply-chain" / "apt-closure-arm64.txt",
]

_UNVERIFIED_BROWSER_FLAG = "ALLOW_UNVERIFIED_BROWSER"

# Trust bases an INCLUDED release-image executable component may carry. Anything
# else (notably transport_trusted) must NOT be baked into a published release.
_ALLOWED_INCLUDED_TRUST = {"release_verified", "lock_anchored"}
_TRUSTED_RELEASE_REPOSITORY = "NousResearch/hermes-agent"


class Findings:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, msg: str) -> None:
        self.items.append(msg)

    def ok(self) -> bool:
        return not self.items


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _steps(job: dict) -> list[dict]:
    return [s for s in (job.get("steps") or []) if isinstance(s, dict)]


def _build_args_text(step: dict) -> str:
    with_ = step.get("with") or {}
    val = with_.get("build-args")
    if val is None:
        return ""
    if isinstance(val, list):
        return "\n".join(str(v) for v in val)
    return str(val)


def _step_text(step: dict) -> str:
    """The step's run script plus every env value, concatenated. Digest
    references frequently arrive via `env: PUSHED_DIGEST: ${{ steps.push... }}`,
    so a behavioral check must inspect both."""
    parts = [str(step.get("run") or "")]
    env = step.get("env") or {}
    if isinstance(env, dict):
        parts.extend(str(v) for v in env.values())
    return "\n".join(parts)


def _builds_image(step: dict) -> bool:
    """True when the step BUILDS a container image (build-push-action, or a
    `docker build` / `docker buildx build` run). Used to enforce build-once."""
    uses = str(step.get("uses") or "")
    if "build-push-action" in uses:
        return True
    run = str(step.get("run") or "")
    if re.search(r"docker\s+buildx\s+build\b", run):
        return True
    if re.search(r"\bdocker\s+build\b", run):
        return True
    return False


def _is_push_by_digest(step: dict) -> bool:
    """True when the step is a build-push-action pushing by digest (the
    content-addressed quarantine push)."""
    uses = str(step.get("uses") or "")
    outputs = str((step.get("with") or {}).get("outputs") or "")
    return "build-push-action" in uses and "push-by-digest=true" in outputs


def _mentions_unverified_browser_flag_set(text: str) -> bool:
    """True when the text sets the flag to an enabling value (=1/true)."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith(_UNVERIFIED_BROWSER_FLAG):
            continue
        _, _, rhs = line.partition("=")
        if rhs.strip().strip('"').strip("'").lower() in {"1", "true", "yes", "on"}:
            return True
    return False


def _missing_baseline_fails_closed(run: str) -> bool:
    """True when the audit's baseline-absent path exits non-zero.

    The audit tests ``[ -f "$baseline" ]``; if the baseline is missing the
    script must ``exit 1`` (fail closed), not warn/record/skip. Returns True
    only when a missing baseline provably blocks the job.
    """
    # No baseline existence test at all → cannot fail closed on absence.
    if not re.search(r"-f\s+\"?\$?\{?baseline", run) and "-f baseline" not in run:
        return False
    m = re.search(r"\belse\b(.*?)\bfi\b", run, re.DOTALL)
    if m is None:
        # No else branch: a missing baseline silently skips the diff.
        return False
    return "exit 1" in m.group(1)


def check_docker_publish(findings: Findings) -> None:
    wf = _load_yaml(_DOCKER_WF)
    jobs = wf.get("jobs") or {}
    publish = jobs.get("publish")
    if not isinstance(publish, dict):
        findings.add("docker.yml: no 'publish' job found")
        return

    steps = _steps(publish)

    push_step = None
    for step in steps:
        # (1) no publish step may enable the unverified browser payload.
        if _mentions_unverified_browser_flag_set(_build_args_text(step)):
            findings.add(
                "docker.yml publish job passes "
                f"{_UNVERIFIED_BROWSER_FLAG}=1 — a published release must not "
                "bake the unverified browser payload"
            )
        run = str(step.get("run") or "")
        if _UNVERIFIED_BROWSER_FLAG in run and _mentions_unverified_browser_flag_set(
            run.replace("--build-arg ", "")
        ):
            findings.add(
                "docker.yml publish job run-step sets "
                f"{_UNVERIFIED_BROWSER_FLAG}=1 — a published release must not "
                "bake the unverified browser payload"
            )
        if _is_push_by_digest(step):
            push_step = step

    # (2) the pushing step must attest SBOM + provenance tied to the digest.
    if push_step is None:
        findings.add("docker.yml publish job has no push-by-digest build-push step")
    else:
        with_ = push_step.get("with") or {}
        if str(with_.get("sbom")).lower() != "true":
            findings.add("docker.yml publish push step must set 'sbom: true'")
        if "mode=max" not in str(with_.get("provenance") or ""):
            findings.add(
                "docker.yml publish push step must set 'provenance: mode=max'"
            )

    # (3) B4 exact-artifact invariant: build the release image EXACTLY ONCE into
    # a content-addressed push-by-digest quarantine, then AUDIT that exact pushed
    # digest BEFORE the merge job tags it. No separately-built audit image, no
    # rebuild.
    build_idxs = [i for i, s in enumerate(steps) if _builds_image(s)]
    push_idx = next((i for i, s in enumerate(steps) if _is_push_by_digest(s)), None)

    if len(build_idxs) == 0:
        findings.add("docker.yml publish job has no image build step")
    elif len(build_idxs) > 1:
        findings.add(
            "docker.yml publish job builds the release image "
            f"{len(build_idxs)} times — it must build EXACTLY ONCE and audit/tag "
            "that same content-addressed digest without rebuilding (B4). A "
            "separately-built audit image is not provably the pushed image."
        )
    elif push_idx is None or build_idxs[0] != push_idx:
        findings.add(
            "docker.yml publish job's single build must be the push-by-digest "
            "(content-addressed quarantine) build (B4)"
        )

    # The apt-closure audit: must not swallow failures / be continue-on-error,
    # must diff a reviewed baseline and fail closed on a MISSING baseline, must
    # reference the EXACT pushed digest, and must run AFTER the push.
    audit_idx = None
    for i, step in enumerate(steps):
        run = str(step.get("run") or "")
        name = str(step.get("name") or "").lower()
        if "apt closure" not in name and "dpkg-query" not in run:
            continue
        if "|| true" in run or "skipped" in run.lower():
            findings.add(
                "docker.yml apt-closure step swallows failures (|| true / "
                "'skipped') — a failed closure capture must block publish"
            )
        if str(step.get("continue-on-error")).lower() == "true":
            findings.add("docker.yml apt-closure step is continue-on-error")
        # the audit must compare to a baseline and fail on drift.
        if "audit" in name and "dpkg-query" in run:
            audit_idx = i
            if "diff" not in run:
                findings.add(
                    "docker.yml pre-tag apt-closure audit must diff against a "
                    "reviewed baseline and fail on drift"
                )
            # A MISSING baseline must fail closed (exit 1), never warn/record.
            if not _missing_baseline_fails_closed(run):
                findings.add(
                    "docker.yml apt-closure audit does not fail closed when the "
                    "reviewed baseline is MISSING — a missing baseline must "
                    "error and block publish (A10), not warn/record/skip"
                )
            # B4: the audit must target the EXACT pushed digest, not a
            # separately-built/loaded tag.
            text = _step_text(step)
            if "outputs.digest" not in text and "@sha256:" not in text:
                findings.add(
                    "docker.yml apt-closure audit does not reference the EXACT "
                    "pushed digest (steps.<push>.outputs.digest / @sha256:<digest>) "
                    "— it must audit the content-addressed image that will be "
                    "tagged, not a separately-built image (B4)"
                )
            if re.search(r":audit-", text) or re.search(r":test\b", text):
                findings.add(
                    "docker.yml apt-closure audit targets a separately-built tag "
                    "(:audit-/:test) instead of the pushed digest — it must audit "
                    "the exact pushed digest (B4)"
                )

    if audit_idx is None:
        findings.add(
            "docker.yml publish job has no apt-closure audit step (B4: the "
            "pushed digest's package closure must be audited before it is tagged)"
        )
    elif push_idx is not None and audit_idx < push_idx:
        findings.add(
            "docker.yml apt-closure audit runs BEFORE the image is pushed — it "
            "cannot audit the exact pushed digest (B4: build once → push by "
            "digest → audit that digest → tag it)"
        )


def check_docker_merge(findings: Findings) -> None:
    """B4: the tag/promote job must tag the EXACT pushed digests without any
    rebuild, and only after the publish (audit) job succeeds."""
    wf = _load_yaml(_DOCKER_WF)
    jobs = wf.get("jobs") or {}
    merge = jobs.get("merge")
    if not isinstance(merge, dict):
        findings.add("docker.yml: no 'merge' (tag/promote) job found")
        return

    needs = merge.get("needs")
    needs_list = [needs] if isinstance(needs, str) else list(needs or [])
    if "publish" not in needs_list:
        findings.add(
            "docker.yml merge (tag) job must depend on 'publish' so tagging only "
            "happens after the pushed digest passed its pre-tag audit (B4)"
        )

    tags_by_digest = False
    for step in _steps(merge):
        if _builds_image(step):
            findings.add(
                "docker.yml merge (tag) job must NOT build/rebuild — it tags the "
                "exact pushed digests via imagetools (B4)"
            )
        run = str(step.get("run") or "")
        if "imagetools create" in run and ("@sha256:" in run or "sha256:" in run):
            tags_by_digest = True
    if not tags_by_digest:
        findings.add(
            "docker.yml merge (tag) job must create the tag from the pushed "
            "content digests (docker buildx imagetools create ...@sha256:<digest>) "
            "so the tagged image is the exact audited digest, never a rebuild (B4)"
        )


def check_release_attest(findings: Findings) -> None:
    wf = _load_yaml(_ATTEST_WF)
    jobs = wf.get("jobs") or {}
    if not jobs:
        findings.add("release-attest.yml has no jobs")
        return
    runs_check = False
    attests_manifest = False
    installs_hash_pinned_dependencies = False
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        repository_gate = str(job.get("if") or "")
        if (
            "github.repository" not in repository_gate
            or _TRUSTED_RELEASE_REPOSITORY not in repository_gate
        ):
            findings.add(
                "release-attest.yml jobs must be restricted to the compiled-in "
                f"release authority {_TRUSTED_RELEASE_REPOSITORY!r}"
            )
        for step in _steps(job):
            run = str(step.get("run") or "")
            if "check_supply_chain.py" in run:
                runs_check = True
            if (
                "--require-hashes" in run
                and "--only-binary=:all:" in run
                and _ATTEST_REQUIREMENTS.name in run
            ):
                installs_hash_pinned_dependencies = True
            uses = str(step.get("uses") or "")
            with_ = step.get("with") or {}
            if "attest-build-provenance" in uses and "manifest.json" in str(
                with_.get("subject-path") or ""
            ):
                attests_manifest = True
    if not runs_check:
        findings.add(
            "release-attest.yml must run scripts/ci/check_supply_chain.py before "
            "attesting (a release cannot attest an incoherent manifest)"
        )
    if not installs_hash_pinned_dependencies:
        findings.add(
            "release-attest.yml must install its parser dependency from "
            "scripts/ci/requirements-release-attest.txt with --require-hashes "
            "and --only-binary=:all:"
        )
    if not _ATTEST_REQUIREMENTS.is_file():
        findings.add(
            "scripts/ci/requirements-release-attest.txt is missing"
        )
    if not attests_manifest:
        findings.add(
            "release-attest.yml must attest supply-chain/manifest.json "
            "(the reviewed artifact manifest)"
        )


def check_manifest_release_verified(findings: Findings) -> None:
    """Delegate to the manifest checker: every release_verified component must
    carry an anchor, so no included payload is transport-trusted at release."""
    sys.path.insert(0, str(_REPO_ROOT))
    try:
        from hermes_cli.supply_chain.manifest import load_manifest
    except Exception as exc:  # pragma: no cover - import guard
        findings.add(f"cannot import manifest loader: {exc}")
        return
    try:
        manifest = load_manifest(_REPO_ROOT / "supply-chain" / "manifest.json")
    except Exception as exc:
        findings.add(f"manifest failed to load: {exc}")
        return
    for comp in manifest.components:
        if comp.trust_class != "release_verified":
            continue
        for art in comp.artifacts:
            anchored = (
                getattr(art, "digest", None) is not None
                and getattr(art.digest, "status", "") == "present"
            ) or getattr(art, "provenance", None) is not None
            if not anchored:
                findings.add(
                    f"release_verified component {comp.name!r} artifact "
                    f"{getattr(art, 'platform', '?')}/{getattr(art, 'arch', '?')} "
                    "has no digest/provenance anchor — it would ship unverified"
                )


def _external_from_lines(dockerfile_text: str) -> list[str]:
    """Return only ``FROM`` lines that introduce external images.

    A later stage may inherit from an earlier named stage (for example
    ``FROM runtime_apt AS runtime``). That is not another image pull and is
    already anchored by the earlier external ``FROM ...@sha256`` line.
    """
    external: list[str] = []
    stages: set[str] = set()
    for raw in dockerfile_text.splitlines():
        line = raw.strip()
        if not line.upper().startswith("FROM "):
            continue
        parts = line.split()
        image_index = 1
        while image_index < len(parts) and parts[image_index].startswith("--"):
            image_index += 1
        if image_index >= len(parts):
            external.append(line)
            continue
        image = parts[image_index]
        if image.lower() not in stages:
            external.append(line)
        for index in range(image_index + 1, len(parts) - 1):
            if parts[index].upper() == "AS":
                stages.add(parts[index + 1].lower())
                break
    return external


def check_release_image(findings: Findings) -> None:
    """Validate the machine-readable included-executable-component set for the
    published release image (WP4 correction 4).

    * every INCLUDED component is release_verified or lock-anchored — a
      transport_trusted component must never be baked into a release;
    * the unverified browser payload is EXCLUDED (kept out until pinned);
    * the declared anchors are cross-checked against the real Dockerfile /
      lockfiles (every FROM is @sha256-pinned; uv.lock + package-lock exist).
    """
    import json

    if not _RELEASE_IMAGE.exists():
        findings.add("supply-chain/release-image.json missing — the release image's included "
                     "executable component set must be machine-readable")
        return
    try:
        decl = json.loads(_RELEASE_IMAGE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        findings.add(f"release-image.json is not valid JSON: {exc}")
        return

    included = decl.get("included_components") or []
    excluded = {str(c.get("name")) for c in (decl.get("excluded_components") or [])}
    if not included:
        findings.add("release-image.json declares no included_components")
    for comp in included:
        name = comp.get("name")
        trust = comp.get("trust")
        if trust not in _ALLOWED_INCLUDED_TRUST:
            findings.add(
                f"release image includes component {name!r} with trust {trust!r} — "
                "an included component must be release_verified or lock_anchored "
                "(a transport_trusted/unverified component must not ship)"
            )

    # The browser payload must be excluded, never included.
    if "playwright-browser" not in excluded:
        findings.add("release-image.json must EXCLUDE 'playwright-browser' (kept absent until pinned)")
    if any(c.get("name") == "playwright-browser" for c in included):
        findings.add("release-image.json includes 'playwright-browser' — the unverified browser "
                     "payload must not be baked into a release image")

    # Cross-check the declared anchors against the real Dockerfile.
    if not _DOCKERFILE.exists():
        findings.add("Dockerfile missing — cannot cross-check release-image anchors")
        return
    text = _DOCKERFILE.read_text(encoding="utf-8")
    from_lines = _external_from_lines(text)
    if not from_lines:
        findings.add("Dockerfile has no external FROM lines to verify")
    for ln in from_lines:
        if not re.search(r"@sha256:[0-9a-f]{64}", ln):
            findings.add(f"Dockerfile base image is not @sha256-pinned: {ln}")
    # lock-anchored inputs must exist.
    if not (_REPO_ROOT / "uv.lock").exists():
        findings.add("release image claims lock-anchored python-deps but uv.lock is missing")
    if not (_REPO_ROOT / "package-lock.json").exists():
        findings.add("release image claims lock-anchored npm-deps but package-lock.json is missing")
    # The browser must not be an unconditional Dockerfile layer.
    if _UNVERIFIED_BROWSER_FLAG not in text:
        findings.add("Dockerfile no longer gates the browser payload behind "
                     f"{_UNVERIFIED_BROWSER_FLAG} — it must stay opt-in/absent")


def check_apt_closure_baseline(findings: Findings) -> None:
    """The reviewed apt-closure baselines must exist (A10).

    Without them the pre-push audit has nothing to diff the built image
    against, so a release must not proceed: publish is intentionally
    fail-closed until a maintainer seeds the baselines from a real build.
    """
    missing = [p for p in _APT_CLOSURE_BASELINES if not p.exists()]
    if missing:
        def _rel(p: Path) -> str:
            try:
                return str(p.relative_to(_REPO_ROOT))
            except ValueError:
                return str(p)
        names = ", ".join(_rel(p) for p in missing)
        findings.add(
            "reviewed apt-closure baseline(s) missing: "
            f"{names} — release publish is fail-closed until a maintainer "
            "seeds them from a CI build (no reviewed package set to audit against)"
        )


def run() -> int:
    findings = Findings()
    check_docker_publish(findings)
    check_docker_merge(findings)
    check_release_attest(findings)
    check_manifest_release_verified(findings)
    check_release_image(findings)
    check_apt_closure_baseline(findings)
    if findings.ok():
        print("release-publish gate: no unverified executable payload in the release path OK")
        return 0
    print("release-publish gate FAILED:", file=sys.stderr)
    for item in findings.items:
        print(f"  - {item}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(run())
