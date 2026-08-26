"""Behavioral tests for the release-publish supply-chain gate (WP4 items 1 & 7).

Feed the real checker synthetic workflow YAML and assert it classifies an
unverified-payload publish path as a FAILURE, and the real repo workflows as
clean. No source-text assertions — the checker parses resolved YAML.
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def gate():
    return importlib.import_module("scripts.ci.check_release_publish")


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return path


# --- the real repo workflows must be clean --------------------------------

def test_real_repo_release_path_is_clean(gate):
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    gate.check_docker_merge(findings)
    gate.check_release_attest(findings)
    gate.check_manifest_release_verified(findings)
    assert findings.ok(), findings.items


# --- negative fixtures: unverified payload in publish must fail -----------

_CLEAN_PUBLISH = """
jobs:
  publish:
    steps:
      - name: Build and push release image by digest (quarantine)
        id: push
        uses: docker/build-push-action@abc
        with:
          build-args: |
            HERMES_GIT_SHA=x
          sbom: true
          provenance: mode=max
          outputs: type=image,name=n,push-by-digest=true,push=true
      - name: Audit apt closure of the pushed digest (pre-tag gate)
        env:
          PUSHED_DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          set -euo pipefail
          docker run --rm "n@${PUSHED_DIGEST}" sh -c 'dpkg-query -W' > apt.txt
          test -s apt.txt
          if [ -f "$baseline" ]; then
            diff -u "$baseline" apt.txt || exit 1
          else
            echo "::error::no baseline" >&2
            exit 1
          fi
      - name: Upload apt closure artifact
        uses: actions/upload-artifact@abc
"""

_CLEAN_ATTEST = """
jobs:
  attest:
    if: github.repository == 'NousResearch/hermes-agent'
    steps:
      - run: >-
          python -m pip install --only-binary=:all: --require-hashes
          -r scripts/ci/requirements-release-attest.txt
      - run: python scripts/ci/check_supply_chain.py
      - uses: actions/attest-build-provenance@abc
        with:
          subject-path: supply-chain/manifest.json
"""


def test_publish_with_unverified_browser_flag_fails(gate, tmp_path, monkeypatch):
    wf = _write(tmp_path / "docker.yml", _CLEAN_PUBLISH.replace(
        "HERMES_GIT_SHA=x", "HERMES_GIT_SHA=x\n            ALLOW_UNVERIFIED_BROWSER=1"
    ))
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    assert any("ALLOW_UNVERIFIED_BROWSER" in f for f in findings.items)


def test_publish_missing_sbom_fails(gate, tmp_path, monkeypatch):
    wf = _write(tmp_path / "docker.yml", _CLEAN_PUBLISH.replace("          sbom: true\n", ""))
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    assert any("sbom" in f.lower() for f in findings.items)


def test_publish_missing_provenance_fails(gate, tmp_path, monkeypatch):
    wf = _write(tmp_path / "docker.yml", _CLEAN_PUBLISH.replace("          provenance: mode=max\n", ""))
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    assert any("provenance" in f.lower() for f in findings.items)


def test_apt_closure_swallowed_failure_fails(gate, tmp_path, monkeypatch):
    wf = _write(tmp_path / "docker.yml", _CLEAN_PUBLISH.replace(
        "test -s apt.txt", "dpkg-query -W > apt.txt || true"
    ))
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    assert any("swallow" in f.lower() or "block publish" in f.lower() for f in findings.items)


def test_apt_closure_continue_on_error_fails(gate, tmp_path, monkeypatch):
    tampered = _CLEAN_PUBLISH.replace(
        "      - name: Audit apt closure of the pushed digest (pre-tag gate)\n",
        "      - name: Audit apt closure of the pushed digest (pre-tag gate)\n        continue-on-error: true\n",
    )
    wf = _write(tmp_path / "docker.yml", tampered)
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    assert any("continue-on-error" in f.lower() for f in findings.items)


def test_a10_audit_warns_on_missing_baseline_fails(gate, tmp_path, monkeypatch):
    """A missing baseline must fail closed (exit 1), not warn/record/skip."""
    warn_only = _CLEAN_PUBLISH.replace(
        '          else\n            echo "::error::no baseline" >&2\n            exit 1\n          fi',
        '          else\n            echo "::warning::no reviewed baseline; recording"\n          fi',
    )
    wf = _write(tmp_path / "docker.yml", warn_only)
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    assert any("fail closed" in f and "MISSING" in f for f in findings.items), findings.items


def test_a10_audit_no_baseline_branch_fails(gate, tmp_path, monkeypatch):
    """An audit that never tests for the baseline silently skips on absence."""
    no_branch = _CLEAN_PUBLISH.replace(
        '          if [ -f "$baseline" ]; then\n            diff -u "$baseline" apt.txt || exit 1\n          else\n            echo "::error::no baseline" >&2\n            exit 1\n          fi',
        "          diff -u any apt.txt || exit 1",
    )
    wf = _write(tmp_path / "docker.yml", no_branch)
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    assert any("fail closed" in f and "MISSING" in f for f in findings.items), findings.items


def test_a10_missing_apt_closure_baselines_fail_closed(gate, tmp_path, monkeypatch):
    """With the reviewed baselines absent, release publish is fail-closed."""
    monkeypatch.setattr(
        gate, "_APT_CLOSURE_BASELINES", [tmp_path / "apt-closure-amd64.txt", tmp_path / "apt-closure-arm64.txt"]
    )
    findings = gate.Findings()
    gate.check_apt_closure_baseline(findings)
    assert any("baseline" in f and "fail-closed" in f for f in findings.items), findings.items


def test_a10_present_apt_closure_baselines_pass(gate, tmp_path, monkeypatch):
    """Once both baselines are seeded, the baseline check passes."""
    amd = tmp_path / "apt-closure-amd64.txt"
    arm = tmp_path / "apt-closure-arm64.txt"
    amd.write_text("pkg=1\n", encoding="utf-8")
    arm.write_text("pkg=1\n", encoding="utf-8")
    monkeypatch.setattr(gate, "_APT_CLOSURE_BASELINES", [amd, arm])
    findings = gate.Findings()
    gate.check_apt_closure_baseline(findings)
    assert findings.ok(), findings.items


def test_real_repo_has_reviewed_apt_closure_baselines(gate):
    """The checked-in baselines make the real release gate operational."""
    findings = gate.Findings()
    gate.check_apt_closure_baseline(findings)
    assert findings.ok(), findings.items


def test_b4_missing_audit_fails(gate, tmp_path, monkeypatch):
    """A publish job that pushes by digest but never audits it must fail."""
    no_audit = """
jobs:
  publish:
    steps:
      - name: Build and push release image by digest (quarantine)
        id: push
        uses: docker/build-push-action@abc
        with:
          build-args: |
            HERMES_GIT_SHA=x
          sbom: true
          provenance: mode=max
          outputs: type=image,name=n,push-by-digest=true,push=true
"""
    wf = _write(tmp_path / "docker.yml", no_audit)
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    assert any("no apt-closure audit step" in f for f in findings.items), findings.items


def test_b4_audit_before_push_fails(gate, tmp_path, monkeypatch):
    """The audit must run AFTER the push so it inspects the exact pushed digest;
    an audit ordered before the build/push cannot reference that digest."""
    reordered = """
jobs:
  publish:
    steps:
      - name: Audit apt closure of the pushed digest (pre-tag gate)
        env:
          PUSHED_DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          set -euo pipefail
          docker run --rm "n@${PUSHED_DIGEST}" sh -c 'dpkg-query -W' > apt.txt
          test -s apt.txt
          if [ -f "$baseline" ]; then
            diff -u "$baseline" apt.txt || exit 1
          else
            echo "::error::no baseline" >&2
            exit 1
          fi
      - name: Build and push release image by digest (quarantine)
        id: push
        uses: docker/build-push-action@abc
        with:
          build-args: |
            HERMES_GIT_SHA=x
          sbom: true
          provenance: mode=max
          outputs: type=image,name=n,push-by-digest=true,push=true
"""
    wf = _write(tmp_path / "docker.yml", reordered)
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    assert any("BEFORE the image is pushed" in f for f in findings.items), findings.items


def test_b4_audit_of_separate_image_fails(gate, tmp_path, monkeypatch):
    """Auditing a separately-built/loaded tag (not the pushed digest) is the
    exact bug B4 closes: the audited image is not provably the pushed one."""
    two_builds = """
jobs:
  publish:
    steps:
      - name: Build release image (load) for pre-push audit
        uses: docker/build-push-action@abc
        with:
          load: true
          tags: n:audit-amd64
          build-args: |
            HERMES_GIT_SHA=x
      - name: Audit apt closure vs reviewed baseline (pre-push gate)
        run: |
          set -euo pipefail
          docker run --rm n:audit-amd64 sh -c 'dpkg-query -W' > apt.txt
          test -s apt.txt
          if [ -f "$baseline" ]; then
            diff -u "$baseline" apt.txt || exit 1
          else
            echo "::error::no baseline" >&2
            exit 1
          fi
      - name: Build and push release image by digest (quarantine)
        id: push
        uses: docker/build-push-action@abc
        with:
          build-args: |
            HERMES_GIT_SHA=x
          sbom: true
          provenance: mode=max
          outputs: type=image,name=n,push-by-digest=true,push=true
"""
    wf = _write(tmp_path / "docker.yml", two_builds)
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    # Two builds is itself a violation, AND the audit targets a separate image.
    assert any("EXACTLY ONCE" in f for f in findings.items), findings.items
    assert any("pushed digest" in f for f in findings.items), findings.items


def test_b4_second_build_fails(gate, tmp_path, monkeypatch):
    """Any second image build in the publish job breaks build-once — the tagged
    digest must be the exact one already built + audited, never rebuilt."""
    bad = _CLEAN_PUBLISH.replace(
        "      - name: Upload apt closure artifact\n        uses: actions/upload-artifact@abc\n",
        "      - name: Second build\n        run: docker buildx build . --load\n",
    )
    wf = _write(tmp_path / "docker.yml", bad)
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_publish(findings)
    assert any("EXACTLY ONCE" in f for f in findings.items), findings.items


# --- B4 merge (tag/promote) job: tag the exact digest without rebuilding ----

def test_real_repo_merge_tags_without_rebuild(gate):
    findings = gate.Findings()
    gate.check_docker_merge(findings)
    assert findings.ok(), findings.items


def test_b4_merge_rebuild_fails(gate, tmp_path, monkeypatch):
    rebuild = """
jobs:
  merge:
    needs: [publish]
    steps:
      - name: rebuild and tag
        run: docker buildx build . --push -t n:latest
"""
    wf = _write(tmp_path / "docker.yml", rebuild)
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_merge(findings)
    assert any("must NOT build" in f or "rebuild" in f.lower() for f in findings.items), findings.items


def test_b4_merge_without_publish_dependency_fails(gate, tmp_path, monkeypatch):
    no_dep = """
jobs:
  merge:
    steps:
      - name: tag
        run: docker buildx imagetools create -t n:latest n@sha256:abc
"""
    wf = _write(tmp_path / "docker.yml", no_dep)
    monkeypatch.setattr(gate, "_DOCKER_WF", wf)
    findings = gate.Findings()
    gate.check_docker_merge(findings)
    assert any("depend on 'publish'" in f for f in findings.items), findings.items


def test_release_attest_without_manifest_attestation_fails(gate, tmp_path, monkeypatch):
    wf = _write(tmp_path / "release-attest.yml", """
jobs:
  attest:
    steps:
      - run: echo nope
""")
    monkeypatch.setattr(gate, "_ATTEST_WF", wf)
    findings = gate.Findings()
    gate.check_release_attest(findings)
    assert any("check_supply_chain" in f for f in findings.items)
    assert any("manifest.json" in f for f in findings.items)


def test_release_attest_without_upstream_authority_gate_fails(
    gate, tmp_path, monkeypatch
):
    wf = _write(
        tmp_path / "release-attest.yml",
        _CLEAN_ATTEST.replace(
            "    if: github.repository == 'NousResearch/hermes-agent'\n", ""
        ),
    )
    requirements = _write(
        tmp_path / "requirements-release-attest.txt",
        "pyyaml==6.0.3 --hash=sha256:abc\n",
    )
    monkeypatch.setattr(gate, "_ATTEST_WF", wf)
    monkeypatch.setattr(gate, "_ATTEST_REQUIREMENTS", requirements)
    findings = gate.Findings()
    gate.check_release_attest(findings)
    assert any("release authority" in item for item in findings.items)


def test_release_attest_without_hash_pinned_dependency_fails(
    gate, tmp_path, monkeypatch
):
    wf = _write(
        tmp_path / "release-attest.yml",
        _CLEAN_ATTEST.replace(
            " --only-binary=:all: --require-hashes", ""
        ),
    )
    requirements = _write(
        tmp_path / "requirements-release-attest.txt",
        "pyyaml==6.0.3 --hash=sha256:abc\n",
    )
    monkeypatch.setattr(gate, "_ATTEST_WF", wf)
    monkeypatch.setattr(gate, "_ATTEST_REQUIREMENTS", requirements)
    findings = gate.Findings()
    gate.check_release_attest(findings)
    assert any("--require-hashes" in item for item in findings.items)


# --- included-executable-component set (correction 4) ---------------------

_GOOD_RELEASE_IMAGE = """{
  "image": "x",
  "included_components": [
    {"name": "debian-base", "trust": "release_verified", "anchor": "dockerfile_from_sha256"},
    {"name": "python-deps", "trust": "lock_anchored", "anchor": "uv_lock"}
  ],
  "excluded_components": [{"name": "playwright-browser", "reason": "unpinned"}]
}"""


def test_real_repo_release_image_is_clean(gate):
    findings = gate.Findings()
    gate.check_release_image(findings)
    assert findings.ok(), findings.items


def test_transport_trusted_included_component_fails(gate, tmp_path, monkeypatch):
    bad = _GOOD_RELEASE_IMAGE.replace('"trust": "lock_anchored"', '"trust": "transport_trusted"')
    monkeypatch.setattr(gate, "_RELEASE_IMAGE", _write(tmp_path / "ri.json", bad))
    findings = gate.Findings()
    gate.check_release_image(findings)
    assert any("transport_trusted" in f or "must be release_verified" in f for f in findings.items)


def test_browser_included_fails(gate, tmp_path, monkeypatch):
    bad = _GOOD_RELEASE_IMAGE.replace(
        '{"name": "python-deps", "trust": "lock_anchored", "anchor": "uv_lock"}',
        '{"name": "python-deps", "trust": "lock_anchored", "anchor": "uv_lock"},\n'
        '    {"name": "playwright-browser", "trust": "release_verified", "anchor": "x"}'
    ).replace('"excluded_components": [{"name": "playwright-browser", "reason": "unpinned"}]',
              '"excluded_components": []')
    monkeypatch.setattr(gate, "_RELEASE_IMAGE", _write(tmp_path / "ri.json", bad))
    findings = gate.Findings()
    gate.check_release_image(findings)
    assert any("playwright-browser" in f for f in findings.items)


def test_unpinned_dockerfile_from_fails(gate, tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "_RELEASE_IMAGE", _write(tmp_path / "ri.json", _GOOD_RELEASE_IMAGE))
    monkeypatch.setattr(gate, "_DOCKERFILE", _write(tmp_path / "Dockerfile", "FROM debian:13.4\nRUN echo hi\n"))
    findings = gate.Findings()
    gate.check_release_image(findings)
    assert any("not @sha256-pinned" in f for f in findings.items)


def test_internal_stage_inheritance_uses_pinned_parent(gate, tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "_RELEASE_IMAGE", _write(tmp_path / "ri.json", _GOOD_RELEASE_IMAGE))
    dockerfile = (
        "FROM debian:13.4@sha256:" + "a" * 64 + " AS runtime_apt\n"
        "ARG ALLOW_UNVERIFIED_BROWSER=\n"
        "FROM runtime_apt AS runtime\n"
    )
    monkeypatch.setattr(gate, "_DOCKERFILE", _write(tmp_path / "Dockerfile", dockerfile))
    findings = gate.Findings()
    gate.check_release_image(findings)
    assert findings.ok(), findings.items
