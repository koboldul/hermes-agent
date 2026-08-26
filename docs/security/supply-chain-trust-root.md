# Supply-chain trust root (Work Package 4)

This document defines the trust anchor, freshness, and rollback-resistance model
for every Hermes-managed direct-download artifact. It is the authoritative
reference cited by `supply-chain/manifest.json`
(`manifest.signer.fingerprint_publication`) and by the operator guidance that
the verifier prints when it fails closed.

The implementation lives in `hermes_cli/supply_chain/` and is enforced in CI by
`scripts/ci/check_supply_chain.py`. The machine-readable inventory of audited
paths is `supply-chain/ledger.json`.

## The core problem

An exact SHA-256 digest proves that bytes match a manifest. It does **not**
prove that a fresh machine received an authentic manifest. A checksum,
signature, public key, and installer all downloaded from the *same* mutable
channel establish transport trust, not authenticity — an attacker who controls
that channel controls all of them at once.

The manifest therefore needs an anchor that does **not** come from the same
endpoint as the artifact. Hermes uses **GitHub Artifact Attestations**
(Sigstore keyless OIDC) rooted in the public Fulcio/Rekor transparency logs and
pinned to an exact `NousResearch/hermes-agent` release-workflow identity.

## Trust classes

Every audited path resolves to exactly one class (see the ledger's
`trust_owner` and the manifest's `trust_class`):

1. **`release_verified`** — the artifact identity chains to the pre-established
   Hermes trust anchor: either a committed exact byte digest *or* an
   independent upstream provenance identity (Sigstore keyless OIDC). This is
   the only class that may write a "release-verified" marker.
2. **`operator_managed`** — an OS package manager or version manager the
   operator chose explicitly owns signature and update verification. Hermes
   records the resolved executable and version, uses it in place, and never
   copies it into Hermes-managed storage or relabels it as release-verified.
3. **`transport_trusted`** — HTTPS plus a release account supplied all
   verification material with no independent anchor. This remains a
   *compatibility* flow. It is labelled accurately, never writes a
   release-verified marker, and is **not** sufficient for hardened
   installation. Under `security.supply_chain.enforce`, it fails closed.
4. **`first_party_git`** — a git checkout update (fetch + resolve + record the
   exact remote commit). A documented first-party trust boundary, visibly
   labelled and never masquerading as a release-verified artifact.

## Signing identity

`supply-chain/manifest.json` records the signer:

- **type:** `github-artifact-attestation` (Sigstore keyless OIDC).
- **issuer:** `https://token.actions.githubusercontent.com`.
- **identity:** the exact workflow
  `NousResearch/hermes-agent/.github/workflows/release-attest.yml@refs/tags/v*`.
- **workflow:** `.github/workflows/release-attest.yml` produces the attestation
  with `actions/attest-build-provenance`, SHA-pinned.
- **release authority:** the attestation job runs only when
  `github.repository == 'NousResearch/hermes-agent'`. Fork tags are valid
  development artifacts, but they cannot mint a Hermes release attestation or
  become a trusted release channel accidentally.

The release gate installs its YAML parser from
`scripts/ci/requirements-release-attest.txt`, which binds the exact
Python 3.12 Linux wheel by URL and SHA-256 and is installed with
`--require-hashes --only-binary=:all:` before any release validation runs.

The identity regexp is pinned in-repo (reviewed code) and independently
published in this document. There is **no in-repo private key**: keyless OIDC
means the signing certificate is minted per-run by Fulcio for the workflow's
OIDC identity and logged in Rekor. An attacker cannot reproduce the identity
without controlling the pinned repository's Actions OIDC — which is exactly the
boundary a maintainer already trusts.

> No pre-existing release trust anchor was found when this work package landed.
> The manifest therefore ships every managed download as `transport_trusted`
> pending an exact pin, and the fresh-install path below is documented but not
> yet asserted as release-verified. Promoting a component to `release_verified`
> requires a maintainer to run the release-maintenance script (below) against a
> real signed release. Nothing here fabricates a digest or an anchor it cannot
> prove.

## How a fresh install validates the anchor

Two manifest sources, two rules (`SupplyChainVerifier.verify_trust_root`):

- **In-tree / installed manifest** — read from the committed source tree. It is
  trusted because it is reviewed code (the pre-established anchor). Freshness,
  sequence, floors, and revocation are still enforced.
- **Downloaded manifest** — its attestation must be verified against the pinned
  identity (`gh attestation verify` or `cosign verify-blob`) *before any field
  is trusted*. If no verifier tool is available, the install **fails closed**
  and directs the operator to the two-channel / OS-package bootstrap below. A
  same-channel key/checksum/signature never satisfies this check.

### Two-channel / OS-package fail-closed bootstrap

A one-line `curl … | sh` / `irm … | iex` against a mutable endpoint is **not**
release-verified and is never taught as the hardened path. When a verifier is
unavailable, hardened operators must use one of:

1. **OS / version manager** — install `uv`, Node, etc. from a package manager
   whose signatures the operator already trusts (`brew`, `apt`, `winget`,
   `pipx`, `nvm`, `fnm`). Hermes then records them as `operator_managed`.
2. **Documented two-channel manual bootstrap** — obtain the Hermes release
   artifact from the GitHub release page **and** independently verify its
   attestation via `gh attestation verify <artifact> --repo
   NousResearch/hermes-agent --cert-identity-regexp <pinned> --cert-oidc-issuer
   https://token.actions.githubusercontent.com` before executing it. The
   attestation is fetched from Rekor, a different trust root than the artifact
   host.

## Freshness, sequence, and rollback resistance

Enforced by `SupplyChainVerifier.check_freshness` and the persisted
anti-rollback state (`hermes_cli/supply_chain/state.py`, stored per-profile
under `HERMES_HOME/supply-chain/state.json`):

- **Monotonic sequence / release epoch** — `manifest.sequence` only increases.
  The machine records the highest accepted sequence; a manifest below that
  high-water mark is a replay/downgrade and is rejected before any download.
- **Minimum accepted sequence** — `manifest.min_sequence` rejects a validly
  signed but too-old manifest even on a fresh machine.
- **Expiry** — `manifest.expires_at`; an expired manifest is rejected.
- **Revocation list** — `manifest.revocations` blocks a specific
  component/version (or every manifest at/below a sequence) so a known-bad but
  validly signed artifact cannot be installed.
- **Security floor / anti-rollback** — a component version below its
  `security_floor`, or below the last version this machine installed, fails
  closed. A vulnerable old version cannot be re-installed by replaying an old
  manifest.

## Key custody, rotation, revocation, recovery

- **Custody** — there is no long-lived signing key to store. The OIDC identity
  is the credential; custody reduces to controlling who can run the pinned
  release workflow on `NousResearch/hermes-agent` (branch/tag protection +
  environment approvals).
- **Rotation** — changing the signing identity means changing
  `manifest.signer.identity_regexp` (and the workflow), which is a reviewed
  source change. An unannounced replacement identity fails verification: clients
  only accept the identity pinned in the code they already trust.
- **Revocation** — add the component/version (or a `max_sequence`) to
  `manifest.revocations` and bump `sequence`. Clients reject the revoked
  artifact on their next manifest refresh.
- **Emergency recovery** — if the OIDC identity is compromised, ship a new
  reviewed manifest (new identity, higher sequence, revoking the compromised
  range) through the normal code-review + release path, and communicate the
  OS-package / two-channel bootstrap for machines that cannot yet fetch the new
  manifest. Rotation is authorized only through the documented old-identity /
  OS-package trust path — never a silent key swap.

## Supported-component EOL and advisory SLA

- Each component carries `review_date` and optional `eol`. CI surfaces expiry;
  a maintainer refreshes the pin via the release-maintenance script.
- Security advisories for pinned runtimes are owned by the release maintainers.
  The target is an emergency verified-update turnaround measured in days: a new
  reviewed manifest that pins the fixed version, raises the security floor, and
  bumps the sequence.

## Git commit / tag signature policy

First-party `first_party_git` updates fetch the configured remote, resolve and
record the exact remote commit before applying, and preserve that commit in the
update receipt. A hardened release channel may additionally require signed
commits/tags; the transparency-log evidence for release artifacts is the
Rekor entry produced by the attestation workflow.

## Release maintenance

`scripts/release/update_supply_chain_manifest.py` is the maintainer-only tool
that pins an exact component/version, downloads upstream checksum/provenance
material, verifies it, computes the manifest digest entries, bumps the
sequence, and refuses to write when upstream verification fails. It never
resolves `latest`; normal managed installation consumes only committed values.

## What pinning does and does not do

Pinning proves *what* was installed; it does not sandbox the code. This
preserves the `SECURITY.md` trust model: operator code review of plugins,
skills, and drivers remains required. Release verification is about
authenticity and integrity of the fetch, not about the safety of what the
verified bytes then do.
