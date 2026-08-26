# Supply-chain secure default — migration & operator guide (Work Package 4)

Hermes is now **secure by default** for every Hermes-managed
install/update/repair path. When a download cannot be chained to the committed
release manifest (an exact digest, or an independent provenance identity), the
mutable auto-install route **does not run**. Instead Hermes prefers an existing
operator-managed executable, and otherwise **fails closed** with actionable
guidance — no network fetch, no execution, no extraction.

This is enforced by `security.supply_chain.enforce: true` (the default). See
`docs/security/supply-chain-trust-root.md` for the trust model and
`supply-chain/ledger.json` for the full inventory of covered paths.

## What changed for operators

Under the default, these no longer auto-install/upgrade unverified code:

| Component | Old default | New default |
|---|---|---|
| `uv` bootstrap / self-update | ran `astral.sh` installer | operator-managed uv used in place, else fails closed |
| Managed Node (Windows heal, POSIX bootstrap, install scripts) | downloaded `nodejs.org/dist/latest-v…` | disabled; install Node via your manager |
| Managed npm upgrade | semver-range registry upgrade | disabled; current npm preserved |
| cua-driver (install + auto-repair) | ran trycua `main`-branch installer | disabled; compatible existing driver preserved |
| Hermes update ZIP fallback | downloaded `refs/heads/<branch>.zip` | disabled; use the git update (records exact commit) |
| tirith scanner auto-install | downloaded `releases/latest` | disabled; degrades to pattern-matching guards |
| Lazy dependency installs | installed unpinned PyPI packages | disabled; `pip install` the extra yourself |
| browser-use payload | `uvx browser-use` / `uv tool install` | disabled; requires an installed managed binary |
| MCP bootstrap deps | ran unpinned bootstrap commands | disabled |
| Profile distribution install | shallow-cloned mutable git HEAD | disabled |
| NixOS first boot uv | ran `astral.sh` installer | disabled; provision uv via Nix |

Docker base images are now all pinned by `@sha256` digest.

## How to keep things working (recommended)

**Install the tool with your OS / version manager — Hermes uses it in place.**
This is the preferred path; the external manager owns signature/integrity, and
Hermes records the resolved executable and version without relabelling it as
release-verified.

- `uv`: `pipx install uv`, `brew install uv`, `winget install astral-sh.uv`
- Node.js: `nvm`, `fnm`, `apt`, `brew`, `winget`, `nvm-windows`
- cua-driver: install manually per the trycua/cua release notes
- browser-use: install the CLI persistently, then Hermes will resolve it

## Explicit opt-in (scoped — config or CLI flag, never env vars)

If you accept the risk of running the legacy, unverified installer for a
specific component, opt in explicitly. Consent is **scoped per component** —
allowing one legacy/external manager never reactivates unrelated auto-downloads.
The compatibility path is visibly labelled and never writes a release-verified
marker.

- **Installed Hermes — scoped, per component (recommended):** in
  `~/.hermes/config.yaml`
  ```yaml
  security:
    supply_chain:
      enforce: true                       # stays secure for everything else
      allow_unverified_components: ["uv"] # only uv's unverified installer runs
  ```
  Component ids: `uv`, `node`, `npm`, `cua-driver`, `tirith`, `lazy-deps`,
  `feature-pip`, `mcp-bootstrap`, `browser-use`, `profile-distribution`,
  `plugins`, `skills`, `hermes-source-zip`, `iron-proxy`, `bws`,
  `android-psutil`, `managed-python`, `wake-word-model`, `electron-native`.
  (`feature-pip` covers optional feature / memory-provider / setup-hook PyPI
  installs; `lazy-deps` covers first-use lazy installs and the
  Chromium/agent-browser binary download; `wake-word-model` covers the one-time
  sherpa KWS model archive; `electron-native` covers the desktop
  node-pty/get-windows network native rebuild.)
  Use `["*"]` to allow all (discouraged, but still an explicit, deliberate list
  choice).

- **`enforce: false` does NOT authorize installers.** It only lowers the
  *verifier's* enforcement posture; it never silently re-enables mutable
  installers. Every component still fails closed unless it is named in
  `allow_unverified_components` (or the `"*"` sentinel). This is deliberate — a
  single global switch must not turn every unrelated auto-download back on at
  once. To allow everything you must write `allow_unverified_components: ["*"]`.
  ```yaml
  security:
    supply_chain:
      enforce: false                       # lowers verifier posture only…
      allow_unverified_components: ["*"]   # …authorization still needs THIS
  ```

- **Pre-config shell / PowerShell installers (before config exists):** pass the
  explicit CLI flag — there is **no environment-variable interface**.
  ```bash
  ./setup-hermes.sh --allow-unverified-bootstrap
  # scripts/install.sh --allow-unverified-bootstrap
  ```
  ```powershell
  powershell -File install.ps1 -AllowUnverifiedBootstrap
  ```

- **NixOS module:** set the option (not an env var)
  ```nix
  services.hermes-agent.allowUnverifiedBootstrap = true;
  ```

- **Docker image build:** the Playwright browser payload has no manifest
  identity, so the build fails closed by default; acknowledge explicitly with
  `--build-arg ALLOW_UNVERIFIED_BROWSER=1`.

The removed `HERMES_ALLOW_UNVERIFIED_BOOTSTRAP` / `HERMES_SUPPLY_CHAIN_ENFORCE`
environment variables are no longer honored as a user interface (repository
policy forbids new `HERMES_*` env vars for non-secret settings). An internal
bridge (`_HERMES_SC_BOOTSTRAP_OVERRIDE`) exists only to carry the parsed CLI
flag into sub-scripts; do not set it directly.

## Secure-default behaviors added in the WP4 hardening rounds

- **Node/uv execution markers now cover the POSIX bootstrap and the PowerShell
  resolver (A1, final).** The A6 marker rule (never execute a managed runtime
  without a current provenance marker) is enforced in every resolver, not only
  the Python one. `scripts/lib/node-bootstrap.sh` verifies the marker before
  `ensure_node` executes a managed Node — including one reached through the
  `~/.local/bin` symlink it puts on PATH — so an unmarked/tampered tree is
  re-healed (or fails closed under the secure default) instead of being run for
  a `--version` probe; a verified bundled install writes the node/npm/npx
  markers so later runs trust it. `scripts/install.ps1` re-validates the cached
  `$script:UvCmd` on **every** `Resolve-UvCmd` call (a managed uv that lost its
  marker or was tampered is dropped and re-discovered, never reused) and gates
  `Test-Node`'s PATH-resolved `node` through the managed-alias check before
  executing it.
- **Managed Node execution requires a WHOLE-TREE provenance marker (A6/A1).** A
  Hermes-managed Node tree (`$HERMES_HOME/node`) is only executed when it carries
  a current `.provenance.json` marker that binds the **complete tree**: the
  `node` executable's bytes AND a deterministic digest over the whole tree — the
  node binary, the npm/npx wrappers, and the npm CLI JS under `node_modules/npm`.
  A swap of ANY of them (node, npm, npx, or a single npm library file) changes a
  bound digest and is rejected. The whole tree is **rehashed on every resolve —
  there is no (size, mtime) cache** (final): a same-size, mtime-restored in-place
  edit of one npm library file (a `touch -r` after a byte swap) would defeat an
  (size, mtime) cache, so it is still caught. node/npm/npx are validated together
  because the marker binds the whole tree, BEFORE any `node --version` probe
  executes. A verified heal/bootstrap writes the marker (the POSIX/PowerShell
  installers additionally write per-binary markers for their own pre-execution
  validation; the Python resolver's first-resolve heal upgrades a tree to the
  whole-tree marker without re-downloading a present tree). An **unmarked legacy
  tree** (installed before markers) or a **tampered** one is ignored: Hermes
  falls back to an operator-PATH Node used in place, or (for a trusted-but-broken
  tree) fails closed. If node tools stop resolving after an update, either install
  a Node with your OS/version manager (used in place) or allow a re-provision with
  `security.supply_chain.allow_unverified_components: ["node"]`. Hermes keeps no
  managed browser-binary store — Chromium/agent-browser resolve from Playwright's
  shared cache, operator PATH, or lock-anchored `node_modules`, and their download
  stays gated (`lazy-deps`).
- **Termux installs fail closed without a hash-locked graph (A7).** The Android
  pip path is version-constrained (`constraints-termux.txt`), not
  `--require-hashes`. Under the secure default it does not run at all; use
  `install.sh --allow-unverified-bootstrap` (break-glass) or provision a
  hash-locked Termux venv yourself.
- **install.ps1 pip fallback is gated (A7).** When the hash-verified
  `uv sync --extra all --locked` is unavailable or fails, the `uv pip install`
  re-resolve cascade — plus the `[web]` repair and the voice/wake pre-install —
  runs only under `-AllowUnverifiedBootstrap`; the secure default aborts and the
  venv transaction rolls back to the previous working install.
- **npm dependency installs never run arbitrary lifecycle scripts (A4).** Every
  production `npm install` / `npm ci` — the Docker image (root workspace + photon
  sidecar), `scripts/install.sh` / `scripts/install.ps1` (Node deps, TUI, desktop
  build, browser tools), `scripts/lib/node-bootstrap.sh`, `nix/lib.nix`,
  `hermes setup` / `hermes update` frontend builds
  (`_run_npm_install_deterministic`), the photon iMessage sidecar, and the
  WhatsApp Baileys bridge — runs with `--ignore-scripts`. npm 10 IGNORES the
  package.json `allowScripts` allowlist, so `--ignore-scripts` is the only
  version-independent guarantee that a dependency cannot run arbitrary
  install-time code. The reviewed, allowlisted native lifecycle (node-pty
  prebuild, esbuild, the Electron binary) then runs via the audited orchestrator
  `apps/desktop/scripts/run-allowed-lifecycle.mjs`, which `npm rebuild`s only
  lock-version-matched allowlisted packages; **`get-windows` is on the
  orchestrator deny-list (`NEVER_RUN`) and is never rebuilt** (its binding is
  staged from a manifest-pinned digest instead). Standalone sidecars run only
  their own reviewed first-party lifecycle explicitly (the photon spectrum-ts
  patch). CI enforces this repo-wide: `scripts/ci/check_supply_chain.py` fails on
  any production `npm install` / `npm ci` that lacks `--ignore-scripts`
  (`--package-lock-only`, which installs nothing, is exempt). This is not
  operator-configurable — there is no way to re-enable unaudited npm lifecycle
  scripts.
- **Cross-profile managed aliases are gated (A6, final).** `hermes_managed_roots()`
  enumerates the default Hermes root AND every `~/.hermes/profiles/*` managed
  root (bin / node / uv-tools / cache / browsers), independent of the active
  `HERMES_HOME`. A secondary profile therefore cannot execute the default (or a
  sibling) profile's managed uv/node/bws/browser-use/… binary reached via a
  PATH / symlink / junction / case alias: every operator-path fallback
  canonicalizes (realpath + case-fold) and, if it lands in ANY profile's managed
  root, requires the provenance marker. The pre-config `install.sh` /
  `install.ps1` fast paths verify a managed uv/node's marker+digest (pure
  shell/PowerShell, no config dependency) BEFORE running it — an unmarked or
  tampered managed binary is never executed, not even for a `--version` probe.
- **browser-use tool-tree integrity is rehashed every resolve (A6, final).** The
  uv-tool provenance marker binds the launcher AND the whole tool venv tree;
  `tool_marker_ok()` rehashes the full tree on every resolve (no launcher-keyed
  cache), so an in-place mutation of any file in the venv is rejected on the very
  next invocation — even within one process.
- **npm coverage extends to package.json scripts + workflows (A3, final).** The
  root `install:*` scripts run `--ignore-scripts` then the audited orchestrator.
  The workflow npm bootstrap no longer runs `npm i -g npm@…` at all (version-
  exact but still registry-metadata-trusting): it runs the digest-pinned trusted
  installer `node scripts/ci/install-npm-pinned.mjs`, which downloads the EXACT
  canonical tarball (bounded redirects restricted to approved hosts; https
  required off-loopback), verifies the sha256 over the bytes BEFORE install, then
  installs the LOCAL verified tarball with `npm -g --ignore-scripts --offline`.
  Identity (version/url/sha256) lives once in `supply-chain/npm-bootstrap.json`,
  validated against `nix/npm-12-0-2.nix`. The CI scanner
  (`scripts/ci/check_supply_chain.py`) parses executable `package.json` `scripts`
  and workflow `run:` / `with: command:` blocks (docs workflows included) and
  fails on an ungated install/ci OR a direct global `npm@…` registry install.
- **Release publish is fail-closed until apt-closure baselines are seeded (A10).**
  `supply-chain/apt-closure-{amd64,arm64}.txt` must exist; the Docker publish job
  audits the built image's package set against them BEFORE push and fails on
  drift or a missing baseline. Seed them from the `apt-closure-candidate-*`
  artifact uploaded by the (non-publishing) build job.

## For maintainers: promoting a component to release-verified

`scripts/release/update_supply_chain_manifest.py` pins an exact
component/version, records per-artifact digests (or an upstream provenance
identity), bumps the manifest sequence, and refuses to write on verification
failure. Once a component is pinned in `supply-chain/manifest.json`,
`gate.py::guard_install` PLANS the fetch — it verifies the compiled-in trust
root + freshness and returns `PROCEED`, but **commits no state** (committing
before the caller's download/publish would advance the high-water for an install
that may still fail). The real reachable sink,
`hermes_cli/supply_chain/publish_cli.py::publish_component` (CLI:
`python -m hermes_cli.supply_chain.publish_cli`), then stages the archive and
calls `publish_release_verified`, which acquires the anti-rollback lock, reloads
+ re-verifies the trust root, rechecks the high-water mark, verifies the staged
digest, atomically publishes WITH rollback, and commits the high-water AFTER the
swap (a state-write failure rolls the publish back). Desktop routes
Electron/get-windows publication through this same helper so the release-verified
sink is one shared kernel-locked transaction across Python and JS. The
downloaded-manifest verify path (`SupplyChainVerifier(downloaded=True)`) is a
tested defensive building block for the planned Sigstore-attested remote
manifest — the in-tree manifest is the only active production trust path today,
so no "load a downloaded manifest" entry point is exported.

### The publication transaction (A6, final)

`hermes_cli/supply_chain/transaction.py::publish_release_verified` is the shared
chokepoint for placing a release-verified artifact on disk. Ordering is
load-bearing and mirrored by any JS integration:

1. **Stage + hash OUTSIDE the lock** — download to a sibling staging dir and
   compute its sha256 with no lock held (slow work does not serialize).
2. Acquire the real cross-process advisory lock (`state.py::_cross_process_lock`,
   `fcntl.flock` / `msvcrt.locking`, no unlink-of-live-holder).
3. **Re-load** anti-rollback state and **re-verify** the compiled trust root +
   freshness, then **re-check** the sequence high-water — a stale publisher
   (lower sequence) that stalled during staging fails here.
4. Verify the staged bytes' digest equals the manifest artifact digest.
5. **Atomically swap** the target with rollback, preserving the previous working
   install on any failure.
6. **Only then** commit the sequence/component floor and release the lock.
   Never commit before a successful publish.

A concurrent test drives the race directly: an older transaction stages and
stalls, a newer one (N+1) publishes and commits under the lock, and the older
one's under-lock recheck then refuses — it can neither publish nor overwrite.

**The Electron/get-windows publication is wired to the real Python transaction.**
The Desktop build has NO JS lock: `apps/desktop/scripts/run-electron-builder.mjs`
(Electron) and `stage-native-deps.mjs` (get-windows) extract/assemble the
verified tree into a sibling stage OUTSIDE the target, then route the swap
through `apps/desktop/scripts/python-publish.mjs::publishThroughPythonTransaction`,
which spawns `python -m hermes_cli.supply_chain.publish_cli`
(`--component --target --staged-dir --staged-sha256 --platform --arch [--state]`).
That CLI is the reachable Python sink (`publish_cli.py::publish_component` →
`transaction.py::publish_release_verified`): it acquires the kernel advisory lock
(`fcntl.flock` / `msvcrt.locking`), reloads + re-verifies state and the compiled
trust root, rechecks the electron/get-windows high-water, verifies the staged
digest against the committed manifest, atomically swaps WITH rollback (the prior
verified dist is preserved on any failure), and commits the high-water AFTER the
swap. Absent `--state`, the anti-rollback high-water lands in the profile state
(`$HERMES_HOME/supply-chain/state.json`), not inside `node_modules`. There is ONE
transaction authority (the Python kernel lock) shared across the JS surfaces — the
earlier JS `O_EXCL` lock was removed. Behavior tests:
`tests/supply_chain/test_a6_transaction.py` (concurrency/replay, digest mismatch,
rollback, commit-after ordering, state-write-failure rollback),
`tests/supply_chain/test_a9_chokepoint.py` (guard is plan-only; the sink commits),
and Desktop's `tests/supply_chain/test_publish_cli_multiprocess.py`
(true-multiprocess CLI + kernel-lock: fresh-install persistence, digest-mismatch
fail-closed, replay/downgrade, cross-process mutual exclusion, dead-holder
reclaim, unusable-state fail-closed).

### CI supply-chain scan is fail-closed without PyYAML (A5, final)

The `manifest-ledger` CI job runs `scripts/ci/check_supply_chain.py` with the
standard library only. Its workflow scan uses a stdlib command extractor that
handles block/folded `run:` scalars, list `run:`, `with: command:`, and
composite-action YAML, so a missing PyYAML can no longer make the scan silently
pass over an ungated `npm install` in a block scalar; an unreadable or
unparseable workflow file is a hard error, not a skip.

## Metadata discovery

Non-executable metadata (model catalog JSON, plugin index JSON) may still be
fetched from a mutable source — it is data, never executed. Executable
extensions (plugins, skills, profiles) still require a reviewed pinned identity
before activation.
