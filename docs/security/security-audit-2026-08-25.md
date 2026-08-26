# Security Audit Findings - 2026-08-25

## Document status

This document records a source review of Hermes Agent at commit
`4715597ecc356e40eabd6d2fd2746e24b8bcb364` on 2026-08-25. It is a
point-in-time engineering assessment, not a claim that the repository is free
of other vulnerabilities.

The audit and remediation plan were published on the public default branch on
2026-08-25. Disclosure is therefore in progress. The remediation plan was
corrected after security-architecture review to require an allowlisted LSP
environment, affirmative auto-install consent, an independently anchored
release trust root with anti-rollback, and inert Desktop social content until
frame-aware IPC and permission controls are proven.

The review used the trust model in [SECURITY.md](../../SECURITY.md). In
particular:

- The operating system is the only boundary against an adversarial model.
- Plugins and skills execute with the agent process's privileges.
- The dashboard is a network-exposed HTTP surface and requires authorization
  when a caller outside the intended trust envelope can reach it. Loopback
  reachability alone does not identify an OS user on a shared host.
- Credential scrubbing is defense in depth, but code paths documented as using
  it must not silently bypass it.

The corresponding implementation plan is
[security-remediation-plan-2026-08-25.md](security-remediation-plan-2026-08-25.md).

## Executive summary

The audit identified five concrete weaknesses:

| ID | Severity | Confidence | Classification | Summary |
| --- | --- | --- | --- | --- |
| SEC-AUDIT-001 | High on shared hosts | High | In-scope vulnerability | An unauthenticated loopback page discloses the dashboard session token. |
| SEC-AUDIT-002 | High | High | In-scope vulnerability | Default LSP auto-install executes mutable packages with the full process environment. |
| SEC-AUDIT-003 | Medium | High | Verified hardening issue | Automatic title and favicon resolution can make requests to private or local services. |
| SEC-AUDIT-004 | Medium | High | Supply-chain hardening | Multiple runtime, dependency, browser, extension, and update paths resolve mutable executable content. |
| SEC-AUDIT-005 | High | High | In-scope vulnerability | Mutable third-party social scripts execute inside the privileged Desktop renderer document. |

The highest priorities are the dashboard credential exchange, the LSP
subprocess environment, and Desktop remote-script isolation. Each can expose
credentials or host-level capabilities without first compromising the model or
bypassing an approval heuristic.

No high-confidence unauthenticated Internet remote-code-execution path, unsafe
deserialization path, or general archive/path traversal path was confirmed in
the reviewed surfaces. That statement is limited to this review and this
revision.

## Scope and method

The review followed concrete data and control flows across:

- dashboard HTTP, WebSocket, JSON-RPC, PTY, environment, file, and session APIs;
- Desktop renderer, preload IPC, Electron main-process networking, and hidden
  BrowserWindow behavior;
- LSP package installation and language-server process creation;
- bootstrap and managed-runtime downloads;
- plugin, skill, MCP, terminal, cron, delegation, and profile trust boundaries;
- logs, state databases, backups, update receipts, attachments, subprocess
  environments, and error responses;
- authentication, authorization, SSRF, command injection, path traversal,
  unsafe deserialization, credential leakage, and supply-chain risks.

A finding was classified as confirmed only when the source showed a complete
attacker-controlled flow to a security-relevant effect. Probabilistic model
behavior and defense-in-depth concerns are listed separately under
[Items requiring validation](#items-requiring-validation).

## Security assets

The main assets exposed by a successful attack are:

- provider API keys, OAuth grants, messaging bot tokens, relay credentials,
  cloud-compute credentials, and dashboard authorization material;
- complete prompts, replies, tool results, attachments, memory, session lineage,
  cron jobs, and profile state;
- the host user's files, shell authority, clipboard, browser sessions, camera,
  and microphone;
- external messaging identities and channels controlled by configured adapters;
- plugin, skill, MCP, update, and managed-runtime integrity.

## Attacker profiles

The relevant attackers are:

1. An unauthenticated network or LAN caller reaching an exposed service.
2. Another OS user, container, CI worker, or sandbox on a shared host.
3. An unauthorized sender on a configured messaging platform.
4. An authorized but malicious participant in a permitted channel.
5. A malicious website, repository, document, tool result, or MCP server.
6. A compromised package registry, package maintainer, CDN, or release account.
7. A malicious or compromised plugin or skill accepted by the operator.
8. A compromised Desktop renderer attempting to cross the preload/main-process
   boundary.

## Verified findings and hardening gaps

This section records behavior verified in source. It does not classify every
item as an in-scope vulnerability under `SECURITY.md`:

- SEC-AUDIT-002 violates the documented credential-scrubbing stance directly.
- SEC-AUDIT-001 permits an unauthorized caller to cross the dashboard's
  network-exposed HTTP boundary on a shared host.
- SEC-AUDIT-003 is a verified SSRF primitive and privacy issue, but it is
  defense-in-depth under the current policy until a supported deployment shows
  a concrete §3.1 boundary crossing.
- SEC-AUDIT-004 is a verified mutable supply-chain path, not evidence that an
  upstream is currently compromised.
- SEC-AUDIT-005 lets remotely controlled JavaScript execute in the same
  renderer world as the app and its preload bridge.

### SEC-AUDIT-001: Loopback dashboard token disclosure

**Severity:** High  
**Confidence:** High  
**Affected deployment:** Browser dashboard in token-authenticated loopback mode  
**Primary files:**

- `hermes_cli/web_server.py`, `auth_middleware`
- `hermes_cli/web_server.py`, `mount_spa` and `_serve_index`
- `hermes_cli/web_server.py`, `reveal_env_var`

#### Current behavior

The dashboard's HTTP middleware requires `_SESSION_TOKEN` for protected
`/api/*` routes when the OAuth/password gate is not active. The SPA entry page
is not an `/api/*` route and is therefore available without that credential.

In loopback mode, `_serve_index()` injects
`window.__HERMES_SESSION_TOKEN__="<token>"` into the returned HTML. A caller
that can connect to the loopback listener can therefore:

1. Request the dashboard page without authentication.
2. Read the session token from the HTML.
3. Reuse it as the dashboard session header or a supported query token.
4. Call privileged dashboard APIs.

`POST /api/env/reveal` demonstrates the confidentiality impact directly: after
the token check, it returns an unredacted value from the selected profile's
credential environment. The same credential also admits session, PTY,
configuration, file, plugin, backup, and JSON-RPC surfaces according to their
normal route authorization.

#### Attacker prerequisites

The attacker needs the ability to connect to the dashboard's loopback TCP port.
This is normally any process on the host, and can include another OS user,
container, CI worker, or co-tenant depending on host networking. The attacker
does not need to know or guess the random token.

The exact disclosure does not apply to the headless `hermes serve` path because
that path does not mount the SPA.

#### Boundary crossed

`SECURITY.md` lists the dashboard as a network-exposed HTTP surface and
requires authorization at network surfaces. Its loopback/OS-account allowance
is stated for editor and local-IPC surfaces, not as a general exception for the
dashboard.

Loopback TCP constrains traffic to the host but does not authenticate an OS
user. On a shared host, another user or co-tenant can be outside the intended
authorization set while still retrieving the session token and calling
protected dashboard routes. This is unauthorized external-surface access under
§3.1. On a genuinely single-user host, the attacker prerequisite is absent.

The remediation should also clarify this deployment distinction in
`SECURITY.md` so "loopback" is not read as per-user authorization.

#### Existing controls

The following controls are useful but do not stop this attack:

- random token generation;
- host-header validation;
- browser Origin and CORS checks;
- rate limiting on individual sensitive routes;
- non-loopback OAuth/password gating;
- WebSocket loopback checks.

They either protect a different boundary or run after the token has been
disclosed.

#### Impact

A successful attacker can obtain sensitive profile data, read conversations,
modify configuration, use agent and terminal surfaces, and potentially execute
commands with the Hermes service account's privileges. In a multiplexed
dashboard, compromise of the shared dashboard credential may expose more than
one profile.

#### Required security property

Fetching unauthenticated static assets must never reveal a reusable privileged
credential. A browser must prove possession of a launch credential that is not
available from the listening socket before it receives an authenticated
session.

---

### SEC-AUDIT-002: Mutable LSP installation and secret-bearing subprocesses

**Severity:** High  
**Confidence:** High  
**Affected deployment:** Default configuration when an LSP server is missing
and the applicable package manager is available  
**Primary files:**

- `hermes_cli/config_defaults.py`, `lsp.install_strategy`
- `agent/lsp/install.py`, `INSTALL_RECIPES` and `_install_npm`
- `agent/lsp/client.py`, `LSPClient._spawn`
- `tools/environments/local.py`, `build_subprocess_env`

#### Current behavior

LSP support is enabled by default and uses `install_strategy: auto`. On first
use in a supported git workspace, a missing server can be installed into
`HERMES_HOME`.

The installation recipes contain mutable package references:

- npm package names without exact versions;
- `golang.org/x/tools/gopls@latest`;
- no repository-owned lock or integrity manifest for the dynamically installed
  dependency graph.

The npm installer does not set `--ignore-scripts`, so package lifecycle scripts
may execute during installation. The `subprocess.run()` call does not pass an
explicit sanitized environment and therefore inherits the complete agent
process environment.

After installation, `LSPClient._spawn()` starts the language server from
`dict(os.environ)` plus optional overrides. This bypasses
`build_subprocess_env()`, whose own contract says every spawn site should use
the central profile-propagation and secret-scrub policy.

#### Attacker prerequisites

An attacker must compromise one of the following:

- an LSP package or transitive package;
- a package maintainer or release account;
- registry or release resolution;
- a package lifecycle script.

The corresponding package manager must be usable: managed npm or npm on
`PATH` for npm recipes, or Go on `PATH` for `gopls`. Without it, auto-install
returns without executing a package.

No prompt-injection success is required once a malicious package is selected.
Normal first-use LSP behavior executes it.

#### Vulnerable flow

1. A file operation in a supported git workspace requests LSP diagnostics.
2. Hermes cannot find the language server.
3. Auto-install resolves a mutable package reference.
4. The package manager executes with the agent's inherited environment.
5. A package lifecycle script can read and exfiltrate credentials immediately.
6. The installed language server later starts with the same full environment.

#### Existing controls

Hermes already has a central subprocess environment builder that removes
provider credentials and Hermes-internal secrets, propagates the correct
profile home, and handles concurrent session context. Shell, MCP, cron, and
other subprocess paths use related scrub logic. The LSP installer and client do
not use that control.

Repository lockfiles do not protect packages dynamically installed into
`HERMES_HOME/lsp`.

#### Impact

A compromised package can execute arbitrary code as the Hermes user and read
provider keys, messaging tokens, profile state, dashboard credentials, relay
secrets, and any other process-visible credential. It can persist through the
managed LSP installation and execute again when the server starts.

#### Required security property

Every LSP installer and language-server child must receive a purpose-specific
environment constructed from a declared allowlist. Removing known secrets from
an inherited environment is insufficient because unrelated credentials and
passthrough values remain process-visible. Automatic installations must require
affirmative consent for the current policy version and resolve to a
repository-reviewed, immutable dependency graph.

---

### SEC-AUDIT-003: Automatic Desktop metadata SSRF and privacy leak

**Severity:** Medium  
**Confidence:** High  
**Affected deployment:** Electron Desktop rendering unlabelled HTTP(S) URLs  
**Primary files:**

- `apps/desktop/src/lib/external-link.tsx`, `isTitleFetchable`,
  `useLinkTitle`, `PrettyLink`, and `LinkifiedText`
- `apps/desktop/electron/main.ts`, `fetchHtmlTitleWithCurl`,
  `runRenderTitleJob`, `fetchLinkTitle`, `faviconFetch`,
  `resolveFaviconCached`, and the IPC registrations
- `apps/desktop/electron/link-title-window.ts`
- `apps/desktop/electron/favicon.ts`, `resolveFavicon`

**Policy classification:** Verified hardening issue. Under the current
`SECURITY.md`, authorized participants are equally trusted, prompt injection
alone is not a vulnerability, and processing uncontrolled content without
whole-process isolation is outside the supported posture. Promote this item to
an in-scope vulnerability only if testing demonstrates a concrete §3.1 effect
in a supported deployment, such as escape from a declared network boundary or
disclosure of protected data. The automatic request and private-network reach
remain real behavior worth fixing.

#### Current behavior

When Desktop renders a bare or otherwise unlabelled URL, `PrettyLink` invokes
`useLinkTitle()`. The hook calls the preload bridge during rendering without a
user click.

The renderer rejects non-HTTP schemes and a narrow list of literal loopback
host forms. The main process does not independently enforce an address policy.
The title path:

1. invokes `curl --location` for the supplied URL;
2. follows up to three redirects;
3. reads a limited response body for a title;
4. falls back to a hidden, sandboxed, JavaScript-enabled BrowserWindow when a
   usable title is not found.

The sibling favicon path is exposed through `hermes:resolveFavicon`. It uses
`electronNet.fetch(..., redirect: "follow")` to fetch the page, an optional
manifest, and candidate icon images. Page-controlled manifest and icon URLs can
therefore redirect or point directly to private network space. It has byte and
type checks for returned images but no DNS/address policy or connection
pinning.

#### Attacker prerequisites

The attacker needs to place a URL in content for which Desktop resolves a title
or favicon. Possible sources include an authorized messaging participant,
model output derived from untrusted content, a tool/MCP result reflected into
the transcript, or a public page that declares a private manifest/icon URL. A
compromised authorized renderer can also invoke the preload capabilities
directly.

#### Why the renderer check is insufficient

The literal-host check does not cover:

- public DNS names resolving to private, loopback, or link-local addresses;
- public-to-private redirects;
- DNS rebinding between validation and connection;
- RFC1918, carrier-grade NAT, reserved, multicast, or IPv6 local ranges;
- cloud metadata endpoints and internal DNS names;
- alternate address representations.

Security enforcement in the renderer is also the wrong boundary. The
main-process IPC handler must treat every renderer argument as untrusted.

#### Impact

The automatic requests disclose the user's public IP address, timing, and
Desktop-specific User-Agent to an attacker-controlled server. They can also
make blind requests to localhost, LAN services, development servers, router
interfaces, or cloud metadata endpoints. GET endpoints with side effects may
be triggered. The hidden title renderer additionally executes attacker
JavaScript in an isolated Electron renderer and can interact with reachable
network services subject to Chromium's controls.

#### Existing controls

The hidden window uses context isolation, sandboxing, disabled Node
integration, muted audio, a separate session, and download cancellation. These
reduce renderer compromise and nuisance effects. They do not prevent SSRF or
automatic privacy leakage. Favicon resolution limits response size and sniffs
image bytes before returning a data URL, but those checks happen after the
network request.

#### Required security property

No external metadata request should occur merely because untrusted text was
rendered under the secure default. When the user requests a title or favicon,
the main process must validate and pin every page, redirect, manifest, and image
destination before connecting.

---

### SEC-AUDIT-005: Mutable social scripts execute in the Desktop app renderer

**Severity:** High  
**Confidence:** High  
**Affected deployment:** Electron Desktop rendering supported social embeds  
**Primary files:**

- `apps/desktop/src/components/assistant-ui/embeds/social-embed.tsx`,
  `SCRIPT`, `loadScript`, and `SocialEmbedRenderer`
- the Desktop preload bridge exposed through `window.hermesDesktop`

#### Current behavior

The social-embed renderer dynamically appends remote script elements for
Instagram, TikTok, and Twitter. The script URLs are not pinned to immutable
versions and have no repository-owned digest or Subresource Integrity value.

These scripts execute in the real Desktop renderer document, not an isolated
cross-origin frame. Electron context isolation separates the renderer from
Electron internals, but the application's context-bridge API is intentionally
exposed to the renderer as `window.hermesDesktop`. Code executing in that
document can call the same preload capabilities as application JavaScript.

#### Attacker prerequisites

An attacker must compromise a social provider's script distribution, release
account, CDN, or trusted transport. An attacker-controlled embed alone does not
replace the provider script, but it can determine when and where that script is
loaded.

#### Boundary crossed

The social provider is an external data/rendering service, not a trusted
Desktop plugin. Loading its mutable script in the application document grants
it renderer authority that is broader than the embed requires. A compromised
provider can cross from remote content into Hermes' native capability bridge.

#### Impact

Depending on the preload methods available to the window, malicious script can
interact with gateway/session operations, files, clipboard, terminal,
downloads, settings, and other native capabilities. It can read renderer state
and exfiltrate conversation or profile data reachable from the Desktop app.
Node integration being disabled does not remove access to the explicit preload
bridge.

#### Existing controls

Electron sandboxing, context isolation, and disabled Node integration reduce
direct Node/Electron access. They do not isolate third-party JavaScript from the
application's own renderer APIs.

#### Required security property

No remotely hosted script may execute in a renderer document that owns Hermes
preload capabilities. The fixed release must degrade to an inert link/preview.
Any later interactive embed must use separately owned guest content without the
bridge, must not inherit trusted-main-frame IPC identity, and must receive no
media or other privileged Electron permissions.

---

### SEC-AUDIT-004: Mutable and unverified managed runtime artifacts

**Severity:** Medium  
**Confidence:** High  
**Affected deployment:** Fresh installation, runtime repair, optional-feature
setup, extension installation/update, browser/Desktop build, Docker build, and
Hermes self-update paths on supported platforms  
**Primary files:**

- `setup-hermes.sh`, uv installation block
- `scripts/install.sh`, managed uv and POSIX Node installation
- `scripts/install.ps1`, uv source/salvage ladder and portable/winget Node
  installation, plus `Update-ManagedNpm`
- `scripts/lib/node-bootstrap.sh`, POSIX Node installation and npm repair
- `hermes_cli/managed_uv.py`, uv bootstrap and self-update
- `hermes_constants.py`, `_heal_managed_node_windows`
- `hermes_cli/npm_engine.py`, `upgrade_managed_npm`
- `nix/nixosModules.nix`, first-boot NodeSource and uv provisioning
- `scripts/install.sh` and `scripts/install.ps1`, cua-driver installation
- `hermes_cli/tools_config.py`, `install_cua_driver`
- `tools/computer_use/cua_backend.py`, automatic runtime-contract repair
- `hermes_cli/update_cmd.py`, branch ZIP fallback and dependency repair
- `apps/bootstrap-installer/` and
  `apps/desktop/electron/bootstrap-runner.ts`, installer resolution
- `hermes_cli/managed_uv.py`, managed Python runtime selection/repair
- `scripts/install_psutil_android.py` and `hermes_cli/psutil_android.py`
- `agent/secret_sources/bitwarden.py`,
  `agent/proxy_sources/iron_proxy.py`, and `tools/tirith_security.py`
- `tools/browser_use_cli.py`, `tools/browser_tool.py`, and browser setup paths
- `apps/desktop/scripts/run-electron-builder.mjs` and native dependency staging
- `tools/lazy_deps.py` and optional setup/plugin dependency installers
- `hermes_cli/plugins_cmd.py`, `hermes_cli/skills_hub.py`,
  `tools/skills_hub.py`, and `hermes_cli/profile_distribution.py`
- `hermes_cli/mcp_catalog.py` and `optional-mcps/n8n/manifest.yaml`
- `Dockerfile`, base image, apt closure, and Playwright browser installation

#### Current behavior

Multiple production paths independently download or update executable content:

- `setup-hermes.sh` and `scripts/install.sh` download the current
  `https://astral.sh/uv/install.sh` and execute it.
- `hermes_cli/managed_uv.py` downloads the POSIX or PowerShell uv installer and
  also invokes `uv self update`.
- `scripts/install.ps1` falls back from the mutable astral installer to a
  mutable GitHub `releases/latest` installer, then can copy an arbitrary
  existing `uv.exe` from `PATH` or `~/.local/bin` into the managed location.
- `nix/nixosModules.nix` downloads and executes the mutable uv installer on
  first boot. It also downloads the current NodeSource signing key, adds the
  mutable `node_22.x` apt repository, and installs Node/npm through apt.
- `scripts/install.sh`, `scripts/install.ps1`,
  `scripts/lib/node-bootstrap.sh`, and
  `hermes_constants._heal_managed_node_windows()` resolve a mutable
  `latest-v<major>.x` Node archive.
- When direct Node installation fails, PowerShell can invoke an unversioned
  Winget install, while the POSIX bootstrap can automatically install through
  fnm, proto, nvm, Termux pkg, or Homebrew. These package-manager paths have a
  different trust owner and are not repository-digest-verified artifacts. The
  NixOS module's NodeSource apt provisioning has the same external-manager
  trust distinction, but its downloaded repository key is still a
  Hermes-owned bootstrap input that must be pinned or removed.
- `scripts/lib/node-bootstrap.sh`, `scripts/install.ps1::Update-ManagedNpm`,
  and `hermes_cli/npm_engine.py` install npm from a mutable semver range into
  the managed Node tree.
- Fresh installers, `hermes computer-use install`, and automatic computer-use
  runtime repair download and execute cua-driver installer scripts from the
  mutable `trycua/cua` `main` branch. Pinning the downstream driver version
  does not authenticate the installer code itself.
- Official one-line installers execute mutable Hermes install scripts. Git
  installs and updates intentionally follow a configured branch, while the
  Windows ZIP fallback and some bootstrap-installer fallbacks download a
  mutable branch archive/script without a signed release identity.
- Managed Python setup and repair let uv choose current
  python-build-standalone catalog builds. Android psutil installs a fixed sdist
  URL but does not verify a repository-pinned archive digest before its build
  backend executes.
- PortableGit, Bitwarden `bws`, iron-proxy, and Tirith auto-install into
  Hermes-managed paths with different combinations of mutable release
  selection, same-channel checksums, optional provenance, or unpinned signer
  material.
- Browser Use, Agent Browser, and Camofox can resolve bare package names or
  semver ranges through `uvx`, `npx`, npm, or pip. Chromium, Electron, Electron
  headers, and native bindings can be downloaded by package postinstall/build
  tooling without a repository-owned per-platform artifact digest.
- Core `uv sync --locked` is immutable, but pip fallback tiers, lazy
  dependencies, platform setup hooks, and memory/plugin dependency installers
  can resolve bare names, ranges, upgrades, or unhashed wheel/sdist URLs.
- Plugin, Desktop-plugin, skill, and profile-distribution installers can clone
  or update mutable branch heads before publishing executable code into Hermes
  paths. Several surfaces record the content hash only after download instead
  of checking a reviewed expected identity.
- The pinned n8n MCP checkout installs unhashed ranged Python requirements,
  leaving its executable transitive dependency graph mutable.
- Published Docker builds use mutable Debian tags, unsnapshotted apt packages,
  and Playwright browser payloads whose final executable closure is not fully
  represented by repository-pinned digests.

These paths use HTTPS, Git object IDs, lockfiles, or package-manager integrity
where available, but the resulting executable closure is not consistently tied
to an identity reviewed before installation. Some are intentional first-party
branch or operator-managed trust boundaries; others publish mutable content as
Hermes-managed code.

#### Attacker prerequisites

An attacker must compromise an upstream release account, distribution endpoint,
CDN, trusted proxy, or local trusted CA/TLS interception point. This is less
likely than ordinary application input attacks, but the resulting code runs
with installer or Hermes-user privileges.

#### Existing controls

The downloads use HTTPS. The Windows Node replacement paths are staging-first
and preserve the old tree on many failures. The POSIX shell paths currently
remove the live managed Node tree before moving the extracted replacement, so
they do not provide the same transactional guarantee. None of these controls
provides immutable artifact identity.

Hermes already contains stronger precedent: core Python dependencies use a lock,
some release paths use exact commit IDs, and the Tirith installer verifies
SHA-256 checksums with optional Sigstore provenance. Tirith still resolves
`latest` and can trust same-release checksum material, so it is partial
precedent rather than completion of the repository-reviewed identity property.

#### Impact

A compromised installer, package, release archive, browser payload, extension,
container input, or build backend can execute arbitrary code during setup,
repair, update, Desktop/browser launch, plugin/skill activation, Docker runtime,
or optional-feature use. It runs with the privileges of the installer, Hermes
process, Desktop renderer, or published container.

#### Required security property

Every Hermes-managed direct installer, bootstrap, repair, self-update, package
graph, browser/Desktop payload, extension distribution, MCP bootstrap, and
published container input identified above must resolve through an immutable
identity reviewed before execution or publication. That identity must chain to
a pre-established trust anchor not supplied by the same mutable channel as the
artifact and verification metadata. Verification must happen before execution,
extraction, import, or activation, and valid but expired, revoked, or replayed
downgrade manifests must be rejected.

First-party branch-following Git updates and explicit external
package/version-manager choices may remain separate documented trust
boundaries. They must record the resolved identity, must not masquerade as
manifest-verified artifacts, and must not activate automatically as a fallback
after managed verification fails.

## Items requiring validation

These concerns have concrete source evidence but do not yet have a proven
security-boundary crossing. They must not be represented as confirmed
vulnerabilities until the validation work succeeds.

### MCP tool descriptions as a prompt-injection control channel

Remote MCP servers control tool names and descriptions that are placed in the
model-visible tool schema. Result bodies are marked as untrusted, but
descriptions remain influential before tool selection. A malicious description
could ask the model to read local data with another tool and send it back as MCP
arguments.

This is probabilistic model behavior, not a deterministic containment escape.
Validate it with a fake MCP server and synthetic canary secrets inside a
whole-process sandbox. Test several supported models and both default and
untrusted MCP modes. Record whether a cross-tool exfiltration occurs without
explicit operator intent.

### Electron media permissions are not visibly tied to one renderer identity

The global media permission handler grants microphone/video capture based on
permission type but does not visibly bind the grant to an exact app
`webContents`, top-level origin, and requesting frame. Normal preview content
uses a separate session and no confirmed external request path was established.

Validate packaged builds with a hostile iframe and preview webview requesting
`getUserMedia()`. If any non-app renderer receives a grant, restrict the
handler by exact renderer identity, app origin, and frame origin.

### Profile-home fallback warns instead of failing closed

`get_hermes_home()` can warn and fall back to the default home when a
non-default profile is active without a propagated `HERMES_HOME`. No crossover
was reproduced during this audit.

Stress concurrent multiplexed sessions while deliberately dropping profile
context at thread and subprocess boundaries. Place canaries in credentials,
session storage, logs, MCP state, cron state, and plugin state. A secondary
profile must never read or write the default profile's canary.

## Information-exposure inventory

The following are high-value surfaces even when they operate as designed:

- `state.db` stores full prompts, responses, tool results, cost/routing
  metadata, and session lineage.
- `agent.log`, `errors.log`, `gateway.log`, and Desktop logs can contain session
  identifiers, paths, failures, request metadata, and activity summaries.
  Redaction is enabled by default but is intentionally disableable.
- backups and update receipts contain profile state, file names, version
  information, and operational history.
- attachments and generated artifacts may contain user or model-supplied
  sensitive data.
- the Desktop preload exposes narrow but powerful file, clipboard, terminal,
  gateway, download, and native-window capabilities.
- local MCP clients can read conversations, send messages, and act on approvals
  according to the local OS-account trust boundary.
- custom provider URLs and enabled platform adapters send data to
  operator-selected third parties.
- installed plugins and skills run with full agent-process privilege by design.

These surfaces should be included in authorization and regression testing when
any shared credential, profile routing, or local IPC behavior changes.

## Positive controls observed

The audit found several controls that should be preserved:

- non-loopback dashboard binds activate an explicit authentication gate;
- generic webhook paths use HMAC-based authentication;
- the OpenAI-compatible API server refuses weak or missing API credentials;
- profile-sensitive paths generally use `get_hermes_home()`;
- multiple archive, plugin, media, and file routes perform containment or
  sensitive-file checks;
- Desktop hidden link windows use sandboxing, context isolation, disabled Node
  integration, muted audio, and download cancellation;
- `build_subprocess_env()` centralizes profile propagation and credential
  scrubbing for subprocesses that use it;
- Windows managed-Node replacement uses staging and rollback rather than
  replacing live files in place;
- logs use a redacting formatter by default;
- whole-process Docker/OpenShell isolation is documented for untrusted input
  surfaces.

## Worst credible attack chains

### Shared-host dashboard compromise

Another local user fetches the unauthenticated SPA, extracts the session token,
reveals credentials, accesses transcripts, and invokes privileged tools as the
Hermes service account.

### LSP supply-chain compromise

A compromised mutable LSP package is installed on first file edit, its
lifecycle script inherits Hermes credentials, and the package persists as the
managed language server.

### Desktop private-network request

An authorized sender places an attacker URL in a message. Desktop renders it,
automatically resolves a title or favicon, follows a redirect or page-declared
manifest/icon URL to a private service, and performs a blind request from the
user's machine.

### Desktop social-provider compromise

A social provider's mutable embed script is compromised. Desktop loads it into
the privileged application document, and the script uses renderer state or the
preload bridge to access and exfiltrate Hermes data.

### Runtime supply-chain compromise

An upstream distribution account or trusted transport endpoint is compromised.
Hermes downloads an unverified installer, package graph, browser/Desktop
payload, extension, or container input, executes it, and persists or publishes
the attacker's code.

### Model-mediated MCP exfiltration

A malicious MCP description instructs the model to gather local data through
other tools and submit it as MCP arguments. This chain remains unconfirmed and
must be validated in a sandbox.

## Current operator mitigations

Until code remediation lands:

1. Run Hermes as a dedicated, non-administrator OS user.
2. Do not use the browser dashboard on a shared host unless an external
   authenticated reverse proxy and host firewall isolate it.
3. Set `lsp.install_strategy: manual` and install reviewed language servers
   through the OS or project package manager. Treat any existing `auto` value as
   unsafe until a fixed release requires affirmative consent and uses the
   restricted environment plus immutable package graph.
4. Avoid rendering untrusted bare links in Desktop, or use Desktop in a
   network-restricted environment when processing untrusted messages.
5. Avoid interactive social embeds in Desktop until remote scripts are isolated
   from the privileged renderer.
6. Set `security.allow_lazy_installs: false` in hardened deployments and
   preinstall reviewed optional dependencies.
7. Prefer uv and Node from an operator-selected OS/version manager with its own
   signature policy. A checksum or key downloaded from the same mutable channel
   as an installer is not independent verification.
8. Use whole-process isolation and restricted egress for untrusted web, email,
   messaging, repository, and MCP content. See
   [network-egress-isolation.md](network-egress-isolation.md).
9. Review plugin and skill code, scripts, dependencies, resolved commit, and
   bundle digest before installation or update.

## Audit limitations

- This was a source review, not a live penetration test.
- No production credentials or real third-party accounts were used.
- The review did not prove every supported platform adapter or optional skill.
- Probabilistic model behavior was not treated as a confirmed exploit without a
  reproducible security effect.
- Dependency vulnerability databases and external infrastructure
  configurations were not assessed.
- Line numbers are intentionally omitted from this durable document because the
  source moves quickly; paths and symbols identify the reviewed flows.
