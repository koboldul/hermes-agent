# Security Remediation Plan - 2026-08-25

## Purpose

This plan remediates the verified findings and hardening gaps in
[security-audit-2026-08-25.md](security-audit-2026-08-25.md) and defines
separate validation work for lower-confidence concerns.

The plan follows four repository rules:

1. Preserve prompt caching and do not change toolsets or past context during a
   conversation.
2. Keep capability at existing edges; none of these fixes requires a new model
   tool.
3. Reuse the existing authentication, subprocess-environment, configuration,
   and testing surfaces instead of creating parallel frameworks.
4. Fix the complete class: sibling routes, redirects, subprocesses, profiles,
   and supported platforms must receive the same protection.

## Outcomes

The remediation is complete when:

- unauthenticated dashboard assets contain no reusable authorization material;
- browser dashboard sessions require proof of a non-public launch credential or
  configured external authentication;
- LSP installers and servers never receive undeclared Hermes credentials;
- every auto-installed LSP dependency is immutable and reviewable;
- Desktop makes no automatic external request merely because a URL was
  rendered under the secure default; any opt-in is explicit and still subject
  to the main-process destination policy;
- every requested Desktop title or favicon fetch rejects and cannot redirect
  or rebind to non-public network space;
- no remote script executes in a Desktop renderer that owns Hermes preload
  capabilities;
- every Hermes-managed uv, Node, npm, and cua-driver install/update/repair path
  resolves an exact repository-reviewed identity before execution, extraction,
  or publication, while external package-manager installs require explicit
  operator choice;
- regression tests exercise behavior through real boundaries rather than
  reading source text;
- documentation states the remaining trust assumptions and operator migration.

## Priority and sequencing

| Order | Work package | Finding | Priority | Dependency |
| --- | --- | --- | --- | --- |
| 0 | Immediate operator guidance | All | P0 | None |
| 1 | Local dashboard browser authentication | SEC-AUDIT-001 | P0 | Existing dashboard session/ticket auth |
| 2 | LSP install and process hardening | SEC-AUDIT-002 | P0 | Existing subprocess environment builder |
| 3A | Desktop metadata-fetch policy | SEC-AUDIT-003 | P1 | Electron main-process network helper |
| 3B | Desktop remote-script isolation | SEC-AUDIT-005 | P0 | Renderer/embed boundary |
| 4 | Verified runtime artifacts | SEC-AUDIT-004 | P1 | Release-owned artifact manifest |
| 5 | Validate hardening hypotheses | Validation items | P2 | Whole-process test harness |
| 6 | Release evidence and operator migration | All | P0 release gate | Packages 1-5 as applicable |

Packages 1, 2, and 3B are P0 and can proceed in parallel. Package 3A is
independent. Package 4 should land as reviewable subprojects rather than one
repository-wide patch.

## Work package 0: Immediate operator guidance

### Goal

Reduce exposure before fixed releases reach every installation.

### Changes

1. Add a shared-host warning to browser dashboard startup output and clarify
   the assumption in `SECURITY.md`:
   - loopback limits traffic to the host, not to one OS user;
   - the current browser dashboard must be treated as single-user;
   - ordinary loopback mode does not activate the configured provider gate;
   - recommend an authenticated reverse proxy with
     `dashboard.public_url` configured until an explicit auth-on-loopback mode
     exists.
2. Document `lsp.install_strategy: manual` as the temporary secure default for
   credential-bearing deployments.
3. Add a Desktop privacy note that unlabelled links can resolve titles and
   favicons automatically.
4. Add a Desktop warning that interactive social embeds currently load remote
   provider scripts in the privileged renderer.
5. Recommend `security.allow_lazy_installs: false` for hardened deployments
   until every enabled optional feature has a reviewed lock.
6. Link deployment guidance to
   [network-egress-isolation.md](network-egress-isolation.md).
7. Prepare a private maintainer advisory before publishing exploit details in a
   release note. Coordinate public disclosure with fixed releases.

### Acceptance criteria

- The warnings describe the exact affected modes and do not imply that
  loopback is Internet-exposed.
- Guidance does not recommend putting behavioral settings in `.env`.
- Headless Desktop `hermes serve` is not incorrectly identified as mounting the
  browser SPA.

## Work package 1: Local dashboard browser authentication

### Goal

Replace token-in-HTML bootstrap with proof of a launch credential while
preserving browser dashboard, Desktop headless backend, remote OAuth/password
auth, WebSockets, PTY, and multi-profile behavior.

### Recommended design

Use a one-time browser bootstrap code exchanged for a new local opaque session
that integrates with the existing request principal and WebSocket ticket model.
Deliver the bootstrap proof through the invoking user's protected terminal, not
the browser launch URL. URL fragments avoid HTTP logs but still appear in the
`webbrowser.open()` process arguments and can be visible to another OS user.
Do not claim provider-minted OAuth/password cookies already support loopback:
`gated_auth_middleware` is currently a no-op there.

1. At `hermes dashboard` startup, generate:
   - the existing internal service token for trusted non-browser callers;
   - a separate, random, single-use browser bootstrap code.
2. Print the bootstrap code only to the invoking terminal. Do not include it in
   process arguments, URLs, environment variables, logs, telemetry, shell
   history, or static assets.
3. Open the browser with a credential-free URL. The SPA presents a local
   bootstrap-code form unless configured OAuth/password auth is active.
4. Serve the SPA without `_SESSION_TOKEN` or any equivalent reusable
   credential.
5. The user enters the terminal-displayed code into the SPA, which submits it
   once to a narrow bootstrap exchange endpoint.
6. The server stores only a hash of the bootstrap code, applies a short expiry,
   and consumes it atomically. Invalid, expired, and replayed codes fail closed.
7. A successful exchange creates a server-side local session with a separate
   random opaque identifier and returns that identifier only in an `HttpOnly`,
   `SameSite=Strict` cookie. Store only its digest server-side. Apply `Secure`
   whenever HTTPS is active.
8. A local-session middleware validates the cookie, attaches a normalized
   local `Session` principal with provider `local-loopback`, and never hands
   the opaque identifier to route handlers or the renderer.
9. Bind a separate anti-CSRF token to the local session. Return it only in an
    authenticated same-origin response, keep it in renderer memory, and require
    it in a custom header on every unsafe cookie-authenticated request.
10. Browser WebSockets and PTY obtain one-time tickets through the existing
    `/api/auth/ws-ticket` behavior after the local principal is attached. Do not
    place a long-lived session credential in a WebSocket URL.
11. Keep the seeded `HERMES_DASHBOARD_SESSION_TOKEN` path for the Desktop
    parent-to-child service boundary. `hermes serve` remains headless and never
    exposes that token through an SPA.
12. Explicit OAuth/password deployments continue using their current gate. The
    bootstrap exchange must not downgrade or bypass configured external auth.
13. A service-managed or non-interactive browser dashboard with no protected
    terminal must require a configured provider or refuse to mount the
    privileged SPA. It must not fall back to putting the code in a URL.

### Server implementation

1. Add a small local-browser auth module owned by the dashboard server:
   - digest;
   - creation and expiry timestamps;
   - atomic bootstrap consumption;
   - opaque local-session digest and expiry;
   - per-session anti-CSRF token digest;
   - constant-time comparison;
   - attempt counter/rate limit.
2. Add one public route dedicated to the exchange. The public route permits
   only the bootstrap proof; it grants no direct API access. Restrict it to the
   browser-dashboard loopback mode and disable it for headless `serve`,
   non-loopback binds, and configured external auth.
3. Add a narrow local-session middleware ahead of the legacy token check. It
   validates the dedicated cookie and attaches a normal request `Session`
   principal. Downstream route authorization remains principal-based; do not
   duplicate route allowlists.
4. Update `auth_middleware`, `_require_token`, `/api/auth/me`, and logout to
   recognize or revoke the attached local principal while preserving provider
   sessions and trusted service-token callers.
5. Factor one helper for "browser session auth active" and use it consistently
   in HTTP, `/api/ws`, PTY, console, public/event WebSockets, plugin routes, and
   profile-routed APIs. Existing branches that check only
   `app.state.auth_required` must not silently skip local-session tickets.
6. Reuse the existing single-use WebSocket ticket store after the local
   principal is attached. Ticket validation must accept the local provider
   identity without enabling provider-cookie verification on ordinary loopback.
7. Add one CSRF owner for all cookie-authenticated dashboard requests, including
   local and provider sessions:
   - unsafe HTTP methods require a matching `X-Hermes-CSRF-Token`;
   - require an exact scheme/host/port `Origin` match, not "any localhost";
   - issue/refresh the token through an authenticated exact-origin endpoint;
   - service-header and non-browser bearer callers remain on their explicit
     credential path and are not made to emulate browser CSRF state.
8. Tighten credentialed CORS to the exact dashboard origin. `localhost:3000`
   and `localhost:9119` are different origins even though cookies consider them
   the same site.
9. Apply exact Origin checks to browser WebSocket upgrades in addition to the
   single-use ticket. A hostile page on another localhost port must not use a
   victim's cookie to mint or consume a socket ticket.
10. Make `_serve_index()` inject only non-secret feature flags and base-path
   configuration.
11. Ensure every current header-token route remains protected when called
   without a valid header, cookie, bearer token, or configured external auth.
12. Bind browser sessions to the running server instance. Restarting the server
   invalidates them.
13. Audit `_PUBLIC_API_PATHS` after adding the exchange route. Public health and
   metadata endpoints must not expose secrets, session bodies, profile paths,
   or authorization material.

### Browser implementation

1. Replace reads of `window.__HERMES_SESSION_TOKEN__` in the dashboard frontend
   with a bootstrap/session state machine:
   - no local session: show the bootstrap-code form;
   - exchange pending: block privileged requests;
   - exchange success: use cookie-authenticated requests;
   - exchange failure: clear the form and show a bounded retry/relaunch path.
2. Set fetch credentials deliberately for same-origin requests.
3. Fetch the anti-CSRF token after authentication and keep it in memory. Attach
   it to every unsafe request through the shared fetch wrapper; do not let
   individual routes opt out.
4. Never store the bootstrap code, session identifier, or anti-CSRF token in
   localStorage, sessionStorage, logs, analytics, or error telemetry.
5. Ensure reverse-proxy base paths preserve cookie paths and exact external
   origin calculation.

### Regression tests

Add behavior tests under `tests/hermes_cli/` using the real FastAPI middleware
and SPA mount:

1. `GET /` succeeds but contains no `_SESSION_TOKEN`, seeded token, bearer
   token, or bootstrap digest.
2. The URL passed to `webbrowser.open()` contains no bootstrap or session
   credential, and no secret appears in child process arguments or environment.
3. An unauthenticated caller cannot access:
   - `/api/env/reveal`;
   - session/message APIs;
   - file or terminal APIs;
   - WebSocket and PTY ticket endpoints.
4. A valid bootstrap code creates a session once.
5. An invalid, expired, or replayed bootstrap code returns an authorization
   failure and creates no session.
6. Concurrent exchanges with the same code produce exactly one success.
7. A bootstrap session can obtain a one-time WebSocket ticket and connect.
8. A ticket cannot be replayed.
9. Configured OAuth/password auth cannot be bypassed with the local bootstrap
   route.
10. The Desktop seeded-token/headless path continues to authenticate.
11. A multiplexed dashboard cannot access another profile without the same
    profile-routing checks applied before this change.
12. Prefix-mounted dashboards set the correct cookie path and route URLs.
13. `/api/auth/me` reports the local principal without returning the opaque
    session identifier.
14. Logout revokes the server-side local session and clears the dedicated
    cookie.
15. Local browser tickets work on every supported WebSocket surface, while an
    unauthenticated socket cannot fall back to the legacy query token.
16. Non-interactive startup without a configured provider fails closed instead
    of emitting a launch credential through a URL or log.
17. A malicious page on another localhost/127.0.0.1 port cannot:
    - submit an unsafe cookie-authenticated request;
    - read or mint a CSRF token;
    - mint a WebSocket ticket;
    - connect to any browser WebSocket surface.
18. Missing, incorrect, expired, and cross-session CSRF tokens fail closed.
19. Exact same-origin browser requests work through direct loopback and
    configured reverse-proxy base paths.

Run the targeted Python tests through `scripts/run_tests.sh`; do not call
pytest directly.

### Compatibility and migration

- Existing browser tabs lose their in-memory token after upgrade and should
  display a relaunch instruction rather than repeatedly returning 401.
- Trusted service callers that use the seeded header token remain compatible.
- Do not retain token-in-HTML as a compatibility fallback. That fallback would
  preserve the vulnerability.
- If a release must stage the frontend and backend separately, gate the new SPA
  on a server capability response and ship both artifacts in one release.

### Acceptance criteria

- A process that knows only the loopback port cannot derive an API credential
  from any unauthenticated response.
- Capturing static HTML and JavaScript assets reveals no reusable secret.
- Bootstrap proof is single-use, short-lived, server-instance scoped, and
  absent from server logs.
- Every unsafe cookie-authenticated request requires an exact-origin match and
  a session-bound anti-CSRF token.
- `/api/env/reveal` is reachable only through an authenticated principal.
- Browser, Desktop headless, reverse-proxy, WebSocket, PTY, and multi-profile
  paths pass their behavioral regression tests.

### Rollback rule

If the cookie/bootstrap path fails in production, rollback the release. Do not
restore token injection. A temporary safe fallback is to disable the browser
SPA or place it behind an authenticated reverse proxy with
`dashboard.public_url` configured so the existing provider gate engages.

## Work package 2: LSP install and process hardening

### Goal

Make language servers follow the same credential-scoping contract as other
lower-trust subprocesses and make automatic installations immutable.

### Configuration decision

Change the default `lsp.install_strategy` from `auto` to `manual`.

- Existing users who explicitly selected `auto` keep that opt-in.
- Users with no explicit value stop downloading packages on first use.
- This is a default change, not a config shape migration; do not bump
  `_config_version` unless persisted user config must be transformed.
- Auto-install remains supported only after the integrity and environment work
  below lands.

### Reuse the canonical subprocess environment

1. Replace inherited environments in all LSP process paths:
   - npm installation;
   - Go installation;
   - pip installation if retained;
   - language-server spawn;
   - helper/version probes that execute managed LSP binaries.
2. Use `tools.environments.local.build_subprocess_env()` rather than creating a
   second secret list.
3. If importing that helper from `agent.lsp` creates a proven dependency cycle,
   extract the existing builder and scrub owner into a dependency-neutral
   module, then update every existing caller. Do not copy the function.
4. Preserve explicit environment overrides only after they pass the canonical
   blocklist/passthrough policy. A caller must not be able to re-add an
   internal secret accidentally through `_env`.
5. Preserve profile-aware `HERMES_HOME`, subprocess HOME behavior, locale,
   PATH, and session-context isolation.

### Immutable package manifest

Create a repository-owned LSP runtime manifest. Each recipe records:

- server identifier;
- package ecosystem;
- exact top-level version;
- executable name;
- supported platforms and architectures;
- dependency lock location;
- expected integrity metadata;
- whether lifecycle scripts are required, with a written justification;
- last review date.

#### npm servers

1. Use a dedicated, committed lock graph for each independently installed
   server or for a deliberately reviewed bundle.
2. Install with `npm ci` against the committed lock, not
   `npm install <mutable-name>`.
3. Default to `--ignore-scripts`.
4. If one pinned package genuinely requires a lifecycle script:
   - isolate that package in its own lock graph;
   - document the script;
   - execute it only in the sanitized environment;
   - add a test proving the installed server is functional.
5. Reject lock drift, missing integrity values, and unexpected package names.
6. Keep the dependency policy's upper-bound principle for repository package
   manifests; runtime LSP lock graphs should be exact.

#### Go servers

1. Replace `gopls@latest` with an exact reviewed version.
2. Use the sanitized environment for the Go build/install subprocess.
3. Commit a dedicated `go.mod` and `go.sum` for the gopls installer. The module
   graph records the exact reviewed top-level and transitive versions and sums.
4. Build/install from that module with `GOWORK=off` and `-mod=readonly`, without
   an `@latest` or other version suffix that bypasses the committed graph.
5. Use the Go checksum database or a repository-controlled module proxy to
   verify downloaded modules against the committed sums.
6. Fail closed on graph drift, missing sums, unlisted modules, or attempts to
   update `go.mod`/`go.sum` during installation.

#### pip servers

No current recipe should silently gain mutable pip behavior. If pip-based
servers remain supported, require exact versions and hash-checked requirements.

### Managed binary resolution

1. Auto-installed mode must launch the executable from the verified managed
   directory, not a later `PATH` match.
2. A pre-remediation managed tree under `HERMES_HOME/lsp` has no trustworthy
   manifest marker. Both `manual` and `auto` modes must refuse to execute it
   until Hermes reinstalls it from the locked manifest or the operator
   explicitly re-approves an exact path and digest.
3. Preserve legacy files for recovery, but move or ignore them as unverified;
   do not silently delete user state and do not let `_existing_binary()` treat
   mere existence as verification.
4. Manual mode may use `PATH` because the operator explicitly owns that trust
   decision. It must not prefer an unmarked legacy managed binary ahead of
   `PATH`.
5. Record the resolved path and package version in diagnostic output without
   printing environment values.
6. Reject a managed executable whose lock/installation marker does not match
   the current manifest.

### Regression tests

Extend `tests/agent/lsp/` with runtime behavior tests:

1. Put canary variables matching provider keys, gateway tokens, dashboard
   tokens, relay secrets, and profile/session internals into `os.environ`.
2. Replace npm/go with a fake executable that records its received environment.
   Assert every canary is absent.
3. Mark one benign variable as an explicit allowed passthrough and assert that
   it remains available.
4. Spawn the existing mock LSP server and have it report its environment.
   Assert canaries are absent and the correct profile home is present.
5. Assert installer overrides cannot re-add an internal secret.
6. Assert `auto` refuses an unpinned recipe, unknown package, lock mismatch,
   checksum mismatch, and unexpected lifecycle-script requirement.
7. Assert `manual` performs no network or package-manager call.
8. Assert a pinned offline fixture installs and starts successfully.
9. Assert concurrent first use cannot race two installers into a partial tree.
10. Assert failed installation leaves no executable marked as verified.
11. Assert changing the default to `manual` does not execute an existing
    unmarked binary in `HERMES_HOME/lsp/bin`.
12. Assert an explicitly re-approved legacy binary is bound to its exact digest
    and is rejected after mutation.
13. Assert the gopls install runs with `GOWORK=off`, `-mod=readonly`, and fails
    when a transitive module version or sum differs from the committed graph.

Tests must execute functions and subprocess boundaries. Do not add tests that
read Python source or regex installer commands.

### Operator UX

1. `hermes lsp status` should show:
   - manual or auto strategy;
   - managed or PATH source;
   - installed and expected versions;
   - integrity state;
   - a remediation command when unavailable.
2. Enabling auto-install should explain that Hermes will install the pinned
   reviewed LSP bundle.
3. Installation failures must identify version, package, and verification stage
   without logging credentials or the full environment.

### Acceptance criteria

- Installer and language-server children receive no undeclared Hermes
  credential canaries.
- Every auto-installed package and transitive dependency is represented by a
  committed immutable lock graph.
- Default installs do not contact a package registry during ordinary file
  editing.
- `manual` remains usable with operator-installed servers.
- LSP diagnostics still work for each currently supported language family.

### Rollback rule

If a pinned auto-install recipe is broken, disable that recipe or require
manual installation. Do not restore mutable package names or a secret-bearing
environment.

## Work package 3A: Desktop metadata-fetch policy

### Goal

Preserve useful link titles and favicons without automatic privacy leakage or
access to local/private network targets.

### Product behavior

Change title resolution from render-triggered to user-triggered:

1. Bare links render immediately with the existing host/path or slug fallback.
   Remote favicons render as the existing local monogram/brand fallback.
2. A clear accessible action requests the title.
3. A successful public title can remain in the in-memory cache.
4. Authored Markdown labels continue to suppress title lookup.
5. A user setting may explicitly opt into automatic public-title resolution.
   This is a documented privacy tradeoff, disabled by default; the secure
   main-process destination policy applies in every mode.
6. Apply the same default to remote favicon discovery. A local bundled brand
   icon needs no network request; public page/manifest/icon discovery does.
7. Do not add a user-facing environment variable. Persist a Desktop/app setting
   through the existing settings surface if opt-in behavior is retained.

This keeps the feature while making network disclosure an explicit user choice
by default.

### Main-process enforcement

Create a focused module such as
`apps/desktop/electron/link-title-policy.ts`. It should expose pure,
dependency-injectable functions for URL parsing, address classification,
redirect policy, and request execution. Give it a capability-neutral name if
both title and favicon resolution consume it.

The main process, not the renderer, is authoritative:

1. Accept only `http:` and `https:`.
2. Reject URLs containing userinfo.
3. Normalize internationalized host names and ports before policy checks.
4. Resolve DNS in the main process.
5. Reject a host when any selected connection address is:
   - unspecified;
   - loopback;
   - private/RFC1918;
   - carrier-grade NAT;
   - link-local;
   - multicast;
   - reserved/documentation/benchmark space;
   - IPv4-mapped IPv6 that maps to a blocked IPv4 range;
   - IPv6 unique-local, link-local, multicast, loopback, or unspecified space.
6. Explicitly cover common metadata destinations, including link-local metadata
   addresses and internal metadata host names.
7. Pin the actual connection to the validated address while retaining the
   original host name for TLS SNI and the HTTP Host header. A DNS check followed
   by an unpinned hostname request is vulnerable to rebinding.
8. Disable automatic redirect following. Resolve a relative `Location`, then
   repeat the full parse, DNS, address, and pinning checks for each hop.
9. Keep strict limits for redirects, connect time, total time, response bytes,
   and concurrent jobs.
10. Accept only a title response; never expose response bodies, headers, or
    internal error details to the renderer.
11. Route `hermes:fetchLinkTitle` and `hermes:resolveFavicon` through this same
    policy. Favicon page HTML, manifest URLs, redirects, and candidate image
    URLs must each receive a fresh parse, resolution, blocked-range check, and
    pinned connection.
12. Revalidate each IPC sender against the registered set of trusted app
    renderers before doing network work. Hermes supports primary, secondary
    session, full instance, and HUD chat windows; authorize those explicit
    `webContents` identities and deny hidden-title, preview, quick-entry, guest,
    and stale/destroyed renderers unless a specific feature requires them.

Use Node/Electron primitives where possible. Do not add a dependency solely for
address classification unless the built-in implementation cannot be made
correct and testable.

### Remove the unsafe fallback

Remove the automatic JavaScript-enabled hidden BrowserWindow fallback from
title resolution.

If JavaScript-rendered titles remain a product requirement, make that a second,
explicit user action in a visible preview surface. Do not silently execute an
attacker page in a hidden renderer merely to improve a label.

### Renderer changes

1. `PrettyLink` must not call `useLinkTitle()` during default render.
2. Update the Artifacts page and every direct `useLinkTitle()` caller; fixing
   only transcript links leaves the same bug class elsewhere.
3. Update every `resolveFavicon` caller so public favicon discovery follows the
   same explicit/opt-in behavior. Retain local bundled brand icons and
   monograms without network access.
4. Retain the renderer's obvious-scheme/localhost filter as a fast UX check,
   but do not treat it as security enforcement.
5. Distinguish blocked, unavailable, loading, and resolved states without
   exposing internal IP details.
6. Keep keyboard and screen-reader activation behavior equivalent to pointer
   activation.

### Regression tests

Add pure main-process tests covering:

- literal IPv4 and IPv6 loopback;
- decimal, hexadecimal, and IPv4-mapped forms after parser normalization;
- RFC1918, carrier-grade NAT, link-local, multicast, reserved, and metadata
  ranges;
- public DNS returning a private address;
- mixed public/private DNS answers;
- a public first hop redirecting to localhost or a private address;
- relative redirects;
- redirect loops and redirect-budget exhaustion;
- DNS answers changing between validation and connection;
- non-HTTP schemes and URLs with credentials;
- valid public IPv4 and IPv6 destinations;
- pinned connection behavior preserving TLS host identity;
- timeout and response-byte limits;
- title/favicon requests from primary, secondary session, full instance, and
  HUD chat windows;
- denial from hidden-title, preview, quick-entry, stale/destroyed, and guest
  `webContents`.
- a public page declaring a private manifest URL;
- a public manifest declaring a private icon URL;
- private DNS, redirects, and rebinding at page, manifest, and image steps.

Extend renderer tests to prove:

1. Rendering a bare link does not call `fetchLinkTitle`.
2. Explicit activation calls it once.
3. Authored labels never fetch.
4. A blocked result leaves the safe fallback label.
5. Cache and in-flight deduplication still work after explicit activation.
6. Rendering a remote favicon candidate performs no network request by default.
7. Explicit favicon resolution returns only a validated data URL or the local
   fallback.

Run targeted tests from `apps/desktop` with the existing Vitest command. Run
the Desktop typecheck because the preload interface changes.

### Acceptance criteria

- Rendering attacker-controlled text causes zero external title requests by
  default.
- No title, page, manifest, icon, or redirect request can connect to a blocked
  address.
- DNS rebinding cannot change the validated destination.
- The main process enforces the policy even when the renderer passes a URL
  directly over IPC.
- The hidden JavaScript title window is absent from the automatic path.
- Public explicit title and favicon resolution retain timeout, byte,
  concurrency, type-sniffing, and caching limits.

### Rollback rule

If safe title resolution fails for a site, show the existing fallback label.
Do not bypass address validation or restore hidden automatic rendering.

## Work package 3B: Desktop remote-script isolation

### Goal

Prevent mutable third-party social JavaScript from executing in any Desktop
renderer that has access to `window.hermesDesktop`.

### Implementation

1. Remove same-document dynamic script injection from
   `social-embed.tsx`. Do not add the provider origins to the application
   renderer's `script-src`.
2. Prefer inert provider links, locally rendered metadata, or server-produced
   thumbnails when an interactive embed is not essential.
3. When an interactive social embed is retained, place it in a separately
   sandboxed cross-origin frame or guest partition:
   - no Hermes preload;
   - no `window.hermesDesktop`;
   - no Node integration;
   - context isolation and sandboxing enabled;
   - minimal `sandbox` permissions;
   - no same-origin privilege unless the provider requires it and the risk is
     explicitly accepted;
   - navigation and popup requests intercepted by the trusted parent.
4. Define a narrow `postMessage` protocol for size/readiness events if needed.
   Validate exact sender window, origin, message type, and payload. Do not
   proxy arbitrary native capabilities through the parent.
5. Enforce a Desktop Content Security Policy that keeps the privileged
   renderer's scripts self-hosted. A production CSP violation must fail visibly
   in development/CI rather than silently relaxing policy.
6. Sweep every Desktop window type and plugin surface for remote `<script>`
   insertion. Runtime plugins are separately operator-trusted code; social
   providers and arbitrary embeds are not promoted into that trust class.

### Regression tests

1. Rendering Instagram, TikTok, and Twitter content appends no remote script to
   the privileged application document.
2. The embed frame/guest has no `hermesDesktop` bridge and cannot invoke preload
   IPC.
3. A hostile embed `postMessage` from the wrong origin/window is ignored.
4. Provider navigation, popup, download, permission, and protocol requests are
   denied or handed to an explicit trusted-parent policy.
5. CSP blocks an injected external script in primary, secondary, instance, and
   HUD chat windows.
6. Static links and safe fallback previews still render when provider scripts
   are unavailable.

### Acceptance criteria

- The privileged renderer executes only packaged/self-hosted application code
  and explicitly trusted runtime plugins.
- Social provider compromise cannot reach `window.hermesDesktop`, renderer
  stores, or the application DOM.
- Removing or blocking a social provider degrades to inert content rather than
  weakening the renderer boundary.

### Rollback rule

If a provider embed stops working, disable the interactive embed and render a
link/fallback. Do not restore same-document remote scripts.

## Work package 4: Verified runtime artifacts

### Goal

Give every Hermes-managed direct-download artifact an immutable,
repository-reviewed identity before execution or extraction. Treat
operator-selected OS/version-manager installations as a separate explicit
trust decision rather than an automatic verification fallback.

### Full affected surface

The immutable policy must cover every production path, not only the two
original examples:

- `setup-hermes.sh`;
- `scripts/install.sh`;
- `scripts/install.ps1`, including `Update-ManagedNpm`;
- `scripts/lib/node-bootstrap.sh`;
- `hermes_cli/managed_uv.py`, including bootstrap, repair, and self-update;
- `hermes_constants._heal_managed_node_windows`;
- `hermes_cli/npm_engine.upgrade_managed_npm`;
- `nix/nixosModules.nix`, including first-boot NodeSource and uv provisioning;
- `scripts/install.sh` and `scripts/install.ps1` cua-driver installers;
- `hermes_cli/tools_config.install_cua_driver`;
- `tools/computer_use/cua_backend._maybe_repair_runtime_contract`;
- official shell/PowerShell installer delivery, `hermes_cli/update_cmd.py`,
  `apps/bootstrap-installer/`, and Desktop bootstrap fallback resolution;
- managed Python runtime repair and Android psutil source installation;
- PortableGit, Bitwarden `bws`, iron-proxy, and Tirith auto-installers;
- Browser Use, Agent Browser, Camofox, Playwright/Chromium, Electron, Electron
  headers, and native Desktop binding installers;
- core dependency fallback, lazy dependency, setup-hook, platform, memory, and
  plugin Python package installers;
- plugin, Desktop-plugin, skill, and profile-distribution install/update paths;
- optional MCP bootstrap dependency installation;
- published Docker base images, apt closure, and browser payload installation;
- any sibling installer or updater discovered while implementing the change.

Search installer, updater, repair, lazy dependency, extension, browser/Desktop
payload, container build, and self-update code for mutable executable resolution
before closing the finding.

The sweep must explicitly resolve these compatibility paths:

- the GitHub `releases/latest/download/uv-installer.ps1` fallback;
- copying `uv.exe` from `PATH` or `~/.local/bin` into managed storage;
- Winget Node installation after a portable-download failure;
- fnm, proto, nvm, Termux pkg, and Homebrew Node installation;
- NodeSource key/repository setup and apt Node installation in the NixOS
  module;
- existing system uv/Node binaries used without copying.

Apply this trust split consistently:

1. Hermes-managed storage contains only manifest-verified artifacts.
2. An existing operator-managed executable may be used in place after version
   and capability checks, but it must not be relabelled or copied as
   Hermes-managed unless its digest matches the manifest.
3. Installing through Winget, Homebrew, pkg, fnm, proto, or nvm requires an
   explicit operator choice. It must not run automatically because a
   manifest-verified direct download failed.
4. External managers retain responsibility for their signatures and package
   integrity. Hermes reports their resolved executable and version and does not
   claim repository-level digest verification for them.
5. Enabling the NixOS module is an explicit operator deployment choice, but
   that does not justify downloading an unpinned repository key or mutable uv
   installer during first boot.

### Supply-chain manifests and locks

Add a small repository-owned manifest for bootstrap artifacts. It should contain:

- component name;
- exact version;
- platform and architecture;
- canonical HTTPS URL;
- SHA-256 or stronger digest;
- optional upstream signature/provenance identity;
- update timestamp.

Use ecosystem-native committed locks for transitive package graphs:

- npm package locks with integrity fields;
- Python lock/requirements files with hashes;
- Go `go.mod`/`go.sum`;
- exact Git commit IDs plus whole-bundle digests for extensions;
- image digests and recorded package closures for containers.

The release/update workflow owns changes to this manifest. A manifest update
must be reviewable separately from the code that consumes it. Standalone
install scripts that run before cloning the repository receive generated,
embedded constants from this canonical manifest; CI proves the embedded values
match so there is one source of truth rather than hand-maintained copies.

Do not resolve `latest` during a Hermes-managed installation. A maintenance
command may discover new releases and prepare a manifest diff, but normal
managed installation consumes only committed values.

### uv bootstrap

1. Stop executing mutable `astral.sh/uv/install.sh` and `install.ps1`
   responses in every setup, install, repair, and runtime-bootstrap path.
   Remove the GitHub `releases/latest` installer fallback.
2. Select an exact uv release artifact for the current platform/architecture.
3. Download it to a private temporary directory.
4. Verify its digest against the committed manifest.
5. When upstream provenance/signatures are available, verify them as an
   additional control.
6. Extract only the expected executable and metadata files.
7. Publish the executable atomically into the user installation directory.
8. Replace `uv self update` with a Hermes-owned update that selects a pinned
   manifest release, verifies it, and atomically replaces the managed binary.
   The self-updater must not bypass repository review.
9. If an existing uv is found on `PATH` or in a conventional user directory,
   either use it in place as operator-managed or verify its digest before
   copying it into managed storage.
10. On verification failure:
   - do not execute or publish anything;
   - remove the temporary artifact;
   - print the expected component/version and a non-sensitive failure reason;
   - direct the operator to a verified manual installation path.

Do not require Python to verify uv: uv bootstrap can run before a usable Python
exists because uv may provision Python itself. On POSIX, use an available
pre-Python verifier such as `sha256sum`, `shasum -a 256`, or
`openssl dgst -sha256`, and fail closed with verified-manual-install
instructions if none exists. On Windows, use PowerShell's `Get-FileHash`.
`setup-hermes.sh` may use a repository helper only after proving the helper's
runtime is available before uv installation.

### Managed Node on Windows, Linux, and macOS

1. Replace every `latest-v<major>.x` discovery path with an exact reviewed patch
   version and platform/architecture-specific digests.
2. Construct the exact versioned Node archive URL from the manifest.
3. Download the ZIP or tarball into a sibling staging flow.
4. Verify the archive digest before opening it.
5. Validate archive members before extraction:
   - no absolute paths;
   - no drive-qualified paths;
   - no `..` traversal;
   - no unexpected top-level root;
   - no special files;
   - no hard links unless an exact reviewed archive requires one;
   - permit only expected relative symlinks whose fully resolved targets remain
     inside the validated top-level root. Node's POSIX archives require the
     internal `bin/npm` and `bin/npx` symlinks, so a blanket link ban would
     break the supported runtime.
6. Verify the expected `node` and `npm` executables exist after extraction.
7. Apply the same manifest policy to the POSIX tarball paths in
   `scripts/install.sh` and `scripts/lib/node-bootstrap.sh`.
8. Preserve the current Windows in-use detection, same-volume stage/swap,
   rollback, and stale-staging cleanup behavior.
9. Add equivalent sibling-directory stage, validate, rename, and rollback
   behavior to both POSIX paths. They currently delete the live tree before
   moving the replacement and must become transactional.
10. Keep the old managed tree when download, verification, extraction, or
   validation fails.
11. Remove Winget, fnm, proto, nvm, pkg, and Homebrew as automatic fallbacks
    after a managed-download failure. Offer them only through an explicit
    operator-selected installer path and report that external manager as the
    trust owner.

### Managed npm

1. Replace semver-range runtime upgrades with an exact npm version selected
   from the same reviewed runtime manifest.
2. Lock the package and transitive integrity data used by
   `_nb_ensure_bundled_npm_range()`, PowerShell `Update-ManagedNpm`, and
   `upgrade_managed_npm()`.
3. Use a sanitized subprocess environment and disable lifecycle scripts unless
   an exact reviewed npm release requires them.
4. Record a managed-runtime marker that binds Node version, Node archive digest,
   npm version, and npm integrity state.
5. Preserve a working old npm when verification or upgrade fails; never publish
   a partially upgraded managed tree.

### NixOS first-boot provisioning

1. Replace the module's mutable uv installer with the same exact
   manifest-verified uv artifact used by other managed paths.
2. Prefer a Nix-pinned Node package copied or exposed through a writable runtime
   layout instead of adding NodeSource at first boot.
3. If NodeSource apt remains necessary:
   - pin and verify the repository-key fingerprint before installation;
   - use a snapshot or exact package version rather than an open `node_22.x`
     stream;
   - identify apt/NodeSource as the external trust owner in module
     documentation and startup output;
   - fail closed when key, fingerprint, repository, or package version differs.
4. First boot must not continue with a partially provisioned toolchain after
   verification failure.
5. Keep credentials and profile state out of provisioning command output and
   failure logs.

### cua-driver installation and repair

1. Stop fetching installer scripts from the mutable `trycua/cua` `main`
   branch in POSIX install, PowerShell install, `hermes computer-use install`,
   and automatic runtime-contract repair paths.
2. Prefer a direct, exact cua-driver release artifact recorded in the shared
   manifest. Verify its digest and any upstream signature/provenance before
   installation.
3. If the upstream installer must be retained:
   - pin its raw URL to a full commit SHA;
   - record and verify the installer script digest before execution;
   - set an exact downstream driver version;
   - verify the downloaded driver artifact independently. A pinned version
     environment variable does not authenticate mutable installer code.
4. Use a private temporary file, sanitized subprocess environment, bounded
   timeout, and atomic publication. Do not use `curl | sh`,
   `Invoke-Expression`, or command strings that execute network responses.
5. Route fresh install, explicit install, update, and automatic repair through
   one verified installer implementation. No sibling path may reconstruct the
   upstream one-liner.
6. Preserve a compatible existing driver on verification or repair failure.
   Automatic repair must fail closed and return the original contract state
   rather than running an unverified fallback.
7. Mark the installed driver with installer commit/digest, artifact version,
   artifact digest, platform, and architecture so later repair can verify
   provenance before execution.

### Hermes installer delivery and self-update

1. Publish shell and PowerShell installers as exact release artifacts with
   signatures and committed digests. The recommended one-line install flow must
   retrieve a versioned script and verify it before execution; do not teach
   `curl | sh` or `irm | iex` against a mutable endpoint.
2. Production GUI/bootstrap-installer builds require an exact commit stamp.
   Reject branch/fallback stamps instead of silently producing an installer
   that fetches mutable branch code.
3. Keep Git-checkout updates as a documented first-party trust boundary:
   - fetch the configured remote;
   - resolve and record the exact remote commit before applying;
   - preserve the commit in the update receipt;
   - optionally require signed commits/tags for a hardened release channel.
4. Replace the Windows `refs/heads/<branch>.zip` fallback with a signed,
   exact-release source archive whose digest is in the release manifest.
   Dependency-install failure must never trigger a source-tree replacement.
5. Desktop bootstrap fallback resolution must consume the same exact installer
   identity as the standalone bootstrap installer.
6. Release receipts record installer version/digest, source commit, archive
   digest, and verification result without exposing credentials.

### Managed Python runtimes and Python package graphs

1. Record exact python-build-standalone build IDs, platform/architecture, URLs,
   and digests. `uv python install` and runtime repair may select only those
   entries.
2. Do not refresh uv's catalog and automatically adopt a newer build or patch
   release during repair. A maintainer manifest update is required.
3. Pin and verify the Android psutil sdist before invoking its build backend.
4. Preserve `uv sync --locked` as the core dependency path. Remove pip/uv
   fallback tiers that re-resolve the core graph after locked installation
   fails.
5. Give each lazy feature, platform setup hook, memory provider, and optional
   Python integration a committed hash-checked lock graph. Top-level version
   pins without transitive hashes are insufficient.
6. Disable automatic lazy installation for a feature whose lock is absent or
   stale. Offer a clear setup action after its reviewed lock lands; do not
   silently execute a bare package name, `-U`, ranged requirement, or unhashed
   wheel URL.
7. Prefer wheels. When an sdist/PEP 517 build is required, pin its digest and
   all build-system requirements because the build backend executes code.
8. Repair and update paths consume the same locks as first install.

### Other Hermes-managed binary installers

1. Add PortableGit/MinGit, Bitwarden `bws`, iron-proxy, and Tirith to the
   artifact manifest with exact version, platform/architecture, URL, and
   digest.
2. Verify PortableGit's self-extracting archive before launching it.
3. Treat a checksum or public key downloaded only from the same mutable release
   channel as untrusted metadata. Pin expected signer identity, key
   fingerprint, workflow identity, or artifact digest independently in Hermes.
4. Pin Tirith to an exact release. Keep checksum and Sigstore verification, but
   do not let `latest` plus same-release checksums satisfy the immutable
   identity requirement.
5. Publish binaries atomically and write a provenance marker. Existing
   operator-managed binaries may be used in place but are not copied into
   Hermes-managed storage without verification.

### Browser and Desktop executable payloads

1. Pin Browser Use to an exact Python lock and remove runtime `uvx browser-use`
   network resolution from the secure default.
2. Pin Agent Browser and Camofox to exact npm lock graphs. Remove
   network-resolving `npx` fallbacks and require a valid managed-install marker
   before launch.
3. Record Playwright Chromium/headless-shell, Electron distributions, Electron
   headers, and downloaded native bindings by exact platform/architecture and
   digest.
4. Disable package postinstall as the authority for artifact selection.
   Pre-stage and verify executable payloads, then let the package/build step
   consume only the verified local files.
5. Configurable mirrors may change transport location, not artifact identity.
   The same expected digest and signer policy applies to every mirror.
6. Desktop build/repair can run with network disabled after verified payloads
   are staged. Missing artifacts fail closed instead of downloading an
   unreviewed replacement.

### Plugins, skills, and profile distributions

1. Resolve every remote executable extension to an exact commit/version and
   whole-bundle digest before publishing it into a Hermes execution path.
2. Default-branch discovery may fetch metadata into quarantine, but activation
   requires the resolved commit/digest to be displayed and explicitly accepted.
   Automatic updates require a new reviewed identity.
3. Require integrity for Desktop runtime plugins and dashboard plugin scripts;
   optional integrity fields are insufficient for remotely installed code.
4. Remove live-`main` fallback for official optional skills. Pin the official
   catalog entry and verify the installed bundle.
5. Honor profile-distribution `#ref` syntax, retain the resolved commit in
   provenance metadata, and update from that declared channel rather than
   silently recloning mutable HEAD.
6. Preserve the `SECURITY.md` trust model: pinning proves what was installed;
   it does not sandbox plugins or skills. Operator code review remains required.
7. Keep plugin packs' exact 40-character SHA behavior as the reference
   invariant.

### MCP bootstrap dependencies

1. Replace ranged n8n MCP requirements with a committed hash-checked lock.
2. Make the catalog bootstrap install with `--require-hashes` or the
   ecosystem-equivalent locked mode.
3. Catalog validation rejects package-install bootstrap commands without an
   immutable graph.
4. Keep the MCP Git checkout pinned to its exact commit and record both source
   and dependency-lock identities in the installation marker.

### Published Docker inputs

1. Pin every base image by digest, including Debian build and runtime stages.
2. Use a dated signed Debian snapshot or record and verify the resolved apt
   package closure used in the published image.
3. Install Playwright browsers from the same verified browser-payload manifest
   used outside Docker.
4. Generate an SBOM and provenance attestation containing base digests, apt
   package versions, Python lock, Node/npm identity, and browser payloads.
5. Rebuilding the same release manifest must not silently resolve newer base,
   apt, or browser content.

### Release maintenance

Add a maintainer-only update script that:

1. accepts an explicit component/version/commit for any manifest-managed
   artifact or package graph;
2. downloads upstream checksum/signature material;
3. verifies upstream provenance;
4. computes the repository manifest entries;
5. produces a deterministic diff;
6. never writes the manifest when upstream verification fails.

CI should verify manifest schema, unique platform mappings, canonical HTTPS
hosts, digest format, and that code requests only manifest-listed artifacts.
CI must not turn this into a change-detector for the newest upstream release.

### Regression tests

#### uv

1. A fixture artifact with the expected digest installs.
2. One-byte mutation fails before execution.
3. Missing architecture mapping fails closed.
4. A failed verification leaves no executable and no temporary artifact.
5. The installer never requests a mutable `latest` URL.
6. POSIX shell, PowerShell, runtime repair, and former self-update paths all use
   the same manifest version.
7. Bootstrap succeeds without Python when a supported system hash verifier is
   present, and fails closed when no verifier exists.
8. A `PATH` or `~/.local/bin` uv is never copied into managed storage unless its
   digest matches the manifest.
9. The mutable GitHub `latest` installer is never requested.

#### managed Node

Extend the behavioral tests around `_heal_managed_node_windows`:

1. Matching ZIP digest preserves the current stage/swap success path.
2. Mismatched digest returns failure before extraction.
3. Mismatch leaves the live managed tree untouched.
4. Traversal or unexpected-root entries are rejected.
5. Missing `node.exe` or `npm.cmd` is rejected.
6. Architecture selects the correct manifest entry.
7. In-use deferral performs no download.
8. Rename failure still rolls back.
9. No test patches the interpreter into another host OS; keep Windows runtime
   behavior under `@pytest.mark.windows_only` and pure archive/manifest helpers
   host-independent.
10. POSIX tarball paths select the same exact version as Windows for the target
    release policy.
11. Each POSIX path preserves the old tree when publication fails after a new
    archive has been verified and extracted.
12. Winget, Homebrew, pkg, fnm, proto, and nvm are not invoked without explicit
    operator selection.

#### managed npm

1. Range-only or unlisted versions are rejected.
2. Exact locked npm installs into a staging tree and publishes atomically.
3. Integrity or lifecycle-policy failure preserves the old managed npm.
4. POSIX shell bootstrap, PowerShell `Update-ManagedNpm`, and `npm_engine.py`
   consume the same manifest entry.
5. Each of the three paths rejects range-only, lock-drifted, or unlisted npm
   resolution and preserves the previous working runtime.

#### NixOS module

1. Build and start a module fixture with outbound network denied after image
   construction; pinned uv and Node remain available without first-boot
   installer downloads.
2. If an external apt path is retained, a wrong NodeSource key fingerprint or
   package version fails before package installation.
3. First-boot verification failure does not write the provisioned sentinel.
4. The runtime reports whether Node is Nix-pinned or externally managed without
   logging repository credentials.

#### cua-driver

1. POSIX and PowerShell fixture installers with matching script and artifact
   digests install successfully.
2. A mutated script or driver artifact fails before execution/publication.
3. Fresh install, explicit CLI install, and automatic repair call the same
   verified implementation.
4. Automatic repair performs no request to a mutable branch URL.
5. Verification failure preserves a compatible existing driver and creates no
   trusted installation marker.
6. Installer arguments, environment, and logs contain no credentials.

#### Hermes install and update

1. Versioned shell/PowerShell installer fixtures verify before execution.
2. Production bootstrap builds reject missing/exact-commit fallback stamps.
3. ZIP fallback accepts only a signed manifest archive for the resolved release
   and never downloads `refs/heads/<branch>.zip`.
4. Git branch updates record the fetched remote commit in the update receipt.
5. Desktop and standalone bootstrap installers resolve the same identity.

#### Python runtimes and packages

1. Managed Python install/repair rejects an unlisted build ID or digest.
2. Android psutil mutation fails before its build backend starts.
3. Core locked-install failure does not trigger mutable pip fallback.
4. Each lazy/setup/plugin feature installs offline from its committed
   hash-checked lock and rejects missing or drifted transitives.
5. A missing lock disables automatic installation and produces an actionable
   error rather than resolving a bare package.

#### Other managed binaries

1. PortableGit is not launched before digest verification.
2. bws, iron-proxy, and Tirith reject an artifact whose signer/checksum is not
   rooted in repository-pinned identity.
3. `latest` cannot select a managed binary.
4. Publication failure preserves the old working binary and marker.

#### Browser and Desktop payloads

1. Browser Use, Agent Browser, and Camofox launch only from matching managed
   lock/installation markers; runtime `uvx`/`npx` network resolution is absent.
2. Chromium, Electron, headers, and native bindings reject digest mismatch
   before extraction, rebuild, or staging.
3. Alternate mirrors cannot change the accepted digest.
4. Desktop/package builds succeed with network disabled after verified payload
   staging and fail closed when one payload is absent.

#### Extensions and distributions

1. Plugin, Desktop-plugin, skill, and profile-distribution activation rejects a
   missing commit/version or bundle digest.
2. Mutable-branch discovery remains quarantined until the resolved identity is
   displayed and accepted.
3. Updates require a different explicit reviewed identity and cannot silently
   pull/reclone HEAD.
4. Profile `#ref` is honored and preserved in provenance metadata.
5. Desktop/dashboard runtime integrity is mandatory for remotely installed
   code.

#### MCP bootstrap

1. The n8n MCP installs from its committed hash-checked dependency graph.
2. Catalog validation rejects ranged/unhashed package bootstrap.
3. A transitive mutation fails before the MCP server can execute.

#### Docker

1. Image builds use expected base digests and the declared package snapshot.
2. Base, apt, or browser drift changes the manifest/SBOM and fails a release
   build rather than silently changing the image.
3. The produced image attestation resolves every executable input to its
   recorded identity.

Run Python tests through `scripts/run_tests.sh`. Run Desktop/Node behavior tests
with the existing workspace commands, Nix checks with the repository's existing
Nix tooling, and Docker evidence through the existing image build/test path.

### Acceptance criteria

- No Hermes-managed direct bootstrap, installer, repair, self-update, package
  graph, browser/Desktop payload, extension activation, MCP bootstrap, or
  published-container input uses an unreviewed mutable identity.
- No cua-driver or other managed installer path executes code from a mutable
  branch or unverified network response.
- External package/version managers run only after explicit operator selection
  and are labelled as externally trusted rather than manifest-verified.
- A modified archive is rejected before execution or extraction.
- Verification failure preserves the previous working installation.
- Supported platform/architecture mappings are explicit and complete.
- Updating a pinned version requires a reviewed manifest change.
- First-party branch-following Git updates and explicit external-manager choices
  are visibly labelled, resolve to recorded identities, and never masquerade as
  manifest-verified artifacts.

### Rollback rule

If an upstream artifact or manifest is unavailable, retain the prior pinned
version or require verified manual installation. Do not fall back to `latest`
or skip verification.

## Work package 5: Validate lower-confidence concerns

These investigations must run separately from verified fixes. Promote an item
to a vulnerability only after a reproducible boundary crossing.

### MCP description injection

1. Build a fake MCP server with a benign schema and a description that requests
   cross-tool retrieval of a synthetic canary.
2. Run inside whole-process isolation with no real credentials.
3. Exercise representative supported models under:
   - default trust;
   - `trust: untrusted`;
   - descriptions removed or structurally constrained.
4. Record model calls, tool arguments, and whether the canary reaches MCP.
5. If reproducible:
   - default remote MCP servers to untrusted;
   - label server descriptions as untrusted metadata;
   - constrain description length and control characters;
   - consider an operator-approved trust elevation for descriptions.

Success means either a reproducible exploit with a scoped fix or documented
evidence that the proposed chain did not reproduce under the tested matrix.

### Electron media permission scope

1. Instrument a packaged build.
2. Request media from:
   - every registered trusted app renderer type;
   - a cross-origin iframe;
   - a preview webview;
   - the hidden title partition before its removal.
3. Log requesting `webContents`, top-level URL, frame URL, and permission.
4. If any guest is admitted, bind grants to the explicit registered set of
   trusted app `webContents`, app origin, and frame origin.
5. Add denial tests for every guest surface.

### Profile fail-closed behavior

1. Create default and secondary profiles with distinct canaries.
2. Run concurrent session, cron, MCP, plugin, logging, and subprocess activity.
3. Deliberately omit context propagation at test seams.
4. Assert secondary operations fail rather than using default-profile state.
5. If crossover occurs, make multiplexed profile resolution fail closed while
   preserving the unscoped single-profile path.

## Work package 6: Release, verification, and migration

### Proposed pull-request slices

Keep authoring and review separable:

1. Dashboard backend bootstrap/session exchange and Python tests.
2. Dashboard frontend migration and browser/WebSocket tests.
3. LSP subprocess environment hardening and canary tests.
4. LSP immutable package manifest and default change.
5. Desktop social-embed isolation and CSP.
6. Desktop main-process metadata URL policy and tests.
7. Desktop explicit title/favicon UX and removal of the hidden title fallback.
8. Versioned Hermes installer and exact source-update fallback.
9. uv and managed Python artifact manifest.
10. managed Node/npm, NixOS, and transactional publication.
11. cua-driver and other managed binary installers.
12. browser/Chromium/Electron/native payload manifest.
13. optional Python dependency locks.
14. plugin/skill/profile distribution identities and MCP bootstrap lock.
15. Docker base/package/browser closure and provenance.
16. operator documentation and release migration notes.
17. validation-only harnesses for MCP descriptions, media, and profiles.

Do not combine all security changes into one unreviewable patch.

### Required evidence per pull request

Each implementation PR must include:

- the finding ID it addresses;
- a line-level account of the old vulnerable flow;
- the new enforced invariant;
- targeted behavior tests;
- compatibility impact;
- rollback behavior that does not restore the vulnerability;
- confirmation that logs and error paths contain no secret material.

### Test matrix

| Surface | Minimum evidence |
| --- | --- |
| Dashboard | FastAPI middleware, SPA bootstrap, cookie/session, WebSocket ticket, prefix, headless Desktop, multi-profile |
| LSP | Installer environment canaries, server environment canaries, offline locked install, manual mode, concurrency |
| Desktop | No same-document remote scripts, CSP/embed isolation, renderer no-auto-fetch, title/favicon page/manifest/image matrix, redirects, DNS pinning, preload IPC, typecheck |
| Runtime supply chain | Hermes installer/update, managed uv/Python/Node/npm/cua/binaries, browser/Electron/native payloads, optional Python locks, extensions, MCP bootstrap, NixOS and Docker inputs |
| Profiles | Default and secondary profile canaries under concurrent activity |

Use the smallest targeted existing commands first. Python tests must use
`scripts/run_tests.sh`. Desktop tests use the existing workspace Vitest and
typecheck commands. Escalate to broader suites only when targeted validation
shows shared behavior changed.

### Deployment sequence

1. Publish operator mitigations.
2. Land and release dashboard, LSP, and Desktop remote-script P0 fixes.
3. Rotate dashboard session material on restart by design.
4. Recommend rotation of provider and messaging credentials only when there is
   evidence that an affected shared-host or LSP-compromise scenario occurred.
5. Land Desktop SSRF/privacy and runtime supply-chain integrity fixes.
6. Publish fixed-version notes with exact affected modes.
7. Monitor authentication failures, LSP install failures, blocked metadata
   requests, and artifact verification failures using counts only. Do not log
   secrets, full URLs with sensitive queries, resolved internal addresses, or
   environment contents.

### Final release gate

The remediation program is complete only when:

- every verified finding has a merged fix and a passing behavior regression;
- the shipped artifacts contain the fixed source and rebuilt Desktop/frontend
  bundles;
- no compatibility fallback restores token disclosure, mutable package
  resolution, unsafe redirects, hidden automatic rendering, or unverified
  execution;
- user-facing security and migration documentation matches runtime behavior;
- shared-host dashboard, LSP auto-install, Desktop social/embed and
  title/favicon behavior, and every audited managed runtime/dependency/update
  path have been verified end to end on supported platforms;
- lower-confidence items have evidence and an explicit disposition.
