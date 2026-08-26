#!/usr/bin/env python3
"""CI gate for the supply-chain manifest, ledger, and mutable-fetch surface.

Three checks, all *behavioral* (they exercise the real loaders and the real
source tree, never assert on formatted source text):

1. **Manifest** — structurally valid; canonical HTTPS hosts only; unique
   platform/arch per component; exact-semver + an anchor (digest or provenance)
   for every ``release_verified`` artifact; a blocker + operator guidance on
   every unanchored ``transport_trusted`` artifact; monotonic sequence; not
   expired; the pinned Hermes release signer identity.
2. **Ledger** — structurally valid; every ``source`` and ``negative_test`` file
   exists; every referenced component exists in the manifest; pending entries
   carry a blocker.
3. **Mutable-fetch scan** — production installer code is scanned for high-signal
   mutable executable/metadata fetches (astral.sh installer, releases/latest,
   nodejs latest-vNN.x, raw main-branch, refs/heads zip, uv self update). Every
   hit's file must appear in the ledger; an unclassified hit fails CI.

Scope note: apps/ (Desktop, Rust bootstrap), agent/lsp/, and web/ are owned by
other work packages and are excluded from the enforcing scan here.

Run: ``python scripts/ci/check_supply_chain.py`` (exit 0 clean, 1 on any
finding). CI must not turn this into a change-detector for the newest upstream
release — it never asserts a specific version/digest value, only relationships.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from hermes_cli.supply_chain.errors import ManifestError  # noqa: E402
from hermes_cli.supply_chain.ledger import Ledger, load_ledger  # noqa: E402
from hermes_cli.supply_chain.manifest import (  # noqa: E402
    CANONICAL_HOSTS,
    TRUST_RELEASE_VERIFIED,
    TRUST_TRANSPORT_TRUSTED,
    ReleaseManifest,
    load_manifest,
)

# The one pinned identity the committed manifest must be signed by.
_EXPECTED_SIGNER_REPO = "NousResearch/hermes-agent"
_EXPECTED_SIGNER_ISSUER = "https://token.actions.githubusercontent.com"

_SEMVER = re.compile(r"^\d+\.\d+\.\d+([.+-].*)?$")

# High-signal mutable executable/metadata fetch patterns (all languages, all
# paths). A hit that is not covered by a supply-chain/ledger.json entry fails CI.
_MUTABLE_PATTERNS = [
    re.compile(r"astral\.sh/uv/install"),
    re.compile(r"releases/latest/download"),
    re.compile(r"releases/latest"),
    re.compile(r"nodejs\.org/dist/latest-v"),
    re.compile(r"raw\.githubusercontent\.com/[^\s\"']+/(main|master)/"),
    # A pinned-commit (or branch) raw script fetch — the bootstrap installers
    # download scripts/install.{ps1,sh} from GitHub raw at a resolved ref, which
    # the main|master pattern above misses when the ref is a commit SHA
    # placeholder. Catches the Rust + Electron bootstrap runners.
    re.compile(r"raw\.githubusercontent\.com/[^\s\"'`]+/scripts/"),
    re.compile(r"refs/heads/[^\s\"']*\.zip"),
    re.compile(r"uv self update"),
    re.compile(r"irm https://astral"),
    re.compile(r"curl -LsSf https://astral"),
    # A URL that points directly at an executable/native/archive payload.
    re.compile(r"https?://[^\s\"'`]+\.(?:zip|tar\.gz|tar\.bz2|tgz|7z|exe|dll|node|AppImage|dmg|nupkg)\b"),
    # A browser payload install invoked as a command (line-start / shell chain),
    # not a quoted guidance string.
    re.compile(r"(?:^|&&|;|\|\||RUN\s+)\s*npx\s+playwright\s+install|playwright\.install\("),
    # A package-manager / fetch tool spawned as a child process that FETCHES and
    # runs code. Anchored to real spawn/exec functions (so 'find_node_executable'
    # does NOT match) and to fetch verbs (so a local 'git rev-parse' does NOT).
    re.compile(r"\b(?:spawn|spawnSync|execa|execaSync|execFile|execFileSync|execSync|fork)\s*\(\s*[\"'`](?:npx|uvx)\b"),
    re.compile(r"\b(?:spawn|spawnSync|execa|execaSync|execFile|execFileSync|execSync|fork)\s*\(\s*[\"'`](?:npm|pnpm|yarn)[\"'`]\s*,\s*(?:\[\s*)?[\"'`](?:install|ci|add|exec|dlx)\b"),
    re.compile(r"\b(?:spawn|spawnSync|execa|execaSync|execFile|execFileSync|execSync|fork)\s*\(\s*[\"'`]git[\"'`]\s*,\s*(?:\[\s*)?[\"'`]clone\b"),
    re.compile(r"\bgit\s+clone\b[^\n]*(?:https?://|git@|git://|ssh://)"),
    re.compile(r"subprocess\.\w+\(\s*\[?\s*[\"'](?:npx|uvx)\b"),
    re.compile(r"subprocess\.\w+\(\s*\[?\s*[\"'](?:pip|uv)[\"']\s*,\s*[\"']install\b"),
]

# Native/electron build-payload patterns. Restricted to native-build contexts
# (apps/ and nix/) so the same token in a core-Python docstring is not flagged.
_NATIVE_PATTERNS = [
    re.compile(r"@electron/get"),                       # electron binary download
    re.compile(r"@electron/rebuild|electron-rebuild"),  # native rebuild vs electron ABI
    re.compile(r"prebuild-install"),                    # native prebuilt binary download
    re.compile(r"node-gyp\s+rebuild"),                  # native source build
    re.compile(r"artifacts\.electronjs\.org"),          # electron headers/dist
    re.compile(r"registry\.npmjs\.org/[^\s\"'`]+\.tgz"),  # pinned npm tarball
]
_NATIVE_SCAN_PREFIXES = ("apps/", "nix/")

# Comment-line prefixes skipped during the scan (prose is not a fetch).
_COMMENT_PREFIXES = ("#", "//", "*", "/*", "--", "<!--", ">")

# ── A4: npm audited-lifecycle enforcement ──────────────────────────────────
# `npm install` / `npm ci` run every dependency's lifecycle scripts, and npm 10
# IGNORES the package.json `allowScripts` allowlist — so the only version-
# independent guarantee that no dependency runs arbitrary install-time code is
# `--ignore-scripts`. Every production npm install/ci must carry it; the
# reviewed, allowlisted lifecycle then runs via the audited orchestrator
# (apps/desktop/scripts/run-allowed-lifecycle.mjs) for the root workspace, or an
# explicit first-party step for a standalone sidecar. `--package-lock-only`
# updates the lockfile WITHOUT installing or running any script, so it is exempt.
_NPM_LIFECYCLE_OK = ("--ignore-scripts", "--package-lock-only")

# npm install/ci invocation forms across shell / Dockerfile / nix / PowerShell /
# Python / JS. Matched only on non-message logical lines (see _NPM_MESSAGE_PREFIX
# and _npm_logical_lines, which joins continuations so a flag on a `\`/`` ` ``
# continuation line counts).
_NPM_INVOKE_PATTERNS = [
    # shell / Dockerfile / nix: (npm | $npm | ${npm} | "$npm") install|ci|i
    # at a command position (line start, &&, ||, ;, |, RUN, then, do).
    re.compile(
        r"""(?:^|&&|\|\||;|\||\bRUN\b|\bthen\b|\bdo\b)
            \s*(?:[A-Za-z_][\w]*=[^\s]+\s+)*
            (?:npm|"?\$\{?[\w]*[Nn][Pp][Mm][\w]*\}?"?)
            \s+(?:install|ci|i)\b
        """,
        re.X,
    ),
    # PowerShell call operator: & $npmExe ci
    re.compile(r"&\s*\$\w*[Nn][Pp][Mm]\w*\s+(?:install|ci|i)\b"),
    # PowerShell arg-string form: $npmPath "install ...", _Invoke... $npmExe "ci ..."
    re.compile(r"\$\w*[Nn][Pp][Mm]\w*\s+[\"'](?:install|ci|i)\b"),
    # Python / JS argv list: [npm, "ci"  |  [_npm_bin, "install"  |  ["npm", "ci"
    re.compile(r"""\[\s*["']?[\w]*[Nn][Pp][Mm][\w]*["']?\s*,\s*["'](?:install|ci|i)\b"""),
]

# A logical line that merely MENTIONS an npm install (log/echo/throw/print/
# comment) is not an invocation. Anchored to the START of the line.
_NPM_MESSAGE_PREFIX = re.compile(
    r"""^\s*(?:
        \#|//|\*|/\*|<!--|--|>
      | log_\w+ | _nb_\w+ | echo\b | printf\b
      | Write-[\w-]+ | throw\b
      | print\s*\( | print\b
      | console\.\w+ | logger\.\w+
      | Show-[\w-]+
    )""",
    re.X | re.I,
)

# A4: an *executable recommendation* -- a printed recovery/guidance string that
# tells the operator to run a chained `npm install`/`npm ci` recipe (e.g.
# ``cd X && npm ci && npm run pack`` or ``Run manually: cd X && npm install``).
# Unlike a bare "npm install failed" mention (no shell chaining), a recipe is
# copy-pasteable, so it must recommend the SAFE command. A recipe is recognised
# by an npm install/ci CHAINED with another command (``&&`` / ``;`` / ``cd``).
_NPM_RECIPE_HINT = re.compile(
    r"""(?:&&|;|\|\|)\s*(?:cd\s+\S+\s*(?:&&|;)\s*)*npm\s+(?:install|ci)\b   # ... && npm ci
      | \bnpm\s+(?:install|ci)(?:\s+(?:-{1,2}[\w-]+|[\w./@~-]+))*\s*&&        # npm ci [flag/word args] && ...
      | \bcd\s+\S[^\n]*?&&[^\n]*?\bnpm\s+(?:install|ci)\b                    # cd X && ... npm ci
    """,
    re.X,
)

# A LOCAL `npm install -g <pkg>`/`--global <pkg>` of an EXTERNAL tool (not npm
# itself) is an explicit operator choice, not the hermes workspace lifecycle, so
# it is not a recipe this gate rewrites. The npm@ bootstrap global case IS
# rewritten and is caught by _NPM_GLOBAL_HINT before this exemption applies.
_NPM_EXTERNAL_GLOBAL = re.compile(
    r"\bnpm\s+(?:install|i)\b[^\n]*?(?:-g\b|--global\b)", re.I
)


# A4: an executable recommendation to GLOBALLY install npm from the registry
# (``npm install -g npm@X`` / ``npm i -g npm@X``). Even with --ignore-scripts a
# global npm@ install still trusts registry METADATA to resolve the tarball, so
# printed guidance must instead route through the digest-pinned bootstrap
# (scripts/ci/install-npm-pinned.mjs). Any npm@ global recommendation that is not
# that installer is flagged — including an UNCHAINED one (no `&&`).
_NPM_GLOBAL_HINT = re.compile(
    r"\bnpm\s+(?:install|i)\b[^\n]*?(?:-g\b|--global\b)[^\n]*?\bnpm@"
    r"|\bnpm\s+(?:install|i)\s+(?:-g|--global)\b[^\n]*?\bnpm@",
    re.I,
)


def _npm_recipe_hint_unsafe(line: str) -> bool:
    """True when *line* is an unsafe executable operator-recommendation: a chained
    ``npm install``/``npm ci`` recipe without the audited-lifecycle guarantee, OR
    a global ``npm install -g npm@X`` registry recommendation that is not the
    digest-pinned bootstrap. The safe recipes (``--ignore-scripts`` paired with
    the orchestrator, or ``install-npm-pinned.mjs``) pass."""
    if "install-npm-pinned" in line:
        return False
    # A global npm@ registry recommendation is unsafe even WITH --ignore-scripts
    # (it trusts registry metadata) — checked before the lifecycle-ok bypass so
    # --ignore-scripts alone cannot whitelist it.
    if _NPM_GLOBAL_HINT.search(line):
        return True
    if any(tok in line for tok in _NPM_LIFECYCLE_OK):
        return False
    if "run-allowed-lifecycle" in line:
        return False
    # A global install of an EXTERNAL tool (`npm install -g <pkg>`, not npm@) is
    # an explicit operator choice, not the hermes workspace lifecycle this gate
    # rewrites (the npm@ bootstrap case already returned True above).
    if _NPM_EXTERNAL_GLOBAL.search(line):
        return False
    return bool(_NPM_RECIPE_HINT.search(line))

# High-signal executable-fetch hits that are NOT a mutable install to classify:
# a substring on the same line marks the hit benign (lock-bound verification).
_MUTABLE_ALLOW = (
    "lock-integrity",
    "verifyLockIntegrity",
    "lockIntegrity",
)

# Gate primitives a real supply-chain gate uses. A ledger entry that claims a
# gate (explicitly_disabled) must reference at least one of these in its source
# — this proves the ledger cannot claim a gate that does not exist in code.
_GATE_MARKERS = (
    "compat_opt_in",
    "guard_install",
    "_managed_node_download_allowed",
    "validate_archive_members",
    "_HERMES_SC_BOOTSTRAP_OVERRIDE",
    "allowUnverifiedBootstrap",
    "supplyChainAllowsUnverified",
    "bundle_exact_identity",
    "ALLOW_UNVERIFIED_BROWSER",
    "_uv_supply_chain_gate",
    "install_cua_driver",
    "_allow_lazy_installs",
    "nativePrebuildDecision",
    "supplyChainAllowsUnverified",
    "runNativePayloadGate",
    "nativeRebuildOptIn",
)

_SCAN_EXTS = {".py", ".sh", ".ps1", ".nix", ".cmd", ".ts", ".tsx", ".mjs", ".cjs", ".js", ".rs"}
_SCAN_EXTRA_NAMES = {"Dockerfile"}

# Directories excluded from the enforcing scan: non-product, generated build
# output, or the supply-chain data/tooling itself (which legitimately names
# these URLs). apps/ and agent/lsp/ are NO LONGER excluded (WP4 item 6) — their
# executable/native/browser payload paths must be classified in the ledger.
# Generated bundles (dist/build/release/node_modules) stay out: they are not
# source and would flag vendored code we do not author.
_SCAN_EXCLUDE_DIRS = {
    "tests", "tests-js", "docs", "website", "node_modules", "__pycache__",
    ".pytest_cache", ".git", "supply-chain", "evals", "mcp-research-data",
    "contributors", "locales", "web", "datagen-config-examples",
    ".bytecode-fingerprint", "hermes_agent.egg-info",
    # generated / vendored build output (not first-party source)
    "dist", "build", "release", "out", ".vite", "web_dist", "coverage",
    ".turbo", ".next", "storybook-static", "e2e", "__mocks__", "__snapshots__",
    # skill content: a skill's own internal data/tool fetches are gated at
    # activation (install_from_quarantine), not per-line here.
    "skills", "optional-skills",
}
_SCAN_EXCLUDE_PATHS = {
    "scripts/ci/check_supply_chain.py",
    "scripts/ci/check_release_publish.py",
    "scripts/release/update_supply_chain_manifest.py",
    # the supply-chain verifier tooling itself legitimately names payload
    # patterns (it is what enforces them).
    "apps/desktop/scripts/native-payload-verifier.mjs",
    "apps/desktop/scripts/verify-native-payloads.mjs",
    # dev/bench tooling that shells local dev tools (npx tsx) — not a shipped
    # runtime fetch path.
    "ui-tui/scripts",
    "apps/desktop/scripts/run-short-session-hang-repro.mjs",
}


def _is_test_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return any(
        name.endswith(sfx)
        for sfx in (".test.ts", ".test.tsx", ".test.js", ".test.mjs", ".test.cjs",
                    ".spec.ts", ".spec.tsx", ".spec.js", ".spec.mjs")
    )


class Findings:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def add(self, message: str) -> None:
        self.errors.append(message)

    def ok(self) -> bool:
        return not self.errors


def _host_ok(url: str) -> bool:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname in CANONICAL_HOSTS


def check_manifest(manifest: ReleaseManifest, findings: Findings, *, now: datetime) -> None:
    meta = manifest.meta
    signer = meta.signer
    if signer.repository != _EXPECTED_SIGNER_REPO:
        findings.add(
            f"manifest signer repository is {signer.repository!r}, "
            f"expected {_EXPECTED_SIGNER_REPO!r}"
        )
    if signer.issuer != _EXPECTED_SIGNER_ISSUER:
        findings.add(f"manifest signer issuer is {signer.issuer!r}, expected the GitHub OIDC issuer")
    if _EXPECTED_SIGNER_REPO not in signer.identity_regexp:
        findings.add("manifest signer identity_regexp is not pinned to the Hermes release repo")

    if now > meta.expires_at:
        findings.add(f"manifest is expired (expires_at {meta.expires_at.isoformat()})")
    if meta.sequence < meta.min_sequence:
        findings.add("manifest sequence is below min_sequence")

    for component in manifest.components:
        where = f"component {component.name!r}"
        if component.trust_class == TRUST_RELEASE_VERIFIED:
            if not _SEMVER.match(component.version):
                findings.add(f"{where}: release_verified requires an exact version, got {component.version!r}")
            for art in component.artifacts:
                if not art.has_anchor:
                    findings.add(f"{where} {art.platform}/{art.arch}: release_verified needs a digest or provenance")
        for art in component.artifacts:
            if not _host_ok(art.url):
                findings.add(f"{where} {art.platform}/{art.arch}: non-canonical URL host {art.url!r}")
            unanchored = component.trust_class == TRUST_TRANSPORT_TRUSTED and not art.has_anchor
            if unanchored and not (art.blocker and art.operator_guidance):
                findings.add(
                    f"{where} {art.platform}/{art.arch}: unanchored transport_trusted "
                    "artifact must carry both a blocker and operator_guidance"
                )


def check_ledger(
    ledger: Ledger, manifest: ReleaseManifest, findings: Findings, *, root: Path
) -> None:
    component_names = {c.name for c in manifest.components}
    for entry in ledger.paths:
        source_path = root / entry.source
        if not source_path.exists():
            findings.add(f"ledger path {entry.id!r}: source file missing: {entry.source}")
        test_file = entry.negative_test.split("::", 1)[0]
        if not (root / test_file).exists():
            findings.add(f"ledger path {entry.id!r}: negative_test file missing: {test_file}")
        if entry.component is not None and entry.component not in component_names:
            findings.add(f"ledger path {entry.id!r}: unknown component {entry.component!r}")
        # An entry that claims a fail-closed gate must actually contain a gate
        # primitive in its source — the ledger cannot claim a gate that does not
        # exist in code (the core failure this ledger is audited against).
        if entry.migration_state == "explicitly_disabled" and source_path.exists():
            try:
                text = source_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            if not any(marker in text for marker in _GATE_MARKERS):
                findings.add(
                    f"ledger path {entry.id!r} claims explicitly_disabled but its "
                    f"source {entry.source} contains no supply-chain gate primitive "
                    f"({', '.join(_GATE_MARKERS[:4])}, …)"
                )


def _iter_scan_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        parts = set(rel.split("/"))
        if parts & _SCAN_EXCLUDE_DIRS:
            continue
        if _is_test_file(rel):
            continue
        if any(rel == p or rel.startswith(p + "/") for p in _SCAN_EXCLUDE_PATHS):
            continue
        if path.suffix in _SCAN_EXTS or path.name in _SCAN_EXTRA_NAMES:
            yield path, rel


def _scan_lines(text: str, rel: str):
    """Yield lines for scanning, with Python triple-quoted string bodies blanked
    so prose examples inside docstrings are not treated as fetches. Handles both
    same-line (``\"\"\"…\"\"\"``) and multi-line docstrings."""
    if not rel.endswith(".py"):
        yield from text.splitlines()
        return
    in_triple: str | None = None
    for line in text.splitlines():
        if in_triple is not None:
            if in_triple in line:
                line = line.split(in_triple, 1)[1]
                in_triple = None
            else:
                yield ""
                continue
        # Collapse any same-line triple-quoted spans; enter multi-line mode on
        # an unterminated opener.
        while True:
            m = re.search(r'"""|\'\'\'', line)
            if not m:
                break
            delim = m.group(0)
            after = line[m.end():]
            close = after.find(delim)
            if close != -1:
                line = line[:m.start()] + " " + after[close + 3:]
            else:
                line = line[:m.start()]
                in_triple = delim
                break
        yield line


def _line_is_fetch(line: str, rel: str) -> bool:
    """True when *line* contains a real mutable-fetch invocation.

    Comment lines and benign lock-bound lines are skipped; native-build
    patterns only apply inside native-build contexts (apps/ and nix/).
    """
    if any(token in line for token in _MUTABLE_ALLOW):
        return False
    if line.lstrip().startswith(_COMMENT_PREFIXES):
        return False
    if any(pattern.search(line) for pattern in _MUTABLE_PATTERNS):
        return True
    if rel.startswith(_NATIVE_SCAN_PREFIXES) and any(
        pattern.search(line) for pattern in _NATIVE_PATTERNS
    ):
        return True
    return False


def scan_mutable_fetches(root: Path, ledger: Ledger, findings: Findings) -> list[str]:
    """Return the ledgered source files that currently contain mutable fetches."""
    hit_files: set[str] = set()
    for path, rel in _iter_scan_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not any(_line_is_fetch(line, rel) for line in _scan_lines(text, rel)):
            continue
        hit_files.add(rel)
        if not ledger.covers(rel):
            findings.add(
                f"unclassified mutable fetch in {rel}: add a supply-chain ledger "
                "entry (supply-chain/ledger.json) classifying its trust owner"
            )
    return sorted(hit_files)


def _npm_logical_lines(text: str, rel: str):
    """Yield logical lines with shell / PowerShell continuations joined.

    Python files delegate to the docstring-aware :func:`_scan_lines` (their npm
    ``argv`` lists are single-line). Everything else joins a trailing ``\\``
    (shell / Dockerfile / nix) or trailing ``` ` ``` (PowerShell) continuation so
    a ``--ignore-scripts`` flag written on a continuation line is seen together
    with the ``install`` / ``ci`` token that precedes it.
    """
    if rel.endswith(".py"):
        yield from _scan_lines(text, rel)
        return
    is_ps = rel.endswith(".ps1")
    buf = ""
    for raw in text.splitlines():
        stripped = raw.rstrip()
        if is_ps and stripped.endswith("`"):
            buf += stripped[:-1] + " "
            continue
        if (not is_ps) and stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        yield buf + raw
        buf = ""
    if buf:
        yield buf


def _npm_line_needs_ignore_scripts(line: str, rel: str = "") -> bool:
    """True when *line* is a real ``npm install`` / ``npm ci`` invocation that
    lacks a no-lifecycle guarantee (``--ignore-scripts`` / ``--package-lock-only``).

    Invocation detection is file-type-aware: the shell command-position pattern
    (``&& npm ci``) is applied ONLY to shell-family files, because inside a
    Python / JS *string literal* (an ``argparse`` help string, an ``f"...  &&
    npm ci"`` guidance message, a ``` `... && npm ci` ``` template literal) that
    same fragment is prose, not an invocation. Code files are matched only by
    the language-level ``argv`` list form (``[npm, "ci"]``), which cannot appear
    inside such a message string.
    """
    if _NPM_MESSAGE_PREFIX.match(line):
        return False
    name = rel.rsplit("/", 1)[-1]
    shell_family = rel.endswith((".sh", ".nix", ".cmd", ".ps1")) or name in _SCAN_EXTRA_NAMES
    patterns = [_NPM_INVOKE_PATTERNS[3]]  # argv list — applies to every file type
    if shell_family:
        patterns.append(_NPM_INVOKE_PATTERNS[0])  # shell command-position
    if rel.endswith(".ps1"):
        patterns.extend(_NPM_INVOKE_PATTERNS[1:3])  # PowerShell call / arg-string
    if not any(pattern.search(line) for pattern in patterns):
        return False
    if any(tok in line for tok in _NPM_LIFECYCLE_OK):
        return False
    return True


def scan_npm_lifecycle(root: Path, findings: Findings) -> list[str]:
    """Flag every production ``npm install`` / ``npm ci`` that would run
    dependency lifecycle scripts without ``--ignore-scripts`` (A4).

    Returns the sorted set of offending files (empty when clean)."""
    hits: set[str] = set()
    for path, rel in _iter_scan_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "npm" not in text:
            continue
        for line in _npm_logical_lines(text, rel):
            if _npm_line_needs_ignore_scripts(line, rel):
                hits.add(rel)
                findings.add(
                    f"ungated npm install/ci in {rel}: `{line.strip()[:120]}` must "
                    "run with --ignore-scripts (A4 audited lifecycle): install with "
                    "--ignore-scripts, then run ONLY the reviewed allowlisted "
                    "lifecycle (apps/desktop/scripts/run-allowed-lifecycle.mjs for "
                    "the root workspace, or an explicit first-party step for a "
                    "sidecar). See docs/security/supply-chain-migration.md."
                )
            elif _npm_recipe_hint_unsafe(line):
                hits.add(rel)
                findings.add(
                    f"unsafe operator-guidance recipe in {rel}: `{line.strip()[:120]}` "
                    "recommends a chained `npm install`/`npm ci` without the audited "
                    "lifecycle. Printed recovery guidance must recommend `npm ci "
                    "--ignore-scripts && node apps/desktop/scripts/run-allowed-"
                    "lifecycle.mjs` (never a plain install)."
                )
    return sorted(hits)


# ── A3: npm coverage for package.json scripts and workflow run/command blocks ─
# The line scanner above covers shell / Dockerfile / nix / Python / JS source.
# npm install/ci ALSO hide in two executable surfaces it does not read as
# "lines": package.json ``scripts`` values and GitHub-workflow ``run:`` /
# ``with: {command: ...}`` blocks. These are swept here (docs workflows are NOT
# excluded), split into shell segments so a per-segment ``--ignore-scripts`` is
# required, and a GLOBAL npm bootstrap (``npm i -g npm@…``) must be pinned to an
# exact version.

# npm install/ci/i at the START of a shell segment (after optional VAR=val env).
_NPM_SEGMENT_INVOKE = re.compile(
    r"""^\s*(?:[A-Za-z_][\w]*=\S+\s+)*
        (?:npm|"?\$\{?[\w]*[Nn][Pp][Mm][\w]*\}?"?)
        \s+(?:install|ci|i)\b""",
    re.X,
)
_NPM_SEGMENT_SPLIT = re.compile(r"&&|\|\||;|\||\n")
_NPM_GLOBAL_FLAG = re.compile(r"(?:^|\s)(?:-g|--global)(?:\s|$|=)")
_NPM_GLOBAL_SPEC = re.compile(r"\bnpm@([^\s'\"]+)")
_EXACT_SEMVER_PIN = re.compile(r"^\d+\.\d+\.\d+$")


def _npm_command_offenses(cmd_text: str) -> list[str]:
    """Offenses for a shell command string (a package.json script value or a
    workflow run/command block):

      * an ``npm install``/``ci``/``i`` segment lacking ``--ignore-scripts``
        (``--package-lock-only`` is exempt — it installs nothing);
      * a DIRECT global npm registry install (``npm i -g npm@…``): even when the
        version is exact, resolving ``npm@<spec>`` trusts registry METADATA to
        pick the tarball. The approved path is the digest-pinned trusted
        installer ``node scripts/ci/install-npm-pinned.mjs`` (verifies the exact
        tarball sha256 from ``supply-chain/npm-bootstrap.json`` before install),
        which installs a LOCAL verified tarball and never names ``npm@<spec>``.
    """
    offenses: list[str] = []
    for seg in _NPM_SEGMENT_SPLIT.split(cmd_text or ""):
        s = seg.strip()
        if not s or not _NPM_SEGMENT_INVOKE.match(s):
            continue
        if not any(tok in s for tok in _NPM_LIFECYCLE_OK):
            offenses.append(
                f"`{s[:100]}` must run with --ignore-scripts (A4/A3 audited lifecycle)"
            )
        if _NPM_GLOBAL_FLAG.search(s):
            m = _NPM_GLOBAL_SPEC.search(s)
            if m:
                offenses.append(
                    f"`{s[:100]}` is a direct global npm registry install "
                    f"(npm@{m.group(1)}) that trusts registry metadata; use the "
                    "digest-pinned trusted installer `node "
                    "scripts/ci/install-npm-pinned.mjs` (verifies the exact tarball "
                    "sha256 from supply-chain/npm-bootstrap.json before install)."
                )
    return offenses


def scan_package_json_scripts(root: Path, findings: Findings) -> None:
    """Flag npm install/ci/global in package.json ``scripts`` that lack
    ``--ignore-scripts`` / an exact global pin. Sweeps every package.json except
    vendored/build trees."""
    import json as _json

    for pj in root.rglob("package.json"):
        rel = pj.relative_to(root).as_posix()
        if set(rel.split("/")) & _SCAN_EXCLUDE_DIRS:
            continue
        try:
            data = _json.loads(pj.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict):
            continue
        for name, cmd in scripts.items():
            for off in _npm_command_offenses(str(cmd)):
                findings.add(f"package.json script {rel}#{name}: {off}")


def _iter_yaml_command_strings(node):
    """Recursively yield every shell-command string in a PARSED workflow /
    composite-action object: ``run:`` values and ``with: {command: ...}`` values,
    at any nesting depth. This is the SOLE extractor for the npm-bootstrap audit:
    :func:`scan_workflow_npm` parses each file with PyYAML ``safe_load`` and walks
    the result here, so a block/folded scalar, flow mapping, quoted key,
    multiline plain scalar, or an anchor/alias is normalized by the YAML parser
    before it reaches this walk."""
    if isinstance(node, dict):
        for key, val in node.items():
            if key in ("run", "command") and isinstance(val, str):
                yield val
            yield from _iter_yaml_command_strings(val)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_yaml_command_strings(item)


def scan_workflow_npm(root: Path, findings: Findings) -> None:
    """Flag npm install/ci/global in GitHub-workflow AND composite-action
    ``run:`` / ``with: command:`` blocks that lack ``--ignore-scripts`` / are a
    direct global ``npm@`` registry install. Docs workflows are NOT excluded.

    Parses every workflow/action with PyYAML ``safe_load`` (pinned pyyaml==6.0.3
    in the manifest-ledger CI job) and recursively collects run/with.command
    strings. FAIL-CLOSED: if PyYAML is unavailable, or a file is unreadable or
    unparseable, a finding is recorded (never a silent skip and never a weak
    regex fallback) so an ungated ``npm install`` can never slip through on a
    missing or odd parser."""
    try:
        import yaml
    except ImportError:
        findings.add(
            "workflow npm scan requires PyYAML (pin pyyaml==6.0.3 in the "
            "manifest-ledger CI job); it is unavailable — failing closed rather "
            "than skipping the ungated-npm audit."
        )
        return
    scan_dirs = [root / ".github" / "workflows", root / ".github" / "actions"]
    files: set[Path] = set()
    for d in scan_dirs:
        if d.is_dir():
            files.update(d.rglob("*.yml"))
            files.update(d.rglob("*.yaml"))
    for wf in sorted(files):
        rel = wf.relative_to(root).as_posix()
        try:
            text = wf.read_text(encoding="utf-8")
        except OSError as exc:
            findings.add(
                f"workflow {rel}: unreadable, cannot audit npm bootstrap "
                f"(fail closed): {exc}"
            )
            continue
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            findings.add(
                f"workflow {rel}: unparseable YAML, cannot audit npm bootstrap "
                f"(fail closed): {exc}"
            )
            continue
        for cmd in _iter_yaml_command_strings(parsed):
            for off in _npm_command_offenses(str(cmd)):
                findings.add(f"workflow {rel}: {off}")


def run(root: Path | None = None, *, now: datetime | None = None) -> Findings:
    root = root or _REPO_ROOT
    now = now or datetime.now(timezone.utc)
    findings = Findings()
    try:
        manifest = load_manifest(root / "supply-chain" / "manifest.json")
    except ManifestError as exc:
        findings.add(f"manifest failed to load: {exc}")
        return findings
    try:
        ledger = load_ledger(root / "supply-chain" / "ledger.json")
    except ManifestError as exc:
        findings.add(f"ledger failed to load: {exc}")
        return findings

    check_manifest(manifest, findings, now=now)
    check_ledger(ledger, manifest, findings, root=root)
    scan_mutable_fetches(root, ledger, findings)
    scan_npm_lifecycle(root, findings)
    scan_package_json_scripts(root, findings)
    scan_workflow_npm(root, findings)
    return findings


def main(argv: list[str] | None = None) -> int:
    findings = run()
    if findings.ok():
        print("supply-chain: manifest, ledger, and mutable-fetch surface OK")
        return 0
    print("supply-chain check FAILED:", file=sys.stderr)
    for error in findings.errors:
        print(f"  - {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
