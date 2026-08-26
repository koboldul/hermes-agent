"""Repository-owned immutable LSP runtime manifest.

SEC-AUDIT-002 requires that every *automatically* installed language server and
its transitive dependency graph resolve to a repository-reviewed, immutable
identity — not a mutable ``npm install <name>`` or ``gopls@latest``.

This module is the single source of truth for that identity.  Each
:class:`LSPRecipe` records:

* server identifier and package ecosystem;
* the exact pinned top-level version and executable name;
* supported platforms;
* the committed dependency-lock location (under ``agent/lsp/locks/``);
* expected top-level integrity metadata (npm ``sha512`` or Go ``h1:`` sum);
* whether package lifecycle scripts are required, with a written
  justification;
* the last review date.

A recipe is *auto-installable* only when it declares an exact version, a
committed lock graph, and expected integrity.  Any other server — including
npm servers not yet locked — is manual-only: the automatic path refuses it and
falls back to operator-installed binaries on ``PATH``.  This deliberately keeps
the automatic path from ever installing a mutable dependency graph (the plan's
"do not ship a partially hardened automatic path").

The lock graphs themselves are committed, Hermes-owned, and pinned to the
public registries with strong integrity:

* ``locks/npm/<name>/{package.json,package-lock.json}`` — installed with
  ``npm ci --ignore-scripts`` against the committed lock;
* ``locks/go/<name>/{go.mod,go.sum}`` — built with ``GOWORK=off`` and
  ``-mod=readonly`` from the committed module (a ``tool`` directive pins the
  exact top-level version without an ``@latest`` suffix).
"""
from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class ManifestError(Exception):
    """Raised when a recipe's committed lock graph fails verification."""


@dataclass(frozen=True)
class LSPRecipe:
    """One reviewed, immutable server identity."""

    server_id: str
    ecosystem: str  # "npm" | "go" | "pip" | "manual"
    version: str = ""  # exact pinned top-level version ("" ⇒ not pinned)
    bin: str = ""
    #: Sibling top-level packages installed inside the same committed lock
    #: graph (e.g. typescript alongside typescript-language-server).
    extra_pkgs: Tuple[str, ...] = ()
    #: Repository-relative lock directory under ``agent/lsp/locks``.
    lock_dir: Optional[str] = None
    #: Expected top-level integrity: npm ``sha512-...`` or Go ``h1:...``.
    top_level_integrity: Optional[str] = None
    lifecycle_scripts: bool = False
    lifecycle_justification: str = ""
    #: Supported ``sys.platform`` values; empty ⇒ all platforms.
    platforms: Tuple[str, ...] = ()
    last_review: str = ""
    #: Recipe opts into copying proxy variables (userinfo stripped).
    allow_proxy: bool = False
    #: Ambient variable names the recipe declares it needs copied.
    copy_ambient: Tuple[str, ...] = ()
    #: Static, non-secret toolchain values the recipe declares.
    recipe_env: Tuple[Tuple[str, str], ...] = ()

    @property
    def auto_installable(self) -> bool:
        """True only for a pinned, locked, integrity-bearing recipe."""
        return (
            self.ecosystem in {"npm", "go", "pip"}
            and bool(self.version)
            and bool(self.lock_dir)
            and bool(self.top_level_integrity)
        )

    @property
    def env_additions(self) -> Dict[str, str]:
        return {k: v for k, v in self.recipe_env}


# ---------------------------------------------------------------------------
# The manifest.  Keyed by the install *package* name (matches the historical
# INSTALL_RECIPES keys) so the CLI mapping in agent/lsp/cli.py keeps working.
# ---------------------------------------------------------------------------

LSP_MANIFEST: Dict[str, LSPRecipe] = {
    # ---- Auto-installable (pinned + committed lock + integrity) ----------
    "pyright": LSPRecipe(
        server_id="pyright",
        ecosystem="npm",
        version="1.1.413",
        bin="pyright-langserver",
        lock_dir="npm/pyright",
        top_level_integrity=(
            "sha512-1lpxKrh0DHHpfAQOfciZo2ojua2jase3wwO9at8kl"
            "dc+F/p1PBscxA5CQ3G1qg5lMOMhXo6ZaiMLMXEAqADIAg=="
        ),
        lifecycle_scripts=False,
        platforms=(),
        last_review="2026-08-25",
    ),
    "gopls": LSPRecipe(
        server_id="gopls",
        ecosystem="go",
        version="v0.23.0",
        bin="gopls",
        lock_dir="go/gopls",
        top_level_integrity="h1:Dn6mf9WXu9iLnTftDDMb9wV0c6Se7PjzEMqP0LEe08Y=",
        lifecycle_scripts=False,
        platforms=(),
        last_review="2026-08-25",
    ),
    # ---- Known npm servers not yet locked → manual-only (auto refuses) ---
    # These retain a reviewed identity slot but no committed lock graph, so
    # ``auto_installable`` is False and the automatic path never installs a
    # mutable dependency tree for them.  Add a committed lock + integrity to
    # promote one to auto-installable.
    "typescript-language-server": LSPRecipe(
        server_id="typescript-language-server",
        ecosystem="npm",
        bin="typescript-language-server",
        extra_pkgs=("typescript",),
    ),
    "@vue/language-server": LSPRecipe(
        server_id="@vue/language-server", ecosystem="npm", bin="vue-language-server"
    ),
    "svelte-language-server": LSPRecipe(
        server_id="svelte-language-server", ecosystem="npm", bin="svelteserver"
    ),
    "@astrojs/language-server": LSPRecipe(
        server_id="@astrojs/language-server", ecosystem="npm", bin="astro-ls"
    ),
    "yaml-language-server": LSPRecipe(
        server_id="yaml-language-server", ecosystem="npm", bin="yaml-language-server"
    ),
    "bash-language-server": LSPRecipe(
        server_id="bash-language-server", ecosystem="npm", bin="bash-language-server"
    ),
    "intelephense": LSPRecipe(
        server_id="intelephense", ecosystem="npm", bin="intelephense"
    ),
    "dockerfile-language-server-nodejs": LSPRecipe(
        server_id="dockerfile-language-server-nodejs",
        ecosystem="npm",
        bin="docker-langserver",
    ),
    # ---- Manual servers (heavy / platform-specific bootstrap) ------------
    "rust-analyzer": LSPRecipe(
        server_id="rust-analyzer", ecosystem="manual", bin="rust-analyzer"
    ),
    "clangd": LSPRecipe(server_id="clangd", ecosystem="manual", bin="clangd"),
    "lua-language-server": LSPRecipe(
        server_id="lua-language-server", ecosystem="manual", bin="lua-language-server"
    ),
    "powershell": LSPRecipe(
        server_id="powershell", ecosystem="manual", bin="pwsh"
    ),
}


def get_recipe(pkg: str) -> Optional[LSPRecipe]:
    return LSP_MANIFEST.get(pkg)


def all_recipes() -> List[LSPRecipe]:
    return list(LSP_MANIFEST.values())


def locks_root() -> Path:
    return Path(__file__).resolve().parent / "locks"


def recipe_lock_path(recipe: LSPRecipe) -> Optional[Path]:
    if not recipe.lock_dir:
        return None
    return locks_root() / recipe.lock_dir


def _lock_file_names(recipe: LSPRecipe) -> Tuple[str, ...]:
    if recipe.ecosystem == "npm":
        return ("package.json", "package-lock.json")
    if recipe.ecosystem == "go":
        return ("go.mod", "go.sum")
    if recipe.ecosystem == "pip":
        return ("requirements.txt",)
    return ()


def read_lock_files(recipe: LSPRecipe) -> Dict[str, bytes]:
    """Return the committed lock file contents, or raise :class:`ManifestError`."""
    lock_dir = recipe_lock_path(recipe)
    if lock_dir is None:
        raise ManifestError(f"{recipe.server_id}: no committed lock graph")
    out: Dict[str, bytes] = {}
    for name in _lock_file_names(recipe):
        p = lock_dir / name
        if not p.is_file():
            raise ManifestError(f"{recipe.server_id}: missing lock file {name}")
        out[name] = p.read_bytes()
    return out


def lock_digest(recipe: LSPRecipe) -> str:
    """Deterministic digest of the committed lock graph."""
    files = read_lock_files(recipe)
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode("utf-8"))
        h.update(b"\0")
        h.update(files[name])
        h.update(b"\0")
    return "sha256:" + h.hexdigest()


def manifest_identity(recipe: LSPRecipe) -> str:
    """Immutable identity binding for provenance markers.

    Includes the pinned version, integrity, and committed lock digest so any
    change to the reviewed identity invalidates previously recorded provenance.
    """
    h = hashlib.sha256()
    for part in (
        recipe.server_id,
        recipe.ecosystem,
        recipe.version,
        recipe.bin,
        recipe.top_level_integrity or "",
    ):
        h.update(part.encode("utf-8"))
        h.update(b"\0")
    try:
        h.update(lock_digest(recipe).encode("utf-8"))
    except ManifestError:
        pass
    return "sha256:" + h.hexdigest()


def supported_on_platform(recipe: LSPRecipe, platform: Optional[str] = None) -> bool:
    if not recipe.platforms:
        return True
    return (platform or sys.platform) in recipe.platforms


def verify_npm_lock(recipe: LSPRecipe, files: Dict[str, bytes]) -> None:
    import json

    try:
        lock = json.loads(files["package-lock.json"].decode("utf-8"))
        pkg = json.loads(files["package.json"].decode("utf-8"))
    except (KeyError, ValueError) as e:
        raise ManifestError(f"{recipe.server_id}: unreadable npm lock ({e})") from e

    deps = pkg.get("dependencies") or {}
    # Exact pin — no ranges, and the manifest version must match the lock.
    declared = deps.get(recipe.server_id)
    if declared != recipe.version:
        raise ManifestError(
            f"{recipe.server_id}: package.json pins {declared!r}, "
            f"manifest expects {recipe.version!r}"
        )
    for extra in recipe.extra_pkgs:
        if extra not in deps:
            raise ManifestError(f"{recipe.server_id}: extra pkg {extra} absent from lock")
    packages = lock.get("packages") or {}
    node = packages.get(f"node_modules/{recipe.server_id}")
    if not isinstance(node, dict):
        raise ManifestError(f"{recipe.server_id}: not represented in package-lock")
    if node.get("version") != recipe.version:
        raise ManifestError(
            f"{recipe.server_id}: lock version {node.get('version')!r} "
            f"!= manifest {recipe.version!r}"
        )
    integ = node.get("integrity")
    if recipe.top_level_integrity and integ != recipe.top_level_integrity:
        raise ManifestError(
            f"{recipe.server_id}: integrity mismatch (lock {integ!r})"
        )
    # Reject unexpected lifecycle scripts on the top-level package.
    if node.get("hasInstallScript") and not recipe.lifecycle_scripts:
        raise ManifestError(
            f"{recipe.server_id}: lock declares an install script but the "
            f"recipe forbids lifecycle scripts"
        )


def verify_go_lock(recipe: LSPRecipe, files: Dict[str, bytes]) -> None:
    gomod = files.get("go.mod", b"").decode("utf-8", "replace")
    gosum = files.get("go.sum", b"").decode("utf-8", "replace")
    module_line = f"golang.org/x/tools/gopls {recipe.version}"
    if module_line not in gomod:
        raise ManifestError(
            f"{recipe.server_id}: go.mod does not require {recipe.version}"
        )
    sum_line = f"golang.org/x/tools/gopls {recipe.version} {recipe.top_level_integrity}"
    if recipe.top_level_integrity and sum_line not in gosum:
        raise ManifestError(
            f"{recipe.server_id}: go.sum missing expected sum for {recipe.version}"
        )


def verify_lock_graph(recipe: LSPRecipe) -> Dict[str, bytes]:
    """Verify the committed lock graph matches the reviewed manifest identity.

    Returns the lock file bytes on success; raises :class:`ManifestError` on
    any drift, missing file, missing integrity, unexpected lifecycle script,
    unpinned version, or unknown package.
    """
    if not recipe.version:
        raise ManifestError(f"{recipe.server_id}: recipe is not pinned to a version")
    if not recipe.top_level_integrity:
        raise ManifestError(f"{recipe.server_id}: recipe has no expected integrity")
    files = read_lock_files(recipe)
    if recipe.ecosystem == "npm":
        verify_npm_lock(recipe, files)
    elif recipe.ecosystem == "go":
        verify_go_lock(recipe, files)
    else:
        raise ManifestError(f"{recipe.server_id}: unsupported ecosystem {recipe.ecosystem}")
    return files


__all__ = [
    "ManifestError",
    "LSPRecipe",
    "LSP_MANIFEST",
    "get_recipe",
    "all_recipes",
    "locks_root",
    "recipe_lock_path",
    "read_lock_files",
    "lock_digest",
    "manifest_identity",
    "supported_on_platform",
    "verify_lock_graph",
    "verify_npm_lock",
    "verify_go_lock",
]
