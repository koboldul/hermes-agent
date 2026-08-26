"""Immutable, restricted-environment installation of LSP server binaries.

SEC-AUDIT-002 rewrite.  The automatic installation path is now:

* **Consent- and lock-gated.**  Only recipes that declare an exact version, a
  committed dependency-lock graph, and expected integrity
  (:mod:`agent.lsp.manifest`) are auto-installable.  Everything else is
  manual-only, so the automatic path never installs a mutable dependency tree.
* **Environment-scrubbed.**  Installers run with a purpose-specific environment
  built from an empty allowlist (:mod:`agent.lsp.restricted_env`) — no provider
  keys, gateway tokens, cloud/registry/CI credentials, agent sockets, or
  inherited package-manager configuration are visible to a lifecycle script.
* **Immutable.**  npm installs use ``npm ci --ignore-scripts`` against the
  committed ``package-lock.json``; Go installs build from the committed
  ``go.mod``/``go.sum`` with ``GOWORK=off`` and ``-mod=readonly`` and no
  ``@latest`` suffix.  Lock drift, integrity mismatch, or an unexpected
  lifecycle-script requirement fails closed.
* **Transactional + provenance-marked.**  Installs land in a private staging
  directory and are swapped in atomically; a provenance marker
  (:mod:`agent.lsp.provenance`) binds the reviewed identity and the installed
  binary's digest.  A managed binary is executed only when its marker verifies
  and the on-disk file is unchanged.  A failed install leaves no verified
  binary.

Managed vs. operator ``PATH``: a verified managed binary is preferred; an
operator-installed binary on ``PATH`` is honoured (the operator owns that trust
decision); an *unmarked* legacy binary under ``HERMES_HOME/lsp/bin`` is never
executed until Hermes reinstalls it or the operator re-approves an exact path.

Isolation caveat: scrubbing the environment removes process-visible
credentials.  An installed language server still has the Hermes user's
filesystem and network authority unless the whole process is separately
isolated (see ``SECURITY.md`` §2.2).
"""
from __future__ import annotations

import logging
import contextlib
import errno
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from hermes_cli._subprocess_compat import windows_hide_flags
from hermes_constants import find_node_executable

from agent.lsp import manifest as _manifest
from agent.lsp import provenance as _provenance
from agent.lsp.manifest import ManifestError
from agent.lsp.restricted_env import LSPEnvPolicy, build_lsp_process_env

logger = logging.getLogger("agent.lsp.install")

_WINDOWS_WRAPPER_SUFFIXES = (".cmd", ".exe", ".bat")


# ---------------------------------------------------------------------------
# Backwards-compatible recipe view (derived from the immutable manifest)
# ---------------------------------------------------------------------------
def _compat_recipes() -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for pkg, recipe in _manifest.LSP_MANIFEST.items():
        out[pkg] = {
            "strategy": recipe.ecosystem,
            "pkg": pkg,
            "bin": recipe.bin,
            "version": recipe.version,
            "auto_installable": recipe.auto_installable,
            "extra_pkgs": list(recipe.extra_pkgs),
        }
    return out


#: Compatibility mapping used by the CLI and older tests.  The authoritative
#: source of truth is :data:`agent.lsp.manifest.LSP_MANIFEST`.
INSTALL_RECIPES: Dict[str, Dict[str, Any]] = _compat_recipes()


_install_locks: Dict[str, threading.Lock] = {}
_install_results: Dict[str, Optional[str]] = {}
_install_lock_meta = threading.Lock()


def _is_windows() -> bool:
    return os.name == "nt"


def hermes_lsp_root() -> Path:
    from hermes_constants import get_hermes_home

    p = get_hermes_home() / "lsp"
    p.mkdir(parents=True, exist_ok=True)
    return p


def hermes_lsp_bin_dir() -> Path:
    """Return the Hermes-owned bin staging dir for LSP servers."""
    p = hermes_lsp_root() / "bin"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _servers_dir() -> Path:
    p = hermes_lsp_root() / "servers"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _cache_dir(name: str) -> Path:
    p = hermes_lsp_root() / "cache" / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def _sanitize_name(pkg: str) -> str:
    return pkg.replace("/", "__").replace("@", "at__")


def _native_binary_candidates(base: Path) -> List[Path]:
    """Return platform-native executable candidates for a staged binary."""
    candidates = [base]
    if _is_windows():
        existing = {str(base).lower()}
        for suffix in _WINDOWS_WRAPPER_SUFFIXES:
            candidate = Path(str(base) + suffix)
            key = str(candidate).lower()
            if key not in existing:
                candidates.append(candidate)
                existing.add(key)
    return candidates


def _path_binary(*names: str) -> Optional[str]:
    """Resolve an operator ``PATH`` binary (never the managed staging tree)."""
    for name in names:
        on_path = shutil.which(name)
        if on_path:
            return on_path
        if _is_windows():
            for suffix in _WINDOWS_WRAPPER_SUFFIXES:
                on_path = shutil.which(f"{name}{suffix}")
                if on_path:
                    return on_path
    return None


def _unverified_managed_present(recipe: "_manifest.LSPRecipe") -> Optional[str]:
    """Return a managed staging file that exists but is NOT provenance-verified.

    Used only for status/diagnostics — never for spawning.
    """
    for cand in _native_binary_candidates(hermes_lsp_bin_dir() / recipe.bin):
        if cand.exists():
            return str(cand)
    return None


def _get_lock(pkg: str) -> threading.Lock:
    with _install_lock_meta:
        lock = _install_locks.get(pkg)
        if lock is None:
            lock = threading.Lock()
            _install_locks[pkg] = lock
        return lock


# ---------------------------------------------------------------------------
# Transient-filesystem-error handling + cross-process publication lock
# ---------------------------------------------------------------------------
# Windows renames of a just-populated directory routinely fail transiently with
# ERROR_ACCESS_DENIED (5) or ERROR_SHARING_VIOLATION (32) while an antivirus
# scanner or a lingering child handle still holds a file inside the tree.  The
# rename succeeds moments later once the handle is released.  We retry ONLY
# these sharing/access classes (never a real error) with bounded backoff so a
# transient scan can never turn a completed install into a cached ``None``.
_TRANSIENT_WINERRORS = {5, 32, 145}  # access denied, sharing violation, dir-not-empty


def _is_transient_fs_error(exc: BaseException) -> bool:
    winerr = getattr(exc, "winerror", None)
    if winerr in _TRANSIENT_WINERRORS:
        return True
    if isinstance(exc, PermissionError):
        return True
    return getattr(exc, "errno", None) in {errno.EACCES, errno.EPERM}


def _os_replace_retry(
    src: str, dst: str, *, attempts: int = 60, base_delay: float = 0.03, max_delay: float = 0.3
) -> None:
    """``os.replace`` with bounded retry for transient Windows sharing errors."""
    last: Optional[BaseException] = None
    for i in range(attempts):
        try:
            os.replace(src, dst)
            return
        except OSError as e:
            if not _is_transient_fs_error(e):
                raise
            last = e
            time.sleep(min(max_delay, base_delay * (1.4 ** i)))
    if last is not None:
        raise last


@contextlib.contextmanager
def _package_publication_lock(pkg: str, timeout: float = 300.0) -> Iterator[None]:
    """Cross-process exclusive lock serialising install+publish for one package.

    Complements the in-process thread lock so two *processes* whose first use of
    the same server races cannot both stage-and-swap into the live target.  The
    lock is best-effort: if it cannot be acquired within *timeout* (or the OS
    provides no locking primitive) we proceed anyway — the caller re-checks
    :func:`agent.lsp.provenance.verify_managed` under the lock, and the atomic
    swap plus marker re-verification keep the tree consistent regardless.
    """
    try:
        import fcntl as _fcntl  # type: ignore
    except ImportError:
        _fcntl = None  # type: ignore
    try:
        import msvcrt as _msvcrt  # type: ignore
    except ImportError:
        _msvcrt = None  # type: ignore

    if _fcntl is None and _msvcrt is None:
        yield
        return

    lock_dir = hermes_lsp_root() / ".locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / (_sanitize_name(pkg) + ".lock")
    if _msvcrt is not None:
        try:
            if not lock_path.exists() or lock_path.stat().st_size == 0:
                lock_path.write_text(" ", encoding="utf-8")
        except OSError:
            pass

    fh = open(lock_path, "r+" if _msvcrt is not None else "a+", encoding="utf-8")
    acquired = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                if _fcntl is not None:
                    _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                else:
                    fh.seek(0)
                    _msvcrt.locking(fh.fileno(), _msvcrt.LK_NBLCK, 1)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    logger.warning(
                        "[install] %s: cross-process lock wait timed out; "
                        "proceeding best-effort",
                        pkg,
                    )
                    break
                time.sleep(0.1)
        yield
    finally:
        if acquired:
            try:
                if _fcntl is not None:
                    _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)
                else:
                    fh.seek(0)
                    _msvcrt.locking(fh.fileno(), _msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        try:
            fh.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Public resolution / install API
# ---------------------------------------------------------------------------
def resolve_binary(
    pkg: str,
    strategy: str = "manual",
    *,
    path_names: tuple = (),
    command_override: Optional[str] = None,
) -> Optional[str]:
    """The single strategy-aware resolver for every LSP server binary.

    This is the one place that decides what a server builder is allowed to
    launch.  The policy differs sharply by effective *strategy* (SEC-AUDIT-002
    Alert 2 — effective ``auto`` must never trust an arbitrary ``PATH`` entry):

    **Effective ``auto``** may execute ONLY:

    1. an explicit operator ``command`` override **that has been re-approved to
       its exact digest** (``hermes lsp approve``);
    2. a current **verified managed** binary (provenance marker matches the
       reviewed manifest and the on-disk digest is unchanged);
    3. a **re-approved exact-digest** binary;
    4. the result of a **committed, locked install**.

    Arbitrary ``PATH`` is never consulted in ``auto``.

    **Effective ``manual``** (the operator owns the trust decision) may execute:

    1. an explicit operator ``command`` override (as-is);
    2. a verified managed / re-approved binary;
    3. an operator ``PATH`` binary.

    ``manual`` never installs.  An unmarked/mutated managed binary is never
    returned in either mode.
    """
    recipe = _manifest.get_recipe(pkg)
    effective = "auto" if str(strategy).strip().lower() == "auto" else "manual"
    marker_key = recipe.server_id if recipe is not None else pkg

    # 1. Explicit operator command override — highest-priority operator intent.
    if command_override:
        co = os.path.abspath(os.path.expanduser(str(command_override)))
        if not os.path.exists(co):
            # An explicit pin that does not resolve is a hard stop: never fall
            # back to PATH or install a *different* binary behind the operator.
            return None
        if effective == "manual":
            return co  # operator owns the command path in manual mode
        # auto: the pinned path must be re-approved and bound to its exact
        # current digest, or it is refused (no arbitrary-command execution).
        reappr = _provenance.verify_reapproved(marker_key)
        if reappr and os.path.abspath(reappr) == co:
            return co
        logger.info(
            "[resolve] %s: config command override %s is not digest-reapproved; "
            "refusing to execute it under auto (run `hermes lsp approve`)",
            pkg,
            co,
        )
        return None

    # 2. Verified managed / re-approved marker — trusted in BOTH modes.
    if recipe is not None:
        managed = _provenance.verify_managed(recipe)
        if managed and os.access(managed, os.X_OK):
            return managed
    else:
        reappr = _provenance.verify_reapproved(marker_key)
        if reappr and os.access(reappr, os.X_OK):
            return reappr

    # 3. Effective auto: committed locked install ONLY — never arbitrary PATH.
    if effective == "auto":
        if recipe is not None and recipe.ecosystem in {"npm", "go", "pip"}:
            return _install_and_verify(recipe)
        return None

    # 4. Manual: an operator PATH binary is allowed (operator owns PATH trust).
    names = tuple(path_names) or ((recipe.bin,) if recipe is not None else (pkg,))
    return _path_binary(*names)


def try_install(pkg: str, strategy: str = "manual") -> Optional[str]:
    """Compatibility wrapper around :func:`resolve_binary`.

    ``strategy`` must already be the *effective* strategy (``"auto"`` only when
    consent is satisfied — see :mod:`agent.lsp.consent`).  Anything other than
    ``"auto"`` never triggers a network/package-manager call.
    """
    effective = "auto" if str(strategy).strip().lower() == "auto" else "manual"
    return resolve_binary(pkg, effective)


def resolve_compound_components(
    server_id: str,
    strategy: str,
    *,
    manual_fn,
    required: tuple,
) -> Optional[Dict[str, str]]:
    """Strategy-aware resolution for a *compound* server (multiple trusted
    artifacts that must all be authorised — e.g. PowerShell's host interpreter
    plus the ``Start-EditorServices.ps1`` bootstrap script).

    **Effective ``auto``** returns the component paths ONLY when EVERY required
    component is exact-path + digest re-approved (``hermes lsp approve``) or a
    provenance-managed artifact — and none has been mutated.  A raw ``PATH``
    host, a config/env bundle path, and an unmarked ``HERMES_HOME`` bundle are
    all refused.

    **Effective ``manual``** delegates to ``manual_fn`` (the operator owns the
    host + bundle trust decision).
    """
    effective = "auto" if str(strategy).strip().lower() == "auto" else "manual"
    if effective == "auto":
        resolved = _provenance.verify_compound_reapproved(server_id)
        if resolved and all(k in resolved for k in required):
            return resolved
        logger.info(
            "[resolve] %s: compound components (%s) are not all digest-reapproved; "
            "refusing under auto (run `hermes lsp approve %s`)",
            server_id,
            ", ".join(required),
            server_id,
        )
        return None
    return manual_fn()


def _install_and_verify(recipe: "_manifest.LSPRecipe") -> Optional[str]:
    if not recipe.auto_installable:
        logger.info(
            "[install] %s is not auto-installable (no committed lock graph); "
            "manual install required",
            recipe.server_id,
        )
        return None
    if not _manifest.supported_on_platform(recipe):
        logger.info("[install] %s not supported on this platform", recipe.server_id)
        return None

    pkg = recipe.server_id
    if pkg in _install_results:
        return _install_results[pkg]
    lock = _get_lock(pkg)
    with lock:  # in-process serialization
        if pkg in _install_results:
            return _install_results[pkg]
        # Re-check for a verified binary produced by a concurrent installer
        # (same process, before we take the cross-process lock).
        managed = _provenance.verify_managed(recipe)
        if managed:
            _install_results[pkg] = managed
            return managed
        # Cross-process publication lock: serialize the stage→swap→marker
        # critical section against other Hermes processes installing the same
        # server.  Re-check verify_managed INSIDE the lock so a peer that just
        # published is adopted rather than re-installed (never double-build,
        # never clobber a peer's tree).
        with _package_publication_lock(pkg):
            managed = _provenance.verify_managed(recipe)
            if managed:
                _install_results[pkg] = managed
                return managed
            try:
                files = _manifest.verify_lock_graph(recipe)
            except ManifestError as e:
                logger.warning("[install] %s: lock verification failed: %s", pkg, e)
                _install_results[pkg] = None
                return None
            result: Optional[str] = None
            try:
                if recipe.ecosystem == "npm":
                    result = _install_npm_locked(recipe, files)
                elif recipe.ecosystem == "go":
                    result = _install_go_locked(recipe, files)
                else:
                    logger.warning("[install] unsupported ecosystem for %s", pkg)
            except Exception as e:  # noqa: BLE001
                logger.warning("[install] %s failed: %s", pkg, e)
                result = None
            if result is not None:
                try:
                    from agent.lsp.consent import CONSENT_POLICY_VERSION

                    # Marker publication is ordered AFTER the binary is swapped
                    # into place, so verify_managed never sees a marker whose
                    # binary is not yet published.
                    _provenance.write_marker(
                        recipe,
                        result,
                        source="managed",
                        consent_version=CONSENT_POLICY_VERSION,
                    )
                except Exception as e:  # noqa: BLE001
                    logger.warning("[install] %s: could not record provenance: %s", pkg, e)
                    result = None
            verified = _provenance.verify_managed(recipe) if result else None
            _install_results[pkg] = verified
            return verified


# ---------------------------------------------------------------------------
# Toolchain resolution seams (monkeypatched in tests with fake executables)
# ---------------------------------------------------------------------------
def _npm_argv() -> Optional[List[str]]:
    npm = find_node_executable("npm")
    return [npm] if npm else None


def _go_argv() -> Optional[List[str]]:
    go = shutil.which("go")
    return [go] if go else None


# ---------------------------------------------------------------------------
# npm — hermetic, immutable ``npm ci --ignore-scripts`` against committed lock
# ---------------------------------------------------------------------------
def _npm_env_policy() -> LSPEnvPolicy:
    argv = _npm_argv()
    path_entries: List[str] = []
    if argv:
        path_entries.append(str(Path(argv[0]).resolve().parent))
    # Hermetic, EMPTY user/global npmrc files (distinct paths — npm refuses to
    # load the same path as both "user" and "global").  Empty files neutralise
    # any ambient ~/.npmrc / global npmrc without npm rejecting them.
    npm_cache = _cache_dir("npm")
    user_rc = npm_cache / "empty-user.npmrc"
    global_rc = npm_cache / "empty-global.npmrc"
    for rc in (user_rc, global_rc):
        if not rc.exists():
            rc.write_text("", encoding="utf-8")
    additions = {
        "NPM_CONFIG_USERCONFIG": str(user_rc),
        "NPM_CONFIG_GLOBALCONFIG": str(global_rc),
        "NPM_CONFIG_CACHE": str(npm_cache),
        "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/",
        "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
    }
    return LSPEnvPolicy(path_entries=tuple(path_entries), additions=additions)


def _install_npm_locked(
    recipe: "_manifest.LSPRecipe", files: Dict[str, bytes]
) -> Optional[str]:
    argv = _npm_argv()
    if argv is None:
        logger.info("[install] cannot install %s: no usable npm found", recipe.server_id)
        return None

    final_dir = _servers_dir() / _sanitize_name(recipe.server_id)
    staging = final_dir.parent / (
        f".staging-{_sanitize_name(recipe.server_id)}-{uuid.uuid4().hex}"
    )
    staging_active: Optional[Path] = staging
    try:
        staging.mkdir(parents=True, exist_ok=False)
        # Materialise the committed lock graph (never trust an on-disk copy in
        # an existing tree; always plant the reviewed bytes).
        for name, data in files.items():
            (staging / name).write_bytes(data)

        env = build_lsp_process_env(_npm_env_policy())
        cmd = [*argv, "ci", "--ignore-scripts", "--no-audit", "--no-fund"]
        logger.info("[install] npm ci (%s) in %s", recipe.version, staging)
        proc = subprocess.run(
            cmd,
            cwd=str(staging),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            stdin=subprocess.DEVNULL,
            env=env,
            creationflags=windows_hide_flags(),
        )
        if proc.returncode != 0:
            logger.warning(
                "[install] npm ci failed for %s: %s",
                recipe.server_id,
                (proc.stderr or "").strip()[:500],
            )
            return None

        if _find_npm_bin(staging, recipe.bin) is None:
            logger.warning(
                "[install] npm ci for %s succeeded but bin %s not found",
                recipe.server_id,
                recipe.bin,
            )
            return None

        # Transactional swap: replace any prior tree atomically.
        _replace_dir(staging, final_dir)
        staging_active = None  # consumed by the swap
        final_bin = _find_npm_bin(final_dir, recipe.bin)
        if final_bin is None:
            return None
        _link_into_bin(final_bin)
        return str(final_bin)
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("[install] npm install errored for %s: %s", recipe.server_id, e)
        return None
    finally:
        if staging_active is not None and staging_active.exists():
            shutil.rmtree(staging_active, ignore_errors=True)


def _find_npm_bin(root: Path, bin_name: str) -> Optional[Path]:
    nm_bin = root / "node_modules" / ".bin" / bin_name
    for c in _native_binary_candidates(nm_bin):
        if c.exists():
            return c
    return None


# ---------------------------------------------------------------------------
# Go — hermetic, immutable install from committed module (GOWORK=off, readonly)
# ---------------------------------------------------------------------------
def _go_env_policy(gobin: Path, gopath: Path) -> LSPEnvPolicy:
    argv = _go_argv()
    path_entries: List[str] = [str(gobin)]
    if argv:
        path_entries.append(str(Path(argv[0]).resolve().parent))
    additions = {
        "GOWORK": "off",
        "GOFLAGS": "-mod=readonly",
        "GOTOOLCHAIN": "local",
        "GOENV": "off",
        "GOSUMDB": "sum.golang.org",
        "GOPROXY": "https://proxy.golang.org,direct",
        "GOPRIVATE": "",
        "CGO_ENABLED": "0",
        "GOBIN": str(gobin),
        "GOPATH": str(gopath),
        "GOMODCACHE": str(gopath / "pkg" / "mod"),
        "GOCACHE": str(_cache_dir("go-build")),
    }
    return LSPEnvPolicy(path_entries=tuple(path_entries), additions=additions)


def _install_go_locked(
    recipe: "_manifest.LSPRecipe", files: Dict[str, bytes]
) -> Optional[str]:
    argv = _go_argv()
    if argv is None:
        logger.info("[install] cannot install %s: go not on PATH", recipe.server_id)
        return None

    gopath = hermes_lsp_root() / "go"
    gopath.mkdir(parents=True, exist_ok=True)
    module_dir = hermes_lsp_root() / "go-build" / _sanitize_name(recipe.server_id)
    stage_bin = module_dir.parent / f".gobin-{uuid.uuid4().hex}"
    try:
        module_dir.mkdir(parents=True, exist_ok=True)
        stage_bin.mkdir(parents=True, exist_ok=False)
        # Plant the reviewed committed module graph.
        for name, data in files.items():
            (module_dir / name).write_bytes(data)

        env = build_lsp_process_env(_go_env_policy(stage_bin, gopath))
        # No @version suffix: the pinned version resolves via the committed
        # module graph under -mod=readonly.
        cmd = [*argv, "install", "-mod=readonly", "golang.org/x/tools/gopls"]
        logger.info("[install] go install %s (%s)", recipe.server_id, recipe.version)
        proc = subprocess.run(
            cmd,
            cwd=str(module_dir),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1200,
            stdin=subprocess.DEVNULL,
            env=env,
            creationflags=windows_hide_flags(),
        )
        if proc.returncode != 0:
            logger.warning(
                "[install] go install failed for %s: %s",
                recipe.server_id,
                (proc.stderr or "").strip()[:500],
            )
            return None

        built = stage_bin / recipe.bin
        if _is_windows():
            built = built.with_suffix(".exe")
        if not built.exists():
            logger.warning(
                "[install] go install for %s succeeded but bin %s not found",
                recipe.server_id,
                recipe.bin,
            )
            return None

        final_bin = hermes_lsp_bin_dir() / built.name
        # Atomic, retrying overwrite (handles transient Windows sharing errors
        # on the freshly-built binary without a separate unlink race).
        _os_replace_retry(str(built), str(final_bin))
        return str(final_bin)
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("[install] go install errored for %s: %s", recipe.server_id, e)
        return None
    finally:
        if stage_bin.exists():
            shutil.rmtree(stage_bin, ignore_errors=True)


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------
def _replace_dir(src: Path, dst: Path) -> None:
    """Atomically replace *dst* with *src* (same volume), retrying transient
    Windows sharing/access errors so an antivirus scan of the just-created tree
    can never surface as an install failure.

    ``src`` is a caller-owned private staging directory (unique per install) and
    ``dst`` is the package's own final directory; the trash side-move only ever
    touches ``dst``'s prior content, so this can never remove another package's
    install.
    """
    if dst.exists():
        trash = dst.parent / f".trash-{uuid.uuid4().hex}"
        _os_replace_retry(str(dst), str(trash))
        shutil.rmtree(trash, ignore_errors=True)
    _os_replace_retry(str(src), str(dst))


def _link_into_bin(target: Path) -> None:
    """Expose *target* under ``lsp/bin/`` for stable access (best effort)."""
    link = hermes_lsp_bin_dir() / target.name
    if link.exists() or link.is_symlink():
        try:
            link.unlink()
        except OSError:
            return
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        try:
            shutil.copy2(target, link)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
def detect_status(pkg: str) -> str:
    """Return install status for ``hermes lsp status``.

    One of ``installed`` (verified managed or operator PATH), ``unverified``
    (a managed file exists but is not provenance-verified), ``manual-only``,
    or ``missing``.
    """
    recipe = _manifest.get_recipe(pkg)
    if recipe is None:
        return "installed" if _path_binary(pkg) else "missing"
    if _provenance.verify_managed(recipe) or _path_binary(recipe.bin):
        return "installed"
    if _unverified_managed_present(recipe):
        return "unverified"
    if recipe.ecosystem == "manual" or not recipe.auto_installable:
        return "manual-only"
    return "missing"


def _existing_binary(name: str) -> Optional[str]:
    """Resolve a trustworthy binary by bin *name* (operator PATH or verified).

    Used by status/``which`` and backend warnings.  Never returns an unmarked
    managed staging binary.
    """
    on_path = _path_binary(name)
    if on_path:
        return on_path
    for recipe in _manifest.all_recipes():
        if recipe.bin == name:
            verified = _provenance.verify_managed(recipe)
            if verified:
                return verified
    return None


__all__ = [
    "INSTALL_RECIPES",
    "resolve_binary",
    "try_install",
    "detect_status",
    "hermes_lsp_bin_dir",
    "hermes_lsp_root",
]
