"""Purpose-specific restricted environment builder for the LSP subsystem.

SEC-AUDIT-002 requires that LSP installers, version probes, and language
servers receive a *declared, purpose-specific* environment rather than an
inherited process environment with a handful of known secrets removed.  The
central terminal-oriented builder in :mod:`tools.environments.local` starts
from ``os.environ`` and strips a denylist; that is the right contract for the
operator's trusted shell but the wrong one for a lower-trust package-lifecycle
script or a language server that may execute compromised third-party code.

This builder inverts the default: it starts from an **empty** environment and
copies only the execution requirements a recipe explicitly declares.  Nothing
else — no provider keys, no gateway tokens, no ``*_SECRET`` / ``*_TOKEN``
variables, no cloud/registry/CI credentials, no SSH/GPG agent sockets, no
inherited package-manager configuration — is visible to the child regardless
of its name.

The module is dependency-neutral: it knows nothing about npm, Go, or pip.
Callers describe what a subprocess needs with an :class:`LSPEnvPolicy` and this
builder materialises exactly that.

Isolation caveat (documented deliberately): scrubbing the environment removes
*process-visible credentials*.  A language server still runs with the Hermes
user's filesystem and network authority.  Full containment requires isolating
the whole process (see ``SECURITY.md`` §2.2), which this builder does not and
cannot provide.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

# --------------------------------------------------------------------------
# Controlled category variable names
# --------------------------------------------------------------------------

# Windows CreateProcess genuinely needs these to launch *any* child; POSIX
# does not.  They are process-launch machinery, never credentials.
_WINDOWS_LAUNCH_VARS: tuple[str, ...] = (
    "SystemRoot",
    "windir",
    "ComSpec",
    "PATHEXT",
    "SystemDrive",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
)

# Real-home detection inputs (paths, not secrets).  Seeded so the subprocess
# HOME contract resolves the operator's real home rather than falling back to
# ``/tmp``.
_HOME_HINT_VARS: tuple[str, ...] = (
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "HERMES_REAL_HOME",
)

_LOCALE_VARS: tuple[str, ...] = (
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_NUMERIC",
    "LC_COLLATE",
    "LC_TIME",
)

_TEMP_VARS: tuple[str, ...] = (
    "TMPDIR",
    "TMP",
    "TEMP",
)

_CERT_VARS: tuple[str, ...] = (
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
)

_PROXY_VARS: tuple[str, ...] = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)

# Package-manager / build-tool configuration that must never be inherited from
# the ambient environment: it can silently redirect a registry, dependency
# graph, lifecycle policy, or executed runtime.  Blocked only on the
# copy-from-ambient path; the install code sets its own hermetic values for
# these families through :attr:`LSPEnvPolicy.additions`.
_AMBIENT_CONFIG_PREFIXES: tuple[str, ...] = (
    "NPM_CONFIG_",
    "NODE_",
    "NPM_",
    "YARN_",
    "PNPM_",
    "GO",          # GOFLAGS, GOPROXY, GOPATH, GONOSUMCHECK, GOWORK, ...
    "PIP_",
    "PYTHON",      # PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, ...
    "PYENV",
    "CARGO_",
    "RUSTUP_",
    "UV_",
)

# Agent sockets / credential-helper channels: never copied from ambient.
_AGENT_SOCKET_VARS: frozenset[str] = frozenset({
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "SSH_CONNECTION",
    "SSH_CLIENT",
    "GPG_AGENT_INFO",
    "GNUPGHOME",
    "DBUS_SESSION_BUS_ADDRESS",
})

# Generic secret-name suffixes/substrings, applied to every declared value so
# a recipe or config override can never re-introduce a credential by name.
_SECRET_SUFFIXES: tuple[str, ...] = (
    "_KEY",
    "_SECRET",
    "_TOKEN",
    "_PASSWORD",
    "_PASSWD",
    "_CREDENTIAL",
    "_CREDENTIALS",
    "_APIKEY",
    "_API_KEY",
    "_ACCESS_KEY",
    "_PRIVATE_KEY",
    "_SESSION_TOKEN",
)
_SECRET_SUBSTRINGS: tuple[str, ...] = (
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "SESSION_TOKEN",
    "APIKEY",
)


@dataclass(frozen=True)
class LSPEnvPolicy:
    """Declares the environment an LSP subprocess is permitted to receive.

    Everything defaults to the safest posture.  A recipe opts into the exact
    controlled categories and values it needs; the builder guarantees nothing
    else leaks in.
    """

    #: Controlled PATH directories prepended ahead of the OS defaults
    #: (managed runtime dirs, the resolved toolchain/binary directory).
    path_entries: tuple[str, ...] = ()
    #: When True the operator's inherited PATH is appended.  Reserved for
    #: manual-mode / operator-owned binaries where the operator explicitly
    #: owns the PATH trust decision.
    include_inherited_path: bool = False
    allow_locale: bool = True
    allow_tmp: bool = True
    allow_cert: bool = True
    #: Proxy variables are copied only when the recipe opts in; userinfo
    #: (embedded credentials) is stripped unless ``allow_proxy_credentials``.
    allow_proxy: bool = False
    allow_proxy_credentials: bool = False
    #: Ambient variable names the recipe explicitly declares it needs copied.
    #: Still filtered against the secret / manager-config / agent-socket
    #: guards — a recipe cannot launder a credential through this list.
    copy_ambient: tuple[str, ...] = ()
    #: Literal, recipe/config-owned non-secret values applied last.  Filtered
    #: against the secret guard so an override cannot re-add an internal
    #: secret, but manager-config families (e.g. hermetic ``NPM_CONFIG_*``)
    #: are permitted here because the recipe owns them deliberately.
    additions: Mapping[str, str] = field(default_factory=dict)


def _norm(name: str) -> str:
    return str(name).upper()


def is_secret_name(name: str) -> bool:
    """Return True when *name* looks like a credential by name alone.

    Combines the central Hermes classifications (provider blocklist, always-
    strip tier, dynamic-secret patterns) with generic name heuristics so a
    declared addition or ambient copy can never re-introduce a secret.
    """
    upper = _norm(name)
    try:
        from tools.environments.local import (
            _ALWAYS_STRIP_KEYS,
            _HERMES_PROVIDER_ENV_BLOCKLIST,
            _HERMES_PROVIDER_ENV_FORCE_PREFIX,
            _is_hermes_internal_secret,
        )

        if name in _ALWAYS_STRIP_KEYS or name in _HERMES_PROVIDER_ENV_BLOCKLIST:
            return True
        if upper.startswith(_norm(_HERMES_PROVIDER_ENV_FORCE_PREFIX)):
            return True
        if _is_hermes_internal_secret(name):
            return True
    except Exception:
        # Central classifications unavailable (partial import) — fall through
        # to the name heuristics, which are self-contained.
        pass
    if upper in _AGENT_SOCKET_VARS:
        return True
    if any(upper.endswith(sfx) for sfx in _SECRET_SUFFIXES):
        return True
    if any(sub in upper for sub in _SECRET_SUBSTRINGS):
        return True
    return False


def _is_ambient_manager_config(name: str) -> bool:
    upper = _norm(name)
    return any(upper.startswith(_norm(p)) for p in _AMBIENT_CONFIG_PREFIXES)


def _system_default_path_entries() -> list[str]:
    if sys.platform == "win32":
        root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
        return [
            os.path.join(root, "System32"),
            root,
            os.path.join(root, "System32", "Wbem"),
            os.path.join(root, "System32", "WindowsPowerShell", "v1.0"),
        ]
    return ["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]


def _dedup_preserve(entries: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for e in entries:
        if not e:
            continue
        key = os.path.normcase(e)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def _sanitize_proxy_value(value: str, allow_credentials: bool) -> str:
    if allow_credentials or not value:
        return value
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.netloc or "@" not in parts.netloc:
        return value
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def build_lsp_process_env(
    policy: LSPEnvPolicy | None = None,
    *,
    ambient: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Materialise the exact environment a policy declares, starting empty.

    The result contains only:

    * a controlled ``PATH`` (policy entries + OS defaults, optionally the
      operator's inherited PATH for manual-mode binaries);
    * Windows process-launch variables where present;
    * profile-aware ``HERMES_HOME`` plus the subprocess ``HOME`` contract;
    * locale / temp / certificate-store values when the policy allows them;
    * proxy values when the policy opts in (userinfo stripped by default);
    * recipe-declared ambient copies and literal additions, each filtered so
      no credential is ever re-introduced.
    """
    policy = policy or LSPEnvPolicy()
    src = dict(os.environ if ambient is None else ambient)
    env: dict[str, str] = {}

    # --- PATH (controlled) ------------------------------------------------
    path_parts: list[str] = list(policy.path_entries)
    path_parts.extend(_managed_runtime_path_entries())
    path_parts.extend(_system_default_path_entries())
    if policy.include_inherited_path:
        inherited = src.get("PATH", "")
        path_parts.extend(p for p in inherited.split(os.pathsep) if p)
    env["PATH"] = os.pathsep.join(_dedup_preserve(path_parts))

    # --- Windows launch machinery ----------------------------------------
    if sys.platform == "win32":
        for key in _WINDOWS_LAUNCH_VARS:
            val = src.get(key)
            if val is not None:
                env[key] = val

    # --- controlled categories -------------------------------------------
    if policy.allow_locale:
        _copy_present(env, src, _LOCALE_VARS)
    if policy.allow_tmp:
        _copy_present(env, src, _TEMP_VARS)
    if policy.allow_cert:
        _copy_present(env, src, _CERT_VARS)
    if policy.allow_proxy:
        for key in _PROXY_VARS:
            val = src.get(key)
            if val is not None:
                env[key] = _sanitize_proxy_value(val, policy.allow_proxy_credentials)

    # --- recipe-declared ambient copies ----------------------------------
    for key in policy.copy_ambient:
        if key not in src:
            continue
        if is_secret_name(key) or _is_ambient_manager_config(key):
            continue
        env[key] = src[key]

    # --- profile HERMES_HOME + subprocess HOME contract ------------------
    # Seed home hints so real-home detection does not collapse to /tmp, then
    # let the central contract set HOME / HERMES_REAL_HOME.
    for key in _HOME_HINT_VARS:
        val = src.get(key)
        if val is not None:
            env.setdefault(key, val)
    try:
        from hermes_constants import (
            apply_subprocess_home_env,
            get_hermes_home,
            get_hermes_home_override,
        )

        hermes_home = get_hermes_home_override() or str(get_hermes_home())
        if hermes_home:
            env["HERMES_HOME"] = hermes_home
        apply_subprocess_home_env(env)
    except Exception:
        pass

    # --- recipe/config literal additions (applied last) ------------------
    for key, value in dict(policy.additions).items():
        if is_secret_name(key):
            continue
        env[str(key)] = str(value)

    return env


def _copy_present(env: dict[str, str], src: Mapping[str, str], names: Sequence[str]) -> None:
    for name in names:
        val = src.get(name)
        if val is not None:
            env[name] = val


def _managed_runtime_path_entries() -> list[str]:
    """Return Hermes-managed runtime bin directories that exist.

    These are Hermes-owned, non-secret directories (managed Node, the LSP bin
    staging dir, the managed ``uv`` bin).  Including them keeps auto-installed
    servers launchable under a controlled PATH without inheriting the
    operator's arbitrary PATH.
    """
    entries: list[str] = []
    try:
        from hermes_constants import get_hermes_home, iter_hermes_node_dirs

        for d in iter_hermes_node_dirs():
            if d.is_dir():
                entries.append(str(d))
        home = get_hermes_home()
        for sub in (("lsp", "bin"), ("bin",)):
            p = home.joinpath(*sub)
            if p.is_dir():
                entries.append(str(p))
    except Exception:
        pass
    return entries


__all__ = [
    "LSPEnvPolicy",
    "build_lsp_process_env",
    "is_secret_name",
]
