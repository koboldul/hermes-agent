"""Canonical component/platform/architecture identities.

The manifest addresses artifacts by an exact ``(platform, arch)`` pair drawn
from a closed, canonical vocabulary. Every consumer (uv, Node, cua-driver, …)
uses its own upstream naming (``x64`` vs ``x86_64``, ``win`` vs ``windows``);
this module is the single place that maps host detection to the canonical
vocabulary so a lookup is unambiguous and a missing mapping fails closed rather
than silently resolving to the wrong artifact.
"""

from __future__ import annotations

import os
import platform as _platform

# Closed vocabularies. A value outside these sets is an error, not a fallback.
PLATFORMS = ("linux", "macos", "windows")
ARCHES = ("x86_64", "aarch64", "x86", "armv7")

_PLATFORM_ALIASES = {
    "linux": "linux",
    "android": "linux",  # Termux reuses Linux binaries
    "darwin": "macos",
    "macos": "macos",
    "mac": "macos",
    "windows": "windows",
    "win32": "windows",
    "win": "windows",
    "cygwin": "windows",
}

_ARCH_ALIASES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "x64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "x86": "x86",
    "i386": "x86",
    "i686": "x86",
    "armv7l": "armv7",
    "armv7": "armv7",
}


def normalize_platform(raw: str) -> str | None:
    """Map an OS string to the canonical platform, or ``None`` if unknown."""
    return _PLATFORM_ALIASES.get((raw or "").strip().lower())


def normalize_arch(raw: str) -> str | None:
    """Map an architecture string to the canonical arch, or ``None``."""
    return _ARCH_ALIASES.get((raw or "").strip().lower())


def current_platform() -> str | None:
    """Return the canonical platform for the running host, or ``None``."""
    return normalize_platform(_platform.system())


def current_arch() -> str | None:
    """Return the canonical arch for the running host, or ``None``.

    Honors ``PROCESSOR_ARCHITEW6432`` so a 32-bit Python on 64-bit Windows
    still resolves the real machine architecture.
    """
    raw = (
        os.environ.get("PROCESSOR_ARCHITEW6432")
        or os.environ.get("PROCESSOR_ARCHITECTURE")
        or _platform.machine()
    )
    return normalize_arch(raw)
