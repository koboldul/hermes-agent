#!/usr/bin/env bash
# Supply-chain gate for shell installers (Work Package 4).
#
# Secure by default. The mutable one-line bootstraps (astral.sh uv installer,
# nodejs.org latest download, trycua cua installer) are NOT release-verified —
# there is no committed digest to check before executing the response. So they
# run only when:
#
#   * an existing operator-managed executable is present (used in place), or
#   * the operator explicitly passed --allow-unverified-bootstrap to the
#     installer (which sets the INTERNAL _HERMES_SC_BOOTSTRAP_OVERRIDE bridge
#     AFTER argument parsing — this is not a user-facing environment variable).
#
# Otherwise the gate prints actionable guidance and the caller must not fetch or
# execute the mutable installer.
#
# Source this file and call:  sc_gate_install <component> <existing-exe> <manual-hint>
#   returns 0  → proceed (operator-managed exe present, or explicit opt-in)
#   returns 1  → fail closed (guidance already printed to stderr)

# True (0) when the operator explicitly opted into unverified installs for this
# invocation. The only signal is the internal bridge set by an installer's
# --allow-unverified-bootstrap flag (or by Hermes after reading config).
sc_opt_in() {
    case "${_HERMES_SC_BOOTSTRAP_OVERRIDE:-}" in
        1|true|yes|on|TRUE|YES|ON|True|Yes|On) return 0 ;;
    esac
    return 1
}

# sc_gate_install <component> <existing-exe-or-empty> <manual-hint>
sc_gate_install() {
    _sc_component="${1:-component}"
    _sc_existing="${2:-}"
    _sc_hint="${3:-}"
    if [ -n "$_sc_existing" ]; then
        return 0
    fi
    if sc_opt_in; then
        return 0
    fi
    printf '%s\n' "✗ Automatic install of ${_sc_component} is disabled by default (supply-chain enforce):" >&2
    printf '%s\n' "  its installer is fetched and executed from a mutable, unverified source." >&2
    printf '%s\n' "  Install ${_sc_component} with your OS/version manager (Hermes will use it in place)," >&2
    printf '%s\n' "  or re-run the installer with --allow-unverified-bootstrap." >&2
    [ -n "$_sc_hint" ] && printf '%s\n' "  Manual install: ${_sc_hint}" >&2
    printf '%s\n' "  See docs/security/supply-chain-migration.md." >&2
    return 1
}

# sc_termux_deps_gate <hashed-graph-file-or-empty>
#
# The Termux/Android install path uses pip with a *version-constrained* file
# (constraints-termux.txt), which pins versions but does NOT verify artifact
# hashes. A compromised wheel/sdist that still satisfies the version pin would
# not be rejected. So under the secure default the Termux dependency install is
# disabled: it runs only when
#
#   * a committed pip ``--require-hashes`` graph exists (a hashed requirements
#     file — its every requirement carries a ``--hash=sha256:...`` line), or
#   * the operator explicitly opted in (``--allow-unverified-bootstrap``).
#
#   returns 0  → proceed (hashed graph available, or explicit opt-in)
#   returns 1  → fail closed (guidance already printed to stderr)
sc_termux_deps_gate() {
    _sc_graph="${1:-}"
    if sc_termux_hashed_graph_available "$_sc_graph"; then
        return 0
    fi
    if sc_opt_in; then
        return 0
    fi
    printf '%s\n' "✗ Termux dependency install is disabled by default (supply-chain enforce):" >&2
    printf '%s\n' "  the Android pip path is version-constrained (constraints-termux.txt), not" >&2
    printf '%s\n' "  hash-locked, so a compromised wheel/sdist would not be rejected, and no" >&2
    printf '%s\n' "  committed --require-hashes graph is available in this checkout." >&2
    printf '%s\n' "  Options:" >&2
    printf '%s\n' "    - Provision a hash-locked Termux venv yourself (operator-managed), OR" >&2
    printf '%s\n' "    - Re-run: install.sh --allow-unverified-bootstrap  (BREAK-GLASS: runs the" >&2
    printf '%s\n' "      version-constrained, UNVERIFIED pip path)." >&2
    printf '%s\n' "  See docs/security/supply-chain-migration.md." >&2
    return 1
}

# sc_termux_hashed_graph_available <file>
#   returns 0 only when <file> exists and contains at least one pip hash pin
#   (``--hash=sha256:``), i.e. it is a real --require-hashes graph. No such file
#   is committed today, so this returns 1 and the gate fails closed by default.
sc_termux_hashed_graph_available() {
    _sc_graph="${1:-}"
    [ -n "$_sc_graph" ] || return 1
    [ -f "$_sc_graph" ] || return 1
    grep -q -- '--hash=sha256:' "$_sc_graph" 2>/dev/null || return 1
    return 0
}
