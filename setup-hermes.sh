#!/bin/bash
# ============================================================================
# Hermes Agent Setup Script
# ============================================================================
# Quick setup for developers who cloned the repo manually.
# Uses uv for desktop/server setup and Python's stdlib venv + pip on Termux.
#
# Usage:
#   ./setup-hermes.sh
#
# This script:
# 1. Detects desktop/server vs Android/Termux setup path
# 2. Creates a Python 3.11 virtual environment
# 3. Installs the appropriate dependency set for the platform
# 4. Creates .env from template (if not exists)
# 5. Symlinks the 'hermes' CLI command into a user-facing bin dir
# 6. Runs the setup wizard (optional)
# ============================================================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Supply-chain (WP4): --allow-unverified-bootstrap opts into the UNVERIFIED
# installers (uv/Node/etc.) for this run. Secure by default — without it, a
# missing tool must come from your OS/version manager. This sets an INTERNAL
# bridge consumed by the gate; it is not a user-facing environment variable.
for _sc_arg in "$@"; do
    case "$_sc_arg" in
        --allow-unverified-bootstrap)
            export _HERMES_SC_BOOTSTRAP_OVERRIDE=1
            echo -e "${YELLOW}⚠${NC} --allow-unverified-bootstrap: running UNVERIFIED transport-trusted installers (not release-verified)."
            ;;
    esac
done

# Prevent uv from discovering config files (uv.toml, pyproject.toml) from the
# wrong user's home directory when running under sudo -u <user>.  See #21269.
export UV_NO_CONFIG=1

PYTHON_VERSION="3.11"

is_termux() {
    [ -n "${TERMUX_VERSION:-}" ] || [[ "${PREFIX:-}" == *"com.termux/files/usr"* ]]
}

get_command_link_dir() {
    if is_termux && [ -n "${PREFIX:-}" ]; then
        echo "$PREFIX/bin"
    else
        echo "$HOME/.local/bin"
    fi
}

get_command_link_display_dir() {
    if is_termux && [ -n "${PREFIX:-}" ]; then
        echo '$PREFIX/bin'
    else
        echo '~/.local/bin'
    fi
}

echo ""
echo -e "${CYAN}⚕ Hermes Agent Setup${NC}"
echo ""

# ============================================================================
# Install / locate uv
# ============================================================================

echo -e "${CYAN}→${NC} Checking for uv..."

UV_CMD=""
if is_termux; then
    echo -e "${CYAN}→${NC} Termux detected — using Python's stdlib venv + pip instead of uv"
else
    if command -v uv &> /dev/null; then
        UV_CMD="uv"
    elif [ -x "$HOME/.local/bin/uv" ]; then
        UV_CMD="$HOME/.local/bin/uv"
    elif [ -x "$HOME/.cargo/bin/uv" ]; then
        UV_CMD="$HOME/.cargo/bin/uv"
    fi

    if [ -n "$UV_CMD" ]; then
        UV_VERSION=$($UV_CMD --version 2>/dev/null)
        echo -e "${GREEN}✓${NC} uv found ($UV_VERSION)"
    else
        # Supply-chain gate (WP4): the astral uv installer is fetched and
        # executed from a mutable, unverified source. Secure by default — it
        # runs only when --allow-unverified-bootstrap was passed.
        if [ "${_HERMES_SC_BOOTSTRAP_OVERRIDE:-}" != "1" ]; then
            echo -e "${RED}✗${NC} Automatic uv install is disabled by default (supply-chain enforce)."
            echo -e "${CYAN}→${NC} Install uv with your OS/version manager (pipx/brew/winget) and re-run,"
            echo -e "${CYAN}→${NC} or re-run: ./setup-hermes.sh --allow-unverified-bootstrap"
            echo -e "${CYAN}→${NC} Manual: https://docs.astral.sh/uv/ (see docs/security/supply-chain-migration.md)"
            exit 1
        fi
        echo -e "${CYAN}→${NC} Installing uv (UNVERIFIED compatibility bootstrap; opted in)..."
        # Capture installer output so a failure shows the user WHY
        # (network, glibc mismatch on old distros, missing curl, disk
        # full, etc.) instead of "✗ Failed to install uv" with zero
        # diagnostic.  Two-stage to avoid `curl | sh` masking curl
        # failures (sh exits 0 on empty stdin under no pipefail).
        _uv_log="$(mktemp 2>/dev/null || echo "/tmp/hermes-uv-install.$$.log")"
        _uv_installer="$(mktemp 2>/dev/null || echo "/tmp/hermes-uv-installer.$$.sh")"
        if ! curl -LsSf https://astral.sh/uv/install.sh -o "$_uv_installer" 2>"$_uv_log"; then
            echo -e "${RED}✗${NC} Failed to download uv installer."
            sed 's/^/    /' "$_uv_log" >&2
            echo -e "${CYAN}→${NC} Install manually: https://docs.astral.sh/uv/"
            rm -f "$_uv_log" "$_uv_installer"
            exit 1
        fi
        if sh "$_uv_installer" >>"$_uv_log" 2>&1; then
            rm -f "$_uv_installer"
            if [ -x "$HOME/.local/bin/uv" ]; then
                UV_CMD="$HOME/.local/bin/uv"
            elif [ -x "$HOME/.cargo/bin/uv" ]; then
                UV_CMD="$HOME/.cargo/bin/uv"
            fi

            if [ -n "$UV_CMD" ]; then
                rm -f "$_uv_log"
                UV_VERSION=$($UV_CMD --version 2>/dev/null)
                echo -e "${GREEN}✓${NC} uv installed ($UV_VERSION)"
            else
                echo -e "${RED}✗${NC} uv installer reported success but binary not found. Add ~/.local/bin to PATH and retry."
                echo -e "${CYAN}→${NC} Installer output:"
                sed 's/^/    /' "$_uv_log" >&2
                rm -f "$_uv_log"
                exit 1
            fi
        else
            echo -e "${RED}✗${NC} Failed to install uv."
            echo -e "${CYAN}→${NC} Installer output:"
            sed 's/^/    /' "$_uv_log" >&2
            echo -e "${CYAN}→${NC} Install manually: https://docs.astral.sh/uv/"
            rm -f "$_uv_log" "$_uv_installer"
            exit 1
        fi
    fi
fi

# ============================================================================
# Python check (uv can provision it automatically)
# ============================================================================

echo -e "${CYAN}→${NC} Checking Python $PYTHON_VERSION..."

if is_termux; then
    if command -v python >/dev/null 2>&1; then
        PYTHON_PATH="$(command -v python)"
        if "$PYTHON_PATH" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
            PYTHON_FOUND_VERSION=$($PYTHON_PATH --version 2>/dev/null)
            echo -e "${GREEN}✓${NC} $PYTHON_FOUND_VERSION found"
        else
            echo -e "${RED}✗${NC} Termux Python must be 3.11+"
            echo "    Run: pkg install python"
            exit 1
        fi
    else
        echo -e "${RED}✗${NC} Python not found in Termux"
        echo "    Run: pkg install python"
        exit 1
    fi
else
    if $UV_CMD python find "$PYTHON_VERSION" &> /dev/null; then
        PYTHON_PATH=$($UV_CMD python find "$PYTHON_VERSION")
        PYTHON_FOUND_VERSION=$($PYTHON_PATH --version 2>/dev/null)
        echo -e "${GREEN}✓${NC} $PYTHON_FOUND_VERSION found"
    else
        echo -e "${CYAN}→${NC} Python $PYTHON_VERSION not found, installing via uv..."
        $UV_CMD python install "$PYTHON_VERSION"
        PYTHON_PATH=$($UV_CMD python find "$PYTHON_VERSION")
        PYTHON_FOUND_VERSION=$($PYTHON_PATH --version 2>/dev/null)
        echo -e "${GREEN}✓${NC} $PYTHON_FOUND_VERSION installed"
    fi
fi

# ============================================================================
# Virtual environment
# ============================================================================

echo -e "${CYAN}→${NC} Setting up virtual environment..."

if [ -d "venv" ]; then
    echo -e "${CYAN}→${NC} Removing old venv..."
    rm -rf venv
fi

if is_termux; then
    "$PYTHON_PATH" -m venv venv
    echo -e "${GREEN}✓${NC} venv created with stdlib venv"
else
    $UV_CMD venv venv --python "$PYTHON_VERSION"
    echo -e "${GREEN}✓${NC} venv created (Python $PYTHON_VERSION)"
fi

export VIRTUAL_ENV="$SCRIPT_DIR/venv"
SETUP_PYTHON="$SCRIPT_DIR/venv/bin/python"

# ============================================================================
# Dependencies
# ============================================================================

echo -e "${CYAN}→${NC} Installing dependencies..."

if is_termux; then
    export ANDROID_API_LEVEL="$(getprop ro.build.version.sdk 2>/dev/null || printf '%s' "${ANDROID_API_LEVEL:-}")"
    echo -e "${CYAN}→${NC} Termux detected — installing the tested Android bundle"
    # A7: the Termux pip path is version-constrained (constraints-termux.txt),
    # NOT hash-locked (--require-hashes), so a compromised wheel/sdist that still
    # satisfies the version pin would not be rejected, and no committed hashed
    # graph exists. Under the secure default this whole path is disabled — it
    # EXITS BEFORE any pip upgrade/install unless the operator opted into
    # unverified bootstrap (--allow-unverified-bootstrap), or a committed
    # --require-hashes graph is present.
    _termux_hashed_graph="requirements-termux.hashes.txt"
    if [ "${_HERMES_SC_BOOTSTRAP_OVERRIDE:-}" != "1" ] && \
       ! { [ -f "$_termux_hashed_graph" ] && grep -q -- '--hash=sha256:' "$_termux_hashed_graph" 2>/dev/null; }; then
        echo -e "${RED}✗${NC} Termux dependency install is disabled by default (supply-chain enforce): the Android pip path is version-constrained, not hash-locked, and no --require-hashes graph is committed."
        echo -e "${CYAN}→${NC} Provision a hash-locked Termux venv yourself, or re-run: ./setup-hermes.sh --allow-unverified-bootstrap. See docs/security/supply-chain-migration.md"
        exit 1
    fi
    "$SETUP_PYTHON" -m pip install --upgrade pip setuptools wheel
    # Supply-chain (WP4): the constrained install (constraints-termux.txt) is
    # authoritative. Unconstrained/unpinned fallbacks re-resolve fresh from PyPI
    # and are disabled by default — they require --allow-unverified-bootstrap.
    if [ -f "constraints-termux.txt" ]; then
        if "$SETUP_PYTHON" -m pip install -e ".[termux]" -c constraints-termux.txt; then
            echo -e "${GREEN}✓${NC} Dependencies installed (constraints-termux.txt)"
        elif [ "${_HERMES_SC_BOOTSTRAP_OVERRIDE:-}" = "1" ]; then
            echo -e "${YELLOW}⚠${NC} Termux bundle install failed; --allow-unverified-bootstrap set — base install (unpinned)"
            "$SETUP_PYTHON" -m pip install -e "." -c constraints-termux.txt
        else
            echo -e "${RED}✗${NC} Termux dependency install failed and the unpinned fallback is disabled by default (supply-chain enforce)."
            echo -e "${CYAN}→${NC} Re-run: ./setup-hermes.sh --allow-unverified-bootstrap (see docs/security/supply-chain-migration.md)"
            exit 1
        fi
    elif [ "${_HERMES_SC_BOOTSTRAP_OVERRIDE:-}" = "1" ]; then
        echo -e "${YELLOW}⚠${NC} constraints-termux.txt missing; --allow-unverified-bootstrap set — unpinned install"
        "$SETUP_PYTHON" -m pip install -e ".[termux]" || "$SETUP_PYTHON" -m pip install -e "."
        echo -e "${GREEN}✓${NC} Dependencies installed (unpinned)"
    else
        echo -e "${RED}✗${NC} constraints-termux.txt missing and an unpinned install is disabled by default (supply-chain enforce)."
        echo -e "${CYAN}→${NC} Restore constraints-termux.txt or re-run ./setup-hermes.sh --allow-unverified-bootstrap. See docs/security/supply-chain-migration.md"
        exit 1
    fi
else
    # Supply-chain (WP4): `uv sync --extra all --locked` (hash-verified) is the
    # authoritative install. The unhashed pip re-resolve fallback re-resolves
    # transitives fresh from PyPI and is disabled by default — it requires
    # --allow-unverified-bootstrap. No bare/ranged/unhashed fallback runs under
    # the secure default.
    _BROKEN_EXTRAS=()  # populate when an extra becomes unresolvable
    _ALL_EXTRAS=(
        modal daytona vercel messaging matrix cron cli dev tts-premium slack
        pty honcho mcp homeassistant sms acp voice dingtalk feishu google
        bedrock web youtube
    )
    _SAFE_EXTRAS=()
    for _e in "${_ALL_EXTRAS[@]}"; do
        _skip=false
        for _b in "${_BROKEN_EXTRAS[@]}"; do
            [ "$_e" = "$_b" ] && _skip=true && break
        done
        [ "$_skip" = false ] && _SAFE_EXTRAS+=("$_e")
    done
    _SAFE_SPEC=".[$(IFS=,; echo "${_SAFE_EXTRAS[*]}")]"
    _try_install() {
        $UV_CMD pip install -e ".[all]" \
            || $UV_CMD pip install -e "$_SAFE_SPEC" \
            || $UV_CMD pip install -e "."
    }
    _unhashed_fallback() {
        if [ "${_HERMES_SC_BOOTSTRAP_OVERRIDE:-}" = "1" ]; then
            echo -e "${YELLOW}⚠${NC} --allow-unverified-bootstrap set — re-resolving from PyPI (transitives NOT hash-verified)."
            _try_install
            echo -e "${GREEN}✓${NC} Dependencies installed (transitives re-resolved, not hash-verified)"
        else
            echo -e "${RED}✗${NC} Hash-verified install unavailable and the unhashed fallback is disabled by default (supply-chain enforce)."
            echo -e "${CYAN}→${NC} Restore/refresh uv.lock (uv lock), or re-run ./setup-hermes.sh --allow-unverified-bootstrap."
            echo -e "${CYAN}→${NC} See docs/security/supply-chain-migration.md"
            exit 1
        fi
    }

    if [ -f "uv.lock" ]; then
        echo -e "${CYAN}→${NC} Using uv.lock for hash-verified installation..."
        echo -e "${CYAN}→${NC} (first run on a fresh venv can take 1-5 minutes; uv prints progress below)"
        if UV_PROJECT_ENVIRONMENT="$SCRIPT_DIR/venv" $UV_CMD sync --extra all --locked; then
            echo -e "${GREEN}✓${NC} Dependencies installed (hash-verified via uv.lock)"
        else
            echo -e "${YELLOW}⚠${NC} Lockfile sync failed (see uv output above)."
            _unhashed_fallback
        fi
    else
        echo -e "${YELLOW}⚠${NC} uv.lock not found."
        _unhashed_fallback
    fi
fi

# ============================================================================
# ============================================================================
# Optional: ripgrep (for faster file search)
# ============================================================================

echo -e "${CYAN}→${NC} Checking ripgrep (optional, for faster search)..."

if command -v rg &> /dev/null; then
    echo -e "${GREEN}✓${NC} ripgrep found"
else
    echo -e "${YELLOW}⚠${NC} ripgrep not found (file search will use grep fallback)"
    read -p "Install ripgrep for faster search? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        INSTALLED=false

        if is_termux; then
            pkg install -y ripgrep && INSTALLED=true
        else
            # Check if sudo is available
            if command -v sudo &> /dev/null && sudo -n true 2>/dev/null; then
                if command -v apt &> /dev/null; then
                    sudo apt install -y ripgrep && INSTALLED=true
                elif command -v dnf &> /dev/null; then
                    sudo dnf install -y ripgrep && INSTALLED=true
                fi
            fi

            # Try brew (no sudo needed)
            if [ "$INSTALLED" = false ] && command -v brew &> /dev/null; then
                brew install ripgrep && INSTALLED=true
            fi

            # Try cargo (no sudo needed)
            if [ "$INSTALLED" = false ] && command -v cargo &> /dev/null; then
                echo -e "${CYAN}→${NC} Trying cargo install (no sudo required)..."
                cargo install ripgrep && INSTALLED=true
            fi
        fi

        if [ "$INSTALLED" = true ]; then
            echo -e "${GREEN}✓${NC} ripgrep installed"
        else
            echo -e "${YELLOW}⚠${NC} Auto-install failed. Install options:"
            if is_termux; then
                echo "    pkg install ripgrep          # Termux / Android"
            else
                echo "    sudo apt install ripgrep     # Debian/Ubuntu"
                echo "    brew install ripgrep         # macOS"
                echo "    cargo install ripgrep        # With Rust (no sudo)"
            fi
            echo "    https://github.com/BurntSushi/ripgrep#installation"
        fi
    fi
fi

# ============================================================================
# Environment file
# ============================================================================

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        # .env holds API keys — restrict to owner-only access (matches
        # scripts/install.sh which already chmods 600 after creation).
        chmod 600 .env 2>/dev/null || true
        echo -e "${GREEN}✓${NC} Created .env from template"
    fi
else
    # Tighten an existing .env's perms in case it was created elsewhere
    # under a permissive umask.
    chmod 600 .env 2>/dev/null || true
    echo -e "${GREEN}✓${NC} .env exists"
fi

# ============================================================================
# PATH setup — symlink hermes into a user-facing bin dir
# ============================================================================

echo -e "${CYAN}→${NC} Setting up hermes command..."

HERMES_BIN="$SCRIPT_DIR/venv/bin/hermes"
COMMAND_LINK_DIR="$(get_command_link_dir)"
COMMAND_LINK_DISPLAY_DIR="$(get_command_link_display_dir)"
mkdir -p "$COMMAND_LINK_DIR"
ln -sf "$HERMES_BIN" "$COMMAND_LINK_DIR/hermes"
echo -e "${GREEN}✓${NC} Symlinked hermes → $COMMAND_LINK_DISPLAY_DIR/hermes"

if is_termux; then
    export PATH="$COMMAND_LINK_DIR:$PATH"
    echo -e "${GREEN}✓${NC} $COMMAND_LINK_DISPLAY_DIR is already on PATH in Termux"
else
    # Determine the appropriate shell config file
    SHELL_CONFIG=""
    if [[ "$SHELL" == *"zsh"* ]]; then
        SHELL_CONFIG="$HOME/.zshrc"
    elif [[ "$SHELL" == *"bash"* ]]; then
        SHELL_CONFIG="$HOME/.bashrc"
        [ ! -f "$SHELL_CONFIG" ] && SHELL_CONFIG="$HOME/.bash_profile"
    else
        # Fallback to checking existing files
        if [ -f "$HOME/.zshrc" ]; then
            SHELL_CONFIG="$HOME/.zshrc"
        elif [ -f "$HOME/.bashrc" ]; then
            SHELL_CONFIG="$HOME/.bashrc"
        elif [ -f "$HOME/.bash_profile" ]; then
            SHELL_CONFIG="$HOME/.bash_profile"
        fi
    fi

    if [ -n "$SHELL_CONFIG" ]; then
        # Touch the file just in case it doesn't exist yet but was selected
        touch "$SHELL_CONFIG" 2>/dev/null || true

        if ! echo "$PATH" | tr ':' '\n' | grep -q "^$HOME/.local/bin$"; then
            if ! grep -q '\.local/bin' "$SHELL_CONFIG" 2>/dev/null; then
                echo "" >> "$SHELL_CONFIG"
                echo "# Hermes Agent — ensure ~/.local/bin is on PATH" >> "$SHELL_CONFIG"
                echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_CONFIG"
                echo -e "${GREEN}✓${NC} Added ~/.local/bin to PATH in $SHELL_CONFIG"
            else
                echo -e "${GREEN}✓${NC} ~/.local/bin already in $SHELL_CONFIG"
            fi
        else
            echo -e "${GREEN}✓${NC} ~/.local/bin already on PATH"
        fi
    fi
fi

# ============================================================================
# Seed bundled skills into ~/.hermes/skills/
# ============================================================================

HERMES_SKILLS_DIR="${HERMES_HOME:-$HOME/.hermes}/skills"
mkdir -p "$HERMES_SKILLS_DIR"

echo ""
echo "Syncing bundled skills to ~/.hermes/skills/ ..."
if "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/tools/skills_sync.py" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Skills synced"
else
    # Fallback: copy if sync script fails (missing deps, etc.)
    if [ -d "$SCRIPT_DIR/skills" ]; then
        cp -rn "$SCRIPT_DIR/skills/"* "$HERMES_SKILLS_DIR/" 2>/dev/null || true
        echo -e "${GREEN}✓${NC} Skills copied"
    fi
fi

# ============================================================================
# Done
# ============================================================================

echo ""
echo -e "${GREEN}✓ Setup complete!${NC}"
echo ""
echo "Next steps:"
echo ""
if is_termux; then
    echo "  1. Run the setup wizard to configure API keys:"
    echo "     hermes setup"
    echo ""
    echo "  2. Start chatting:"
    echo "     hermes"
    echo ""
else
    echo "  1. Reload your shell:"
    echo "     source $SHELL_CONFIG"
    echo ""
    echo "  2. Run the setup wizard to configure API keys:"
    echo "     hermes setup"
    echo ""
    echo "  3. Start chatting:"
    echo "     hermes"
    echo ""
fi
echo "Other commands:"
echo "  hermes status        # Check configuration"
if is_termux; then
    echo "  hermes gateway       # Run gateway in foreground"
else
    echo "  hermes gateway install # Install gateway service (messaging + cron)"
fi
echo "  hermes cron list     # View scheduled jobs"
echo "  hermes doctor        # Diagnose issues"
echo ""

# Ask if they want to run setup wizard now
read -p "Would you like to run the setup wizard now? [Y/n] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    echo ""
    # Run directly with venv Python (no activation needed)
    "$SCRIPT_DIR/venv/bin/python" -m hermes_cli.main setup
fi
