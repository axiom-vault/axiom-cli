#!/usr/bin/env bash
# install.sh — AxiomVault CLI installer
#
# Downloads the prebuilt binary for the current platform from GitHub Releases,
# verifies its SHA-256 checksum, and installs it to /usr/local/bin or ~/.local/bin.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/axiom-vault/axiom-cli/main/install.sh | bash
#   # or with a specific version:
#   AXIOMVAULT_VERSION=v0.1.0 bash install.sh

set -euo pipefail

REPO="axiom-vault/axiom-cli"
BIN_NAME="axiomvault"
GITHUB_API="https://api.github.com/repos/${REPO}/releases"

# ── helpers ───────────────────────────────────────────────────────────────────

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed."
}

# ── platform detection ────────────────────────────────────────────────────────

detect_os() {
    case "$(uname -s)" in
        Linux)  echo "unknown-linux-gnu" ;;
        Darwin) echo "apple-darwin" ;;
        *)      die "Unsupported operating system: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)         echo "x86_64" ;;
        aarch64|arm64)  echo "aarch64" ;;
        *)              die "Unsupported architecture: $(uname -m)" ;;
    esac
}

# ── version resolution ────────────────────────────────────────────────────────

resolve_version() {
    if [ -n "${AXIOMVAULT_VERSION:-}" ]; then
        echo "${AXIOMVAULT_VERSION}"
        return
    fi
    # Fetch latest stable release tag from GitHub API
    need curl
    curl -sfL "${GITHUB_API}/latest" \
        | grep '"tag_name"' \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

# ── install directory ─────────────────────────────────────────────────────────

pick_install_dir() {
    if [ -w /usr/local/bin ]; then
        echo "/usr/local/bin"
    elif [ -n "${HOME:-}" ]; then
        echo "${HOME}/.local/bin"
    else
        die "Cannot determine a writable install directory."
    fi
}

# ── main ──────────────────────────────────────────────────────────────────────

main() {
    need curl
    need tar
    need sha256sum 2>/dev/null || need shasum   # macOS uses shasum

    OS="$(detect_os)"
    ARCH="$(detect_arch)"
    TARGET="${ARCH}-${OS}"
    VERSION="$(resolve_version)"

    [ -n "$VERSION" ] || die "Could not determine the latest release version."

    TARBALL="${BIN_NAME}-${TARGET}.tar.gz"
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

    say "Installing ${BIN_NAME} ${VERSION} (${TARGET})"

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    say "Downloading ${TARBALL}..."
    curl -fsSL "${BASE_URL}/${TARBALL}" -o "${TMPDIR}/${TARBALL}"
    curl -fsSL "${BASE_URL}/SHA256SUMS"  -o "${TMPDIR}/SHA256SUMS"

    say "Verifying checksum..."
    cd "${TMPDIR}"
    if command -v sha256sum >/dev/null 2>&1; then
        grep "${TARBALL}" SHA256SUMS | sha256sum --check --quiet
    else
        # macOS fallback
        EXPECTED=$(grep "${TARBALL}" SHA256SUMS | awk '{print $1}')
        ACTUAL=$(shasum -a 256 "${TARBALL}" | awk '{print $1}')
        [ "${EXPECTED}" = "${ACTUAL}" ] || die "Checksum mismatch for ${TARBALL}"
    fi
    say "Checksum OK"

    say "Extracting binary..."
    tar xzf "${TARBALL}"

    INSTALL_DIR="$(pick_install_dir)"
    mkdir -p "${INSTALL_DIR}"

    say "Installing to ${INSTALL_DIR}/${BIN_NAME}..."
    mv "${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
    chmod +x "${INSTALL_DIR}/${BIN_NAME}"

    say "Done! ${BIN_NAME} ${VERSION} installed."

    # PATH reminder when installing to ~/.local/bin
    if [[ "${INSTALL_DIR}" == *"/.local/bin" ]]; then
        echo ""
        warn "${INSTALL_DIR} may not be in your PATH."
        warn "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        warn "  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
    fi
}

main "$@"
