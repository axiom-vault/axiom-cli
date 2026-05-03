#!/usr/bin/env bash
# install.sh — AxiomVault CLI installer
#
# Downloads the prebuilt binary for the current platform from GitHub Releases,
# verifies its SHA-256 checksum, and installs it to /usr/local/bin or ~/.local/bin.

set -euo pipefail

REPO="axiom-vault/axiom-cli"
BIN_NAME="axiomvault"
GITHUB_API="https://api.github.com/repos/${REPO}/releases"
INCLUDE_PRERELEASES=0
INSTALL_DIR_OVERRIDE=""
COMPLETIONS_SHELL=""

# ── helpers ───────────────────────────────────────────────────────────────────

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
note() { printf '\033[1;34mnote:\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
AxiomVault CLI installer

Usage:
  ./install.sh [OPTIONS]
  curl -fsSL https://raw.githubusercontent.com/axiom-vault/axiom-cli/main/install.sh | bash

Options:
  -h, --help              Show this help message and exit
  -v, --version VERSION   Install a specific release tag, e.g. v0.1.0-beta.2
      --prerelease        Allow installing the latest prerelease when no stable release exists
      --dir DIR           Install into DIR instead of /usr/local/bin or ~/.local/bin
      --completions SHELL Install shell completions after installing the binary
                          Supported shells: bash, fish, zsh

Environment:
  AXIOMVAULT_VERSION      Same as --version
  AXIOMVAULT_PRERELEASE   Set to 1/true/yes to allow latest prerelease fallback
  AXIOMVAULT_INSTALL_DIR  Same as --dir
  AXIOMVAULT_COMPLETIONS   Same as --completions

Examples:
  ./install.sh --help
  ./install.sh --version v0.1.0-beta.2
  ./install.sh --prerelease
  ./install.sh --version v0.1.0-beta.2 --completions zsh
  AXIOMVAULT_INSTALL_DIR="$HOME/.local/bin" ./install.sh --version v0.1.0-beta.2

By default, this installer only installs stable GitHub Releases. If this project
has not published a stable release yet, choose an explicit --version or pass
--prerelease to install the latest prerelease.
EOF
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed."
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                [ "$#" -ge 2 ] || die "--version requires a value."
                AXIOMVAULT_VERSION="$2"
                shift 2
                ;;
            --version=*)
                AXIOMVAULT_VERSION="${1#*=}"
                shift
                ;;
            --prerelease)
                INCLUDE_PRERELEASES=1
                shift
                ;;
            --dir)
                [ "$#" -ge 2 ] || die "--dir requires a value."
                INSTALL_DIR_OVERRIDE="$2"
                shift 2
                ;;
            --dir=*)
                INSTALL_DIR_OVERRIDE="${1#*=}"
                shift
                ;;
            --completions)
                [ "$#" -ge 2 ] || die "--completions requires a shell: bash, fish, or zsh."
                COMPLETIONS_SHELL="$2"
                shift 2
                ;;
            --completions=*)
                COMPLETIONS_SHELL="${1#*=}"
                shift
                ;;
            *)
                die "Unknown option: $1. Run ./install.sh --help for usage."
                ;;
        esac
    done

    if [ -n "${AXIOMVAULT_INSTALL_DIR:-}" ]; then
        INSTALL_DIR_OVERRIDE="${AXIOMVAULT_INSTALL_DIR}"
    fi

    if [ -n "${AXIOMVAULT_COMPLETIONS:-}" ]; then
        COMPLETIONS_SHELL="${AXIOMVAULT_COMPLETIONS}"
    fi

    if [ -n "${COMPLETIONS_SHELL}" ]; then
        case "${COMPLETIONS_SHELL}" in
            bash|fish|zsh) ;;
            *) die "Unsupported completions shell '${COMPLETIONS_SHELL}'. Supported shells: bash, fish, zsh." ;;
        esac
    fi

    case "${AXIOMVAULT_PRERELEASE:-}" in
        1|true|TRUE|yes|YES) INCLUDE_PRERELEASES=1 ;;
    esac
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

extract_first_tag() {
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1
}

resolve_version() {
    if [ -n "${AXIOMVAULT_VERSION:-}" ]; then
        echo "${AXIOMVAULT_VERSION}"
        return
    fi

    need curl

    latest_json="$(curl -sfL "${GITHUB_API}/latest" 2>/dev/null || true)"
    latest_tag="$(printf '%s\n' "${latest_json}" | extract_first_tag)"
    if [ -n "${latest_tag}" ]; then
        echo "${latest_tag}"
        return
    fi

    if [ "${INCLUDE_PRERELEASES}" -eq 1 ]; then
        releases_json="$(curl -sfL "${GITHUB_API}" 2>/dev/null || true)"
        prerelease_tag="$(printf '%s\n' "${releases_json}" | extract_first_tag)"
        [ -n "${prerelease_tag}" ] || die "No GitHub Releases found for ${REPO}."
        note "No stable release found; installing latest prerelease ${prerelease_tag}."
        echo "${prerelease_tag}"
        return
    fi

    die "No stable release found for ${REPO}. Run './install.sh --help' and either pass --version <tag> or --prerelease."
}

# ── install directory ─────────────────────────────────────────────────────────

install_completions() {
    [ -n "${COMPLETIONS_SHELL}" ] || return 0

    say "Installing ${COMPLETIONS_SHELL} completions..."
    "${INSTALL_DIR}/${BIN_NAME}" completions "${COMPLETIONS_SHELL}" --install
}

completion_hint_shell() {
    case "$(basename "${SHELL:-}")" in
        bash|fish|zsh) basename "${SHELL}" ;;
        *) echo "" ;;
    esac
}

print_completion_hint() {
    [ -z "${COMPLETIONS_SHELL}" ] || return 0

    hint_shell="$(completion_hint_shell)"
    echo ""
    if [ -n "${hint_shell}" ]; then
        note "Shell completions are available. Enable them with:"
        note "  ${BIN_NAME} completions ${hint_shell} --install"
        note "Or rerun this installer with: ./install.sh --completions ${hint_shell}"
    else
        note "Shell completions are available for bash, fish, and zsh."
        note "Run: ${BIN_NAME} completions <shell> --install"
    fi
}

pick_install_dir() {
    if [ -n "${INSTALL_DIR_OVERRIDE}" ]; then
        echo "${INSTALL_DIR_OVERRIDE}"
    elif [ -w /usr/local/bin ]; then
        echo "/usr/local/bin"
    elif [ -n "${HOME:-}" ]; then
        echo "${HOME}/.local/bin"
    else
        die "Cannot determine a writable install directory."
    fi
}

# ── main ──────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    need curl
    need tar
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 \
        || die "Neither 'sha256sum' nor 'shasum' is installed."

    OS="$(detect_os)"
    ARCH="$(detect_arch)"
    TARGET="${ARCH}-${OS}"
    VERSION="$(resolve_version)"

    [ -n "$VERSION" ] || die "Could not determine the release version."

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

    install_completions

    say "Done! ${BIN_NAME} ${VERSION} installed."

    print_completion_hint

    if [[ "${INSTALL_DIR}" == *"/.local/bin" ]]; then
        case ":${PATH:-}:" in
            *":${INSTALL_DIR}:"*) ;;
            *)
                echo ""
                warn "${INSTALL_DIR} is not in your PATH."
                warn "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
                warn "  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
                ;;
        esac
    fi
}

main "$@"
