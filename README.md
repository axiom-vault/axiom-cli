<h1 align="center">AxiomVault CLI</h1>

<p align="center">
  Command-line interface for AxiomVault — cross-platform encrypted vault with client-side encryption, built in Rust.
</p>

<p align="center">
  <a href="https://github.com/axiom-vault/axiom-cli/actions/workflows/rust-ci.yml"><img src="https://github.com/axiom-vault/axiom-cli/actions/workflows/rust-ci.yml/badge.svg" alt="Rust CI"></a>
  <a href="https://github.com/axiom-vault/axiom-cli/actions/workflows/pr-check.yml"><img src="https://github.com/axiom-vault/axiom-cli/actions/workflows/pr-check.yml/badge.svg" alt="PR Check"></a>
  <a href="https://github.com/axiom-vault/axiom-cli/releases/latest"><img src="https://img.shields.io/github/v/release/axiom-vault/axiom-cli?include_prereleases" alt="Latest Release"></a>
  <a href="https://github.com/axiom-vault/axiom-cli/blob/main/LICENSE"><img src="https://img.shields.io/github/license/axiom-vault/axiom-cli" alt="License"></a>
</p>

---

> [!WARNING]
> This project is in **early development** and is **not production ready**. APIs may change, features may be incomplete. Do not use for storing sensitive data in production.

## Overview

`axiomvault` is the command-line client for [AxiomVault](https://github.com/axiom-vault/axiom-core). It encrypts your files locally before they touch any cloud service, powered by the Rust core library.

**Core library:** [axiom-vault/axiom-core](https://github.com/axiom-vault/axiom-core)

## Installation

### Quick install (Linux & macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/axiom-vault/axiom-cli/main/install.sh | bash
```

The script auto-detects your OS and architecture, downloads the matching prebuilt binary from GitHub Releases, verifies its SHA-256 checksum, and installs it to `/usr/local/bin` (or `~/.local/bin` if `/usr/local/bin` is not writable).

### Prebuilt binaries

Download the right tarball from [Releases](https://github.com/axiom-vault/axiom-cli/releases/latest):

| Platform | Asset |
|----------|-------|
| Linux x86_64 | `axiomvault-x86_64-unknown-linux-gnu.tar.gz` |
| Linux arm64 | `axiomvault-aarch64-unknown-linux-gnu.tar.gz` |
| macOS x86_64 | `axiomvault-x86_64-apple-darwin.tar.gz` |
| macOS arm64 (M-series) | `axiomvault-aarch64-apple-darwin.tar.gz` |

Each release also ships a `SHA256SUMS` file. Example for Linux x86_64:

```bash
curl -L https://github.com/axiom-vault/axiom-cli/releases/latest/download/axiomvault-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv axiomvault /usr/local/bin/
```

### Debian / Ubuntu (.deb)

```bash
# Download and install the .deb for x86_64
curl -LO https://github.com/axiom-vault/axiom-cli/releases/latest/download/axiomvault-x86_64-unknown-linux-gnu.deb
sudo dpkg -i axiomvault-x86_64-unknown-linux-gnu.deb
```

### RPM-based (Fedora, RHEL, openSUSE)

```bash
# Download and install the .rpm for x86_64
curl -LO https://github.com/axiom-vault/axiom-cli/releases/latest/download/axiomvault-x86_64-unknown-linux-gnu.rpm
sudo rpm -i axiomvault-x86_64-unknown-linux-gnu.rpm
```

### Homebrew (macOS & Linux)

```bash
brew tap axiom-vault/tap
brew install axiomvault
```

The Homebrew formula is published from the [`axiom-vault/homebrew-tap`](https://github.com/axiom-vault/homebrew-tap) repository after each stable release.

### AUR (Arch Linux)

```bash
# Using an AUR helper such as yay:
yay -S axiomvault-bin
```

> **Note:** An AUR package (`axiomvault-bin`) is planned. Track progress in the GitHub Issues.

### From source (cargo)

```bash
# Requires Rust stable. The git dependency on axiom-core is not yet on crates.io.
cargo install --git https://github.com/axiom-vault/axiom-cli axiomvault-cli
```

## Build from Source

Requires the [Rust](https://rustup.rs/) stable toolchain.

```bash
git clone https://github.com/axiom-vault/axiom-cli.git
cd axiom-cli
cargo build --release
```

The binary is produced at `target/release/axiomvault`.

## Usage

```bash
# Create a vault
axiomvault create --name MyVault --path ~/my-vault

# Add files
axiomvault add --vault-path ~/my-vault --source ~/secret.pdf --dest /secret.pdf

# List contents
axiomvault list --vault-path ~/my-vault

# Extract files
axiomvault extract --vault-path ~/my-vault --source /secret.pdf --dest ~/secret.pdf

# Interactive session
axiomvault open --path ~/my-vault
```

### Google Drive

```bash
# Authenticate (opens browser)
axiomvault gdrive-auth --output ~/gdrive-tokens.json

# Create vault on Drive
axiomvault gdrive-create --name CloudVault \
    --folder-id YOUR_FOLDER_ID \
    --tokens ~/gdrive-tokens.json

# Open cloud vault
axiomvault gdrive-open --folder-id YOUR_FOLDER_ID \
    --tokens ~/gdrive-tokens.json
```

### Sync

```bash
axiomvault sync --vault-path ~/my-vault --strategy keep-both
axiomvault sync-status --vault-path ~/my-vault
axiomvault sync-configure --vault-path ~/my-vault --mode periodic --interval 300
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `create` | Create a new encrypted vault |
| `open` | Open vault interactively |
| `info` | Display vault information |
| `list` | List vault contents |
| `add` | Add file to vault |
| `extract` | Extract file from vault |
| `mkdir` | Create directory in vault |
| `remove` | Remove file or directory |
| `change-password` | Change vault password |
| `gdrive-auth` | Authenticate with Google Drive |
| `gdrive-create` | Create vault on Google Drive |
| `gdrive-open` | Open vault from Google Drive |
| `sync` | Synchronize vault with remote |
| `sync-status` | Show sync status |
| `sync-configure` | Configure sync behavior |

**KDF strength levels:**

```
--strength interactive   # ~0.5s, mobile-friendly (64 MiB, 3 iterations)
--strength moderate      # ~1s, balanced (default, 32 MiB, 3 iterations)
--strength sensitive     # ~3s, high security (256 MiB, 4 iterations)
```

## Development

```bash
cargo fmt --all                    # Format
cargo clippy -- -D warnings        # Lint
cargo test                         # Test
```

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push and open a pull request

All PRs must pass CI checks (formatting, clippy, tests) before merging.

## License

[Apache 2.0](LICENSE)