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

`axiom` is the command-line client for [AxiomVault](https://github.com/axiom-vault/axiom-core). It encrypts your files locally before they touch any cloud service, powered by the Rust core library.

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
| Linux x86_64 | `axiom-x86_64-unknown-linux-gnu.tar.gz` |
| Linux arm64 | `axiom-aarch64-unknown-linux-gnu.tar.gz` |
| macOS x86_64 | `axiom-x86_64-apple-darwin.tar.gz` |
| macOS arm64 (M-series) | `axiom-aarch64-apple-darwin.tar.gz` |

Each release also ships a `SHA256SUMS` file.

Example for Linux x86_64:

```bash
curl -L https://github.com/axiom-vault/axiom-cli/releases/latest/download/axiom-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv axiom /usr/local/bin/
```

### Debian / Ubuntu (.deb)

```bash
# Download and install the .deb for x86_64
curl -LO https://github.com/axiom-vault/axiom-cli/releases/latest/download/axiom-x86_64-unknown-linux-gnu.deb
sudo dpkg -i axiom-x86_64-unknown-linux-gnu.deb
```

### RPM-based (Fedora, RHEL, openSUSE)

```bash
# Download and install the .rpm for x86_64
curl -LO https://github.com/axiom-vault/axiom-cli/releases/latest/download/axiom-x86_64-unknown-linux-gnu.rpm
sudo rpm -i axiom-x86_64-unknown-linux-gnu.rpm
```

### Homebrew (macOS & Linux)

```bash
brew tap axiom-vault/tap
brew install axiom
```

The Homebrew formula is published from the [`axiom-vault/homebrew-tap`](https://github.com/axiom-vault/homebrew-tap) repository after each stable release.

### AUR (Arch Linux)

```bash
# Using an AUR helper such as yay:
yay -S axiom-bin
```

> **Note:** An AUR package (`axiom-bin`) is planned. Track progress in the GitHub Issues.

### From source (cargo)

```bash
# Requires Rust stable. The git dependency on axiom-core is not yet on crates.io.
cargo install --git https://github.com/axiom-vault/axiom-cli axiomvault-cli --bin axiom

# Optional FUSE mount support (requires libfuse3-dev on Linux or macFUSE on macOS)
cargo install --git https://github.com/axiom-vault/axiom-cli axiomvault-cli --bin axiom --features fuse
```

## Build from Source

Requires the [Rust](https://rustup.rs/) stable toolchain.

```bash
git clone https://github.com/axiom-vault/axiom-cli.git
cd axiom-cli
cargo build --release
```

The binary is produced at `target/release/axiom`.

## Usage

```bash
# Create a vault
axiom vault create --name MyVault --path ~/my-vault

# Add files
axiom file add --vault-path ~/my-vault --source ~/secret.pdf --dest /secret.pdf

# List contents
axiom file list --vault-path ~/my-vault

# Extract files
axiom file extract --vault-path ~/my-vault --source /secret.pdf --dest ~/secret.pdf

# Interactive session
axiom vault open --path ~/my-vault

# Mount as a filesystem (when built with --features fuse)
mkdir -p ~/my-vault-mount
axiom mount fuse --path ~/my-vault ~/my-vault-mount
```

### Google Drive

```bash
# Authenticate (opens browser)
axiom remote gdrive auth --output ~/gdrive-tokens.json

# Create vault on Drive
axiom remote gdrive create --name CloudVault \
  --folder-id YOUR_FOLDER_ID \
  --tokens ~/gdrive-tokens.json

# Open cloud vault
axiom remote gdrive open --folder-id YOUR_FOLDER_ID \
  --tokens ~/gdrive-tokens.json
```

### Sync

```bash
axiom sync run --vault-path ~/my-vault --strategy keep-both
axiom sync status --vault-path ~/my-vault
axiom sync configure --vault-path ~/my-vault --mode periodic --interval 300
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `vault create` | Create a new encrypted vault |
| `vault open` | Open vault interactively |
| `vault info` | Display vault information |
| `vault check` | Check vault health and integrity |
| `vault migrate` | Migrate vault format |
| `file list` | List vault contents |
| `file add` | Add file to vault |
| `file extract` | Extract file from vault |
| `file mkdir` | Create directory in vault |
| `file remove` | Remove file or directory |
| `password change` | Change vault password |
| `password reset` | Reset vault password |
| `recovery show-key` | Show recovery key |
| `recovery enable` | Enable recovery keys for a legacy vault |
| `remote gdrive auth` | Authenticate with Google Drive |
| `remote gdrive create` | Create vault on Google Drive |
| `remote gdrive open` | Open vault from Google Drive |
| `remote icloud` | Placeholder for future iCloud remote support |
| `remote dropbox` | Placeholder for future Dropbox remote support |
| `sync run` | Synchronize vault with remote |
| `sync status` | Show sync status |
| `sync conflicts` | List sync conflicts |
| `sync resolve` | Resolve a sync conflict |
| `sync configure` | Configure sync behavior |
| `raid add-backend` | Add a RAID backend |
| `raid remove-backend` | Remove a RAID backend |
| `raid status` | Show RAID status |
| `raid rebuild` | Rebuild degraded RAID shards |
| `raid configure` | Configure RAID mode |
| `mount webdav` | Serve the vault over WebDAV |
| `mount fuse` | Mount vault as a FUSE filesystem (requires `--features fuse`) |

**KDF strength levels:**

```text
--strength interactive # ~0.5s, mobile-friendly (64 MiB, 3 iterations)
--strength moderate    # ~1s, balanced (default, 32 MiB, 3 iterations)
--strength sensitive   # ~3s, high security (256 MiB, 4 iterations)
```

## Development

```bash
cargo fmt --all      # Format
cargo clippy -- -D warnings  # Lint
cargo test           # Test
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
