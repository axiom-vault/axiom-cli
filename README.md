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

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) stable toolchain

### Build

```bash
git clone https://github.com/axiom-vault/axiom-cli.git
cd axiom-cli
cargo build --release
```

The binary is produced at `target/release/axiomvault`.

### Usage

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