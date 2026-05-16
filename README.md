<h1 align="center">AxiomVault CLI</h1>

<p align="center">
  Command-line interface for AxiomVault — cross-platform encrypted vault with client-side encryption, built in Rust.
</p>

## Installation

### Prebuilt binaries

Release artifacts are published on GitHub Releases.

- Linux: `.tar.gz`, `.deb`, `.rpm`
- macOS: `.tar.gz`

### Homebrew (macOS/Linux)

```bash
brew tap axiom-vault/tap
brew install axiom
```

### Arch Linux (AUR)

```bash
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

# YubiKey challenge-response bytes via env (plain UTF-8 or hex:...)
# Prompt once, then scope the response to each command instead of exporting it
read -rsp "YubiKey response: " AXIOM_YUBIKEY_RESPONSE; printf '\n'
AXIOM_YUBIKEY_RESPONSE="$AXIOM_YUBIKEY_RESPONSE" axiom hardware-key enroll --path ~/my-vault --label 'desk yubikey' --key-id slot-2
axiom hardware-key status --path ~/my-vault
AXIOM_YUBIKEY_RESPONSE="$AXIOM_YUBIKEY_RESPONSE" axiom hardware-key test --path ~/my-vault
AXIOM_YUBIKEY_RESPONSE="$AXIOM_YUBIKEY_RESPONSE" axiom hardware-key open --path ~/my-vault
unset AXIOM_YUBIKEY_RESPONSE

# Mount as a filesystem (when built with --features fuse)
mkdir -p ~/my-vault-mount
axiom mount fuse --path ~/my-vault ~/my-vault-mount
```

### Hardware-key env source

For now the CLI reads YubiKey challenge-response bytes from `AXIOM_YUBIKEY_RESPONSE` or `AXIOM_HARDWARE_KEY_RESPONSE`, so a physical device is not required during development and testing.

Prefer a one-shot env assignment or a prompt like the example above instead of `export` in shared shells, scripts, or long-lived terminals.

Accepted formats:

- raw UTF-8 bytes, for example `simulated-yubikey-response`
- hex with a `hex:` prefix, for example `hex:736563726574`

### Google Drive

```bash
axiom remote gdrive auth --output ~/gdrive-tokens.json
axiom remote gdrive create --name CloudVault --folder-id YOUR_FOLDER_ID --tokens ~/gdrive-tokens.json
axiom remote gdrive open --folder-id YOUR_FOLDER_ID --tokens ~/gdrive-tokens.json
```

### Dropbox

```bash
axiom remote dropbox auth --output ~/dropbox-tokens.json
axiom remote dropbox create --name CloudVault --root-path /AxiomVault --tokens ~/dropbox-tokens.json
axiom remote dropbox open --root-path /AxiomVault --tokens ~/dropbox-tokens.json
```

`remote dropbox auth` accepts `--app-key` / `--app-secret` or falls back to `AXIOM_DROPBOX_APP_KEY` / `AXIOM_DROPBOX_APP_SECRET`. The legacy `AXIOMVAULT_DROPBOX_APP_KEY` / `AXIOMVAULT_DROPBOX_APP_SECRET` names remain supported.

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
| `hardware-key enroll` | Enroll env-sourced YubiKey challenge-response bytes for a local vault |
| `hardware-key status` | Show local vault hardware-key enrollment status |
| `hardware-key remove` | Remove the enrolled local vault hardware key |
| `hardware-key test` | Verify `AXIOM_YUBIKEY_RESPONSE` or `AXIOM_HARDWARE_KEY_RESPONSE` against a local vault |
| `hardware-key open` | Open a local vault with `AXIOM_YUBIKEY_RESPONSE` or `AXIOM_HARDWARE_KEY_RESPONSE` |
| `remote gdrive auth` | Authenticate with Google Drive |
| `remote gdrive create` | Create vault on Google Drive |
| `remote gdrive open` | Open vault from Google Drive |
| `remote dropbox auth` | Authenticate with Dropbox |
| `remote dropbox create` | Create vault on Dropbox |
| `remote dropbox open` | Open vault from Dropbox |
| `remote icloud` | Placeholder for future iCloud remote support |
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
--strength moderate # ~1s, balanced (default, 32 MiB, 3 iterations)
--strength sensitive # ~3s, high security (256 MiB, 4 iterations)
```

## Development

```bash
cargo fmt --all
cargo clippy -- -D warnings
cargo test
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
