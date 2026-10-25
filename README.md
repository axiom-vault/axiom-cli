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

# YubiKey challenge-response: prompted with echo off, hex:... with at least 16 bytes
axiom hardware-key enroll --path ~/my-vault --label 'desk yubikey' --key-id slot-2
axiom hardware-key status --path ~/my-vault
axiom hardware-key test --path ~/my-vault
axiom hardware-key open --path ~/my-vault

# Mount as a filesystem (when built with --features fuse)
mkdir -p ~/my-vault-mount
axiom mount fuse --path ~/my-vault ~/my-vault-mount
```

### Hardware-key response

`hardware-key enroll`, `test` and `open` prompt for the YubiKey challenge-response bytes and read them from the terminal with echo off.
The response is never read from an environment variable: `AXIOM_YUBIKEY_RESPONSE` and `AXIOM_HARDWARE_KEY_RESPONSE` are ignored.

The response must be hex with a `hex:` prefix and decode to at least 16 bytes (32 hex digits).
A real YubiKey HMAC-SHA1 response is 20 bytes, for example `hex:5f3a9c0e7b21d4486a0c93f1e2b7d65804a1c3e9`.
Whitespace and underscores between hex digits are ignored.
Plain UTF-8 strings, such as a typed passphrase, are rejected, because they do not carry enough entropy to protect the vault key.

### Non-interactive password

Passwords are never read from environment variables; `AXIOM_PASSWORD` and `AXIOMVAULT_PASSWORD` are ignored.
For scripts, pass the password that opens an existing vault in a file with the global `--password-file <PATH>` flag, before or after the subcommand:

```bash
(umask 077; read -rsp 'Vault password: ' pw; printf '\n'; printf '%s\n' "$pw" > ~/.axiom-pw)
axiom --password-file ~/.axiom-pw file list --vault-path ~/my-vault
axiom file list --vault-path ~/my-vault --password-file ~/.axiom-pw
```

- The file must be a regular file with no group or other permissions (`chmod 600`); otherwise it is refused.
- Its bytes are used as-is, except that exactly one trailing `\n` or `\r\n` is stripped. An empty password is refused.
- New passwords (`vault create`, `remote gdrive create`, and the new password for `password change` and `password reset`) are always prompted.
- Without a terminal and without `--password-file`, the command fails instead of waiting for input.
- Unix only; on other platforms `--password-file` is refused.

### LLM access through the agent (Unix)

`axiom agent` runs the key-holding agent from axiom-core, so an LLM can use a vault through the MCP server `axiom-mcp` without ever seeing the password or key.
The agent holds the only unlocked session and serves it on a Unix socket; you unlock it from your own terminal.

```bash
axiom agent serve --vault ~/my-vault [--allow-writes] [--root /sub] &
axiom agent unlock   # in your own terminal; reads the password from the terminal only
axiom agent status
axiom agent lock
```

Then configure `axiom-mcp` from [axiom-core](https://github.com/axiom-vault/axiom-core) as the MCP server in your LLM client.
Writes, import/export and the visible subtree are `serve` flags enforced by the agent; `axiom agent --help` lists them.
`--password-file` is not accepted.

This does not isolate the vault from your own user: any process running as your uid can use an unlocked vault within the agent's policy, and the password prompt is only as trustworthy as your shell.
For the threat model and running the agent as a separate user, see [`core/agent/README.md`](https://github.com/axiom-vault/axiom-core/blob/release/2.0/core/agent/README.md).

### Google Drive

```bash
axiom remote gdrive auth --output ~/gdrive-tokens.json
axiom remote gdrive create --name CloudVault --folder-id YOUR_FOLDER_ID --tokens ~/gdrive-tokens.json
axiom remote gdrive open --folder-id YOUR_FOLDER_ID --tokens ~/gdrive-tokens.json
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
| `vault list --root <DIR> [--depth N] [--json]` | Find vaults under DIR and show their unverified plaintext id, version and provider (no password; never opens a vault) |
| `file list` | List vault contents |
| `file add` | Add file to vault |
| `file extract` | Extract file from vault |
| `file mkdir` | Create directory in vault |
| `file remove` | Remove file or directory |
| `password change` | Change vault password |
| `password reset` | Reset vault password |
| `recovery show-key` | Show recovery key |
| `hardware-key enroll` | Enroll a prompted YubiKey challenge-response (hex, at least 16 bytes) for a local vault |
| `hardware-key status` | Show local vault hardware-key enrollment status |
| `hardware-key remove` | Remove the enrolled local vault hardware key |
| `hardware-key test` | Verify a prompted hardware-key response against a local vault |
| `hardware-key open` | Open a local vault with a prompted hardware-key response |
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
| `mount list [--json]` | List your running `mount webdav` servers (listening address or `starting`) and, on Linux, FUSE mounts (Linux, macOS) |
| `mount fuse` | Mount vault as a FUSE filesystem (requires `--features fuse`) |
| `agent serve\|unlock\|lock\|status` | Run and control the key-holding agent for `axiom-mcp` (Unix only) |

**KDF strength levels:**

```text
--strength interactive # ~0.5s, mobile-friendly (64 MiB, 3 iterations)
--strength moderate    # ~1s, balanced (default, 32 MiB, 3 iterations)
--strength sensitive   # ~3s, high security (256 MiB, 4 iterations)
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
