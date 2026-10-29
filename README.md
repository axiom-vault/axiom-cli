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

# Optional FUSE mount support (see "FUSE mount" below; macOS needs macFUSE)
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

### Vault ID

`vault create`, `remote gdrive create` and `remote dropbox create` give each new vault an ID made of `--name` and a random suffix, for example `MyVault-3f2c9a1e0b7d4c6e8a5f1b2d3c4e5f60`, and print it.
Two vaults created with the same name therefore never share an ID, and a deleted vault can be recreated under its old name at the same path.
Existing vaults keep the ID they were created with.

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
- New passwords (`vault create`, `remote gdrive create`, `remote dropbox create`, and the new password for `password change` and `password reset`) are always prompted.
- Without a terminal and without `--password-file`, the command fails instead of waiting for input.
- Unix only; on other platforms `--password-file` is refused.

### Recovery key

`vault create` shows a 24-word recovery key once.
By default it is printed to the terminal, followed by a "Press Enter" prompt; the key is never printed to a redirected or piped standard output, and the command refuses to run that way.
For scripts, write the key to a new file instead:

```bash
axiom vault create --name MyVault --path ~/my-vault --recovery-out ~/my-vault.recovery </dev/null
```

- The file is created with mode `0600` and must not exist yet; an existing file is never overwritten, and this is checked before the vault is created.
- The words are written space-separated on one line, the format `password reset` asks for. They are not printed and there is no prompt.
- When standard input is not a terminal (a pipe, `</dev/null`, CI, a systemd unit), the "Press Enter" prompt is skipped, so `echo | axiom vault create ...` is no longer needed.
- The new password is still prompted on the terminal (see above).

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

### Dropbox

```bash
axiom remote dropbox auth --output ~/dropbox-tokens.json
axiom remote dropbox create --name CloudVault --root-path /AxiomVault --tokens ~/dropbox-tokens.json
axiom remote dropbox open --root-path /AxiomVault --tokens ~/dropbox-tokens.json
```

`remote dropbox auth` accepts `--app-key` / `--app-secret` or falls back to `AXIOM_DROPBOX_APP_KEY` / `AXIOM_DROPBOX_APP_SECRET`. The legacy `AXIOMVAULT_DROPBOX_APP_KEY` / `AXIOMVAULT_DROPBOX_APP_SECRET` names remain supported. The app key is saved in the token file next to the tokens, so `create` and `open` can refresh the access token after it expires. OAuth token files are only reported as successful after the code exchange and token save complete. On Unix, token files are written atomically with `0600` permissions, and an existing path is replaced only if it already holds Dropbox tokens; on other platforms saving tokens is refused.

### Sync

```bash
axiom sync run --vault-path ~/my-vault --strategy keep-both
axiom sync status --vault-path ~/my-vault
axiom sync configure --vault-path ~/my-vault --mode periodic --interval 300
```

### FUSE mount

Build with `--features fuse`.
On Linux the mount is done in pure Rust: building, including cross-compiling (`cross build --release --target aarch64-unknown-linux-gnu --features fuse --bin axiom`), needs no `libfuse3-dev`, and at runtime only the `fusermount3` binary is needed (package `fuse3` on Debian, Ubuntu and Fedora).
On macOS, building and mounting need macFUSE.

`axiom mount fuse` runs in the foreground until you stop it with Ctrl+C.
To keep it running, start it with `&`, in a terminal multiplexer such as tmux, or as a systemd unit.

## CLI Reference

| Command | Description |
|---------|-------------|
| `vault create [--recovery-out <FILE>]` | Create a new encrypted vault; optionally write the recovery key to a new 0600 file instead of printing it |
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
