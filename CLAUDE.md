# axiom-cli

## Agent notes

- Never open, unlock, list or read a real vault or its password, credentials, recovery words or contents as an agent. Use only synthetic fixtures; the human performs any real-vault password entry privately, without agent observation.
- Use explicit throwaway vault/token/recovery paths in tests; discovery commands and default credential paths can touch the user's state.
- The package is `axiomvault-cli`, but the executable is `axiom` (`Cargo.toml`); build with `cargo build --release` and use `target/release/axiom`.
- FUSE is opt-in (`--features fuse`); default builds omit `mount fuse`. Linux builds use pure Rust and need `fusermount3` at runtime; macOS needs macFUSE (README).
- All axiom-core Git dependencies and lockfile entries must use one exact revision; `scripts/check_core_revisions.py` enforces this to prevent mixed core versions.
- For an intentional integration checkout, `python3 scripts/use_local_core.py ../axiom-core Cargo.toml` rewrites core dependencies to paths. Record the tested checkout and do not commit these temporary rewrites as release pins.
- Keep argument parsing in `src/cli.rs`, routing in `src/dispatch.rs`, and command behavior in `src/commands/`; this is the existing command structure.
- Dispatch `axiom agent` before creating the CLI Tokio runtime/tracing subscriber (`src/main.rs`): the embedded agent creates its own.
- Password environment variables are intentionally ignored. Existing-vault `--password-file` accepts owner-only regular files and raw bytes, stripping one final newline; keep this boundary instead of introducing environment or UTF-8-only password paths (`src/password.rs`).
- New passwords still require a terminal prompt. Synthetic scripted creation uses a new `--recovery-out` path so recovery words do not enter redirected output; do not weaken the stdout/overwrite checks.
- `axiom agent` refuses `--password-file`; a human unlocks it from a terminal. The daemon/MCP policy is not isolation from other processes running as the same user (README).
- Keep OAuth tokens in local private files and pass credential references in vault configuration; do not serialize access/refresh tokens or client secrets into `vault.config` (`gdrive.rs`, `dropbox.rs`).

## Validation

Use the pinned dependency set for normal validation; CI also checks the moving core integration branch separately. Its success does not replace pinned-core checks.

```sh
cargo fmt --all -- --check
cargo check
cargo test --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/check_core_revisions.py Cargo.toml Cargo.lock
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps
```

These commands come from `.github/workflows/{rust-ci,pr-check,core-compatibility}.yml`; include FUSE-enabled checks when changing gated mount code so the default build cannot hide errors.
