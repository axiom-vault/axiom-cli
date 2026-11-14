# Desktop build and core integration

`Cargo.toml` and `Cargo.lock` pin every core crate to the same published core
revision. Normal builds require no local core override. Core includes the shared
`AppService::open_gdrive_vault` value-based entry point and the FUSE rename,
unknown-capacity and download read-stall fixes. CLI owns token-file loading;
refresh remains in core. This work does not add FFI or Android code.

From the CLI repository root:

```sh
cargo build --locked --release
cargo build --locked --release --features fuse --bin axiom
cargo test --locked --all-targets
cargo test --locked --all-targets --features fuse
cargo clippy --locked --all-targets --all-features -- -D warnings
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/check_core_revisions.py Cargo.toml Cargo.lock
```

The FUSE-enabled binary is `target/release/axiom`. Linux mounting requires
`fusermount3`; macOS requires macFUSE. Validation of a mount or cloud provider uses
synthetic fixtures, never a person's real vault or credentials.

When intentionally testing an unreleased core checkout, the compatibility CI
uses `python3 scripts/use_local_core.py ../axiom-core Cargo.toml`. This rewrites
Git dependencies to the checkout paths and changes dependency resolution.
Record the exact core commit tested, keep those temporary rewrites out of release
commits, and run the pinned checks again before release. A passing test against a
local checkout is not proof that the published Git pins resolve correctly.

If using an explicit Cargo override instead, give external `cargo-clippy` its
`--config` argument after `clippy` so the child Cargo invocation receives it.
The normal commands above use the published pin and no override or lint allowance.
