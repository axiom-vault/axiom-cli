set dotenv-load := false

# Show available recipes
default:
 just --list

# Format Rust code
fmt:
 cargo fmt --all

# Check formatting without modifying files
fmt-check:
 cargo fmt --all -- --check

# Lint with warnings treated as errors
lint:
 cargo clippy --all-targets --all-features -- -D warnings

# Type-check the workspace
check:
 cargo check --all-targets --all-features

# Run tests
test:
 cargo test --all-features

# Run format, lint, and tests
ci: fmt-check lint test

# Build debug binary
build:
 cargo build

# Build release binary
release:
 cargo build --release

# Build release binary with FUSE support
release-fuse:
 cargo build --release --features fuse

# Run the CLI, passing arguments after --
run *args:
 cargo run -- {{args}}

# Install the CLI locally
install:
 cargo install --path . --bin axiom

# Generate documentation
doc:
 cargo doc --no-deps --all-features

# Clean build artifacts
clean:
 cargo clean
