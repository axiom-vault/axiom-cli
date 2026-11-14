# Local desktop candidate build

The desktop candidate pairs this CLI branch with local axiom-core commit
`ad88261bdb786925904316a2766c42a1bcf4539f` on `feat/dolphin-gdrive-mount`.
Core supplies the FUSE rename and download-stall fixes. The normal CLI manifest
still pins the public base; a default build alone does not include those fixes.
No candidate commits were pushed.

From the CLI worktree, with the paired core in `../axiom-core`:

```bash
mkdir -p .build-tmp target
python3 - <<'PY' > .build-tmp/local-core.toml
from pathlib import Path
import json, tomllib
core = Path('../axiom-core').resolve()
print('[patch."https://github.com/axiom-vault/axiom-core"]')
for manifest in sorted((core / 'core').glob('*/Cargo.toml')):
    name = tomllib.loads(manifest.read_text())['package']['name']
    print(name + ' = { path = ' + json.dumps(str(manifest.parent)) + ' }')
PY
env TMPDIR="$PWD/.build-tmp" CARGO_TARGET_DIR="$PWD/target" \
  lessor hold build --need cores=4 --wait 600 -- \
  cargo --config .build-tmp/local-core.toml build --release --features fuse --bin axiom
```

Use the same override for `cargo test` and `cargo check`. For the external Clippy
subcommand, pass it **after** `clippy` so its child Cargo invocation receives it:
`cargo clippy --config .build-tmp/local-core.toml --features fuse --all-targets`.
The paired core has four pre-existing `needless_range_loop` warnings in unchanged
composite code. The verified candidate uses `-- -D warnings -A clippy::needless_range_loop`;
there is no source suppression. Baseline CLI strict Clippy also passed.

The local override changes Cargo.lock to path sources. Keep a copy with build
evidence, then restore the public lockfile before committing this CLI branch.
Check `cargo --config .build-tmp/local-core.toml metadata --features fuse` to verify
that every axiomvault package resolves to the intended candidate worktrees.
