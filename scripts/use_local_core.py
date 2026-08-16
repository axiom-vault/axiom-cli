#!/usr/bin/env python3
"""Rewrite axiom-core git dependencies to a checked-out integration tree."""

from __future__ import annotations

import pathlib
import re
import sys

CRATE_PATHS = {
    "axiomvault-common": "core/common",
    "axiomvault-crypto": "core/crypto",
    "axiomvault-storage": "core/storage",
    "axiomvault-vault": "core/vault",
    "axiomvault-sync": "core/sync",
    "axiomvault-webdav": "core/webdav",
    "axiomvault-fuse": "core/fuse",
}
DEPENDENCY = re.compile(
    r"^(?P<prefix>\s*)(?P<crate>axiomvault-[\w-]+)\s*=\s*\{"
    r"(?P<body>[^\n]*axiom-vault/axiom-core[^\n]*)\}\s*$",
    re.MULTILINE,
)
OPTIONAL = re.compile(r"\boptional\s*=\s*true\b")


def rewrite_manifest(manifest: str, checkout: pathlib.Path) -> str:
    seen: set[str] = set()

    def replacement(match: re.Match[str]) -> str:
        crate = match.group("crate")
        try:
            relative = CRATE_PATHS[crate]
        except KeyError as error:
            raise ValueError(f"no local path mapping for {crate}") from error
        seen.add(crate)
        path = (checkout / relative).as_posix()
        optional = ", optional = true" if OPTIONAL.search(match.group("body")) else ""
        return f'{match.group("prefix")}{crate} = {{ path = "{path}"{optional} }}'

    rewritten = DEPENDENCY.sub(replacement, manifest)
    if not seen:
        raise ValueError("no axiom-core dependencies were rewritten")
    return rewritten


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: use_local_core.py CORE_CHECKOUT CARGO_TOML", file=sys.stderr)
        return 2
    checkout = pathlib.Path(sys.argv[1])
    manifest_path = pathlib.Path(sys.argv[2])
    try:
        rewritten = rewrite_manifest(manifest_path.read_text(encoding="utf-8"), checkout)
        manifest_path.write_text(rewritten, encoding="utf-8")
    except (OSError, ValueError) as error:
        print(f"local core rewrite failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
