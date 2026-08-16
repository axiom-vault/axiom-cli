#!/usr/bin/env python3
"""Fail when axiom-core git dependencies are unpinned or diverge."""

from __future__ import annotations

import pathlib
import re
import sys

CORE_DEPENDENCY = re.compile(
    r"^\s*(axiomvault-[\w-]+)\s*=\s*\{([^\n]*axiom-vault/axiom-core[^\n]*)\}\s*$",
    re.MULTILINE,
)
REVISION = re.compile(r'\brev\s*=\s*"([0-9A-Za-z._/-]+)"')


def core_revisions(manifest: str) -> set[str]:
    revisions: set[str] = set()
    for _crate, body in CORE_DEPENDENCY.findall(manifest):
        match = REVISION.search(body)
        if match:
            revisions.add(match.group(1))
    return revisions


def validate_manifest(manifest: str) -> str:
    dependencies = CORE_DEPENDENCY.findall(manifest)
    if not dependencies:
        raise ValueError("no axiom-core git dependencies found")

    missing = [crate for crate, body in dependencies if not REVISION.search(body)]
    if missing:
        raise ValueError(
            "axiom-core dependencies must use an exact rev: " + ", ".join(sorted(missing))
        )

    revisions = core_revisions(manifest)
    if len(revisions) != 1:
        raise ValueError(
            "axiom-core dependency revisions diverge: " + ", ".join(sorted(revisions))
        )
    return next(iter(revisions))


def main() -> int:
    manifest_path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "Cargo.toml")
    try:
        revision = validate_manifest(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"core revision check failed: {error}", file=sys.stderr)
        return 1
    print(f"all axiom-core dependencies use {revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
