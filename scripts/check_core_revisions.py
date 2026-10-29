#!/usr/bin/env python3
"""Fail when axiom-core git dependencies are unpinned or diverge."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

CORE_DEPENDENCY = re.compile(
    r"^\s*(axiomvault-[\w-]+)\s*=\s*\{([^\n]*axiom-vault/axiom-core[^\n]*)\}\s*$",
    re.MULTILINE,
)
REVISION = re.compile(r'\brev\s*=\s*"([0-9a-f]{40})"')
CORE_SOURCE = "git+https://github.com/axiom-vault/axiom-core"
EXPECTED_CORE_CRATES = {
    "axiomvault-agent",
    "axiomvault-common",
    "axiomvault-crypto",
    "axiomvault-storage",
    "axiomvault-vault",
    "axiomvault-sync",
    "axiomvault-webdav",
    "axiomvault-fuse",
}


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
            "axiom-core dependencies must use an exact 40-character commit rev: "
            + ", ".join(sorted(missing))
        )

    revisions = core_revisions(manifest)
    if len(revisions) != 1:
        raise ValueError(
            "axiom-core dependency revisions diverge: " + ", ".join(sorted(revisions))
        )
    crates = {crate for crate, _body in dependencies}
    missing_crates = EXPECTED_CORE_CRATES - crates
    if missing_crates:
        raise ValueError(
            "missing axiom-core dependencies: " + ", ".join(sorted(missing_crates))
        )
    return next(iter(revisions))


def validate_lockfile(lockfile: str, revision: str) -> None:
    """Every axiom-core package in Cargo.lock must come from `revision`."""
    packages = [
        (package["name"], package["source"])
        for package in tomllib.loads(lockfile).get("package", [])
        if package.get("source", "").startswith(CORE_SOURCE)
    ]
    expected = f"{CORE_SOURCE}?rev={revision}#{revision}"
    stale = sorted(f"{name} ({source})" for name, source in packages if source != expected)
    if stale:
        raise ValueError(
            f"Cargo.lock axiom-core packages diverge from {revision}: " + ", ".join(stale)
        )
    missing = EXPECTED_CORE_CRATES - {name for name, _source in packages}
    if missing:
        raise ValueError(
            "Cargo.lock is missing axiom-core packages: " + ", ".join(sorted(missing))
        )


def main() -> int:
    manifest_path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "Cargo.toml")
    lockfile_path = (
        pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else manifest_path.with_name("Cargo.lock")
    )
    try:
        revision = validate_manifest(manifest_path.read_text(encoding="utf-8"))
        validate_lockfile(lockfile_path.read_text(encoding="utf-8"), revision)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"core revision check failed: {error}", file=sys.stderr)
        return 1
    print(f"Cargo.toml and Cargo.lock pin all axiom-core crates to {revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
