import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "check_core_revisions.py"
spec = importlib.util.spec_from_file_location("check_core_revisions", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

LOCAL_CORE_SCRIPT = ROOT / "scripts" / "use_local_core.py"
local_spec = importlib.util.spec_from_file_location("use_local_core", LOCAL_CORE_SCRIPT)
local_core = importlib.util.module_from_spec(local_spec)
local_spec.loader.exec_module(local_core)

REV = "a" * 40
OTHER_REV = "b" * 40


def dependency(crate, rev=REV):
    return f'{crate} = {{ git = "https://github.com/axiom-vault/axiom-core", rev = "{rev}" }}'


def lock_package(crate, rev=REV):
    source = f"git+https://github.com/axiom-vault/axiom-core?rev={rev}#{rev}"
    return f'[[package]]\nname = "{crate}"\nversion = "0.1.0"\nsource = "{source}"\n'


ALL_LOCKED = "\n".join(lock_package(crate) for crate in sorted(module.EXPECTED_CORE_CRATES))


class CoreRevisionTests(unittest.TestCase):
    def test_accepts_one_revision_for_every_core_crate(self):
        manifest = "\n".join(dependency(crate) for crate in module.EXPECTED_CORE_CRATES)
        self.assertEqual(module.validate_manifest(manifest), REV)

    def test_rejects_divergent_core_revisions(self):
        manifest = "\n".join(
            [dependency("axiomvault-common"), dependency("axiomvault-vault", OTHER_REV)]
        )
        with self.assertRaisesRegex(ValueError, "diverge"):
            module.validate_manifest(manifest)

    def test_rejects_unpinned_core_git_dependencies(self):
        manifest = 'axiomvault-common = { git = "https://github.com/axiom-vault/axiom-core" }'
        with self.assertRaisesRegex(ValueError, "exact 40-character commit rev"):
            module.validate_manifest(manifest)

    def test_rejects_branch_names_and_short_revisions(self):
        for rev in ("release/2.0", "535912f"):
            with self.assertRaisesRegex(ValueError, "exact 40-character commit rev"):
                module.validate_manifest(dependency("axiomvault-common", rev))

    def test_rejects_a_manifest_missing_any_core_crate(self):
        manifest = "\n".join(
            dependency(crate)
            for crate in sorted(module.EXPECTED_CORE_CRATES - {"axiomvault-agent"})
        )
        with self.assertRaisesRegex(ValueError, "missing axiom-core dependencies.*agent"):
            module.validate_manifest(manifest)

    def test_accepts_a_lockfile_on_the_manifest_revision(self):
        module.validate_lockfile(ALL_LOCKED + lock_package("axiomvault-app"), REV)

    def test_rejects_a_lockfile_on_another_revision(self):
        lockfile = ALL_LOCKED.replace(
            lock_package("axiomvault-sync"), lock_package("axiomvault-sync", OTHER_REV)
        )
        with self.assertRaisesRegex(ValueError, "Cargo.lock .* diverge.*axiomvault-sync"):
            module.validate_lockfile(lockfile, REV)

    def test_rejects_a_transitive_core_package_on_another_revision(self):
        lockfile = ALL_LOCKED + lock_package("axiomvault-app", OTHER_REV)
        with self.assertRaisesRegex(ValueError, "diverge.*axiomvault-app"):
            module.validate_lockfile(lockfile, REV)

    def test_rejects_a_lockfile_missing_a_core_package(self):
        lockfile = ALL_LOCKED.replace(lock_package("axiomvault-webdav"), "")
        with self.assertRaisesRegex(ValueError, "missing axiom-core packages.*webdav"):
            module.validate_lockfile(lockfile, REV)

    def test_repository_manifest_and_lockfile_agree(self):
        revision = module.validate_manifest((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        module.validate_lockfile((ROOT / "Cargo.lock").read_text(encoding="utf-8"), revision)

    def test_rewrites_every_core_dependency_to_local_checkout(self):
        manifest = f"""
axiomvault-common = {{ git = "https://github.com/axiom-vault/axiom-core", rev = "{REV}" }}
axiomvault-fuse = {{ git = "https://github.com/axiom-vault/axiom-core", rev = "{REV}", optional = true }}
serde = "1"

[target.'cfg(unix)'.dependencies]
axiomvault-agent = {{ git = "https://github.com/axiom-vault/axiom-core", rev = "{REV}" }}
"""
        rewritten = local_core.rewrite_manifest(manifest, pathlib.Path("../axiom-core"))
        self.assertIn('axiomvault-common = { path = "../axiom-core/core/common" }', rewritten)
        self.assertIn(
            'axiomvault-fuse = { path = "../axiom-core/core/fuse", optional = true }',
            rewritten,
        )
        self.assertIn('axiomvault-agent = { path = "../axiom-core/core/agent" }', rewritten)
        self.assertIn('serde = "1"', rewritten)
        self.assertNotIn("axiom-vault/axiom-core", rewritten)

    def test_maps_every_expected_core_crate_to_a_local_path(self):
        self.assertEqual(set(local_core.CRATE_PATHS), module.EXPECTED_CORE_CRATES)


if __name__ == "__main__":
    unittest.main()
