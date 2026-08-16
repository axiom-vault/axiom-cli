import importlib.util
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "check_core_revisions.py"
spec = importlib.util.spec_from_file_location("check_core_revisions", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

LOCAL_CORE_SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "use_local_core.py"
local_spec = importlib.util.spec_from_file_location("use_local_core", LOCAL_CORE_SCRIPT)
local_core = importlib.util.module_from_spec(local_spec)
local_spec.loader.exec_module(local_core)


class CoreRevisionTests(unittest.TestCase):
    def test_accepts_one_revision_for_every_core_crate(self):
        manifest = """
axiomvault-common = { git = "https://github.com/axiom-vault/axiom-core", rev = "abc" }
axiomvault-vault = { git = "https://github.com/axiom-vault/axiom-core", rev = "abc" }
"""
        self.assertEqual(module.core_revisions(manifest), {"abc"})

    def test_rejects_divergent_core_revisions(self):
        manifest = """
axiomvault-common = { git = "https://github.com/axiom-vault/axiom-core", rev = "abc" }
axiomvault-vault = { git = "https://github.com/axiom-vault/axiom-core", rev = "def" }
"""
        with self.assertRaisesRegex(ValueError, "diverge"):
            module.validate_manifest(manifest)

    def test_rejects_unpinned_core_git_dependencies(self):
        manifest = 'axiomvault-common = { git = "https://github.com/axiom-vault/axiom-core" }'
        with self.assertRaisesRegex(ValueError, "exact rev"):
            module.validate_manifest(manifest)

    def test_rewrites_every_core_dependency_to_local_checkout(self):
        manifest = """
axiomvault-common = { git = "https://github.com/axiom-vault/axiom-core", rev = "abc" }
axiomvault-fuse = { git = "https://github.com/axiom-vault/axiom-core", rev = "abc", optional = true }
serde = "1"
"""
        rewritten = local_core.rewrite_manifest(manifest, pathlib.Path("../axiom-core"))
        self.assertIn('axiomvault-common = { path = "../axiom-core/core/common" }', rewritten)
        self.assertIn(
            'axiomvault-fuse = { path = "../axiom-core/core/fuse", optional = true }',
            rewritten,
        )
        self.assertIn('serde = "1"', rewritten)
        self.assertNotIn("axiom-vault/axiom-core", rewritten)


if __name__ == "__main__":
    unittest.main()
