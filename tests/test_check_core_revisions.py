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

    def test_rejects_a_manifest_missing_any_of_the_seven_core_crates(self):
        manifest = "\n".join(
            f'{crate} = {{ git = "https://github.com/axiom-vault/axiom-core", rev = "abc" }}'
            for crate in sorted(module.EXPECTED_CORE_CRATES - {"axiomvault-webdav"})
        )
        with self.assertRaisesRegex(ValueError, "missing axiom-core dependencies.*webdav"):
            module.validate_manifest(manifest)

    def test_compatibility_workflow_is_bound_to_reviewed_core_sha(self):
        workflow = (
            pathlib.Path(__file__).parents[1]
            / ".github"
            / "workflows"
            / "core-compatibility.yml"
        ).read_text(encoding="utf-8")
        reviewed_sha = "4240839a769106f03172a928f5cf24fb01a38704"
        self.assertIn(f"AXIOM_CORE_SHA: {reviewed_sha}", workflow)
        self.assertIn('ref: ${{ env.AXIOM_CORE_SHA }}', workflow)
        self.assertNotIn("inputs.core_ref", workflow)

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
