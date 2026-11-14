"""Desktop integration uses only owned temporary state, never the user's profile."""
import importlib.util
import tempfile
import unittest
from unittest.mock import patch
import errno
import json
from pathlib import Path
from types import SimpleNamespace
from xml.dom import minidom

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "axiom-desktop.py"


class DesktopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("desktop", SCRIPT)
        cls.desktop = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.desktop)

    def test_oauth_uses_explicit_id_and_primary_or_legacy_environment_before_prompt(self):
        cases = [
            ("flag-client", {"AXIOM_GOOGLE_CLIENT_ID": "primary-client", "AXIOMVAULT_GOOGLE_CLIENT_ID": "legacy-client", "AXIOM_GOOGLE_CLIENT_SECRET": "primary-secret", "AXIOMVAULT_GOOGLE_CLIENT_SECRET": "legacy-secret"}, ("flag-client", "primary-secret")),
            (None, {"AXIOM_GOOGLE_CLIENT_ID": "primary-client", "AXIOMVAULT_GOOGLE_CLIENT_ID": "legacy-client", "AXIOM_GOOGLE_CLIENT_SECRET": "primary-secret"}, ("primary-client", "primary-secret")),
            (None, {"AXIOMVAULT_GOOGLE_CLIENT_ID": "legacy-client", "AXIOMVAULT_GOOGLE_CLIENT_SECRET": "legacy-secret"}, ("legacy-client", "legacy-secret")),
        ]
        for flag, environment, expected in cases:
            args = SimpleNamespace(client_id=flag, client_json=None)
            with self.subTest(flag=flag), patch.dict(self.desktop.os.environ, environment, clear=True), patch("builtins.input", side_effect=AssertionError("unexpected ID prompt")), patch("getpass.getpass", side_effect=AssertionError("unexpected secret prompt")):
                self.assertEqual(self.desktop.google_oauth_client(args), expected)

    def test_installed_client_json_supplies_child_secret_without_secret_argv(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "synthetic-client.json"
            path.write_text(json.dumps({"installed": {"client_id": "json-client", "client_secret": "json-secret"}}))
            args = SimpleNamespace(client_id=None, client_json=path)
            tokens = Path(root) / "tokens.json"
            with patch.dict(self.desktop.os.environ, {"AXIOM_GOOGLE_CLIENT_ID": "env-client", "AXIOM_GOOGLE_CLIENT_SECRET": "env-secret"}, clear=True), patch("builtins.input", side_effect=AssertionError("unexpected ID prompt")), patch("getpass.getpass", side_effect=AssertionError("unexpected secret prompt")), patch.object(self.desktop.subprocess, "run") as run:
                self.desktop.authenticate_gdrive(args, tokens)
            command = run.call_args.args[0]
            self.assertEqual(command[-4:], ["--client-id", "json-client", "--output", str(tokens)])
            self.assertNotIn("json-secret", command)
            self.assertEqual(run.call_args.kwargs["env"]["AXIOM_GOOGLE_CLIENT_SECRET"], "json-secret")

    def test_oauth_prompts_only_for_missing_values_and_allows_public_client(self):
        args = SimpleNamespace(client_id=None, client_json=None)
        with patch.dict(self.desktop.os.environ, {}, clear=True), patch("builtins.input", return_value="prompt-client") as prompt, patch("getpass.getpass", return_value="") as secret_prompt:
            self.assertEqual(self.desktop.google_oauth_client(args), ("prompt-client", None))
        prompt.assert_called_once()
        secret_prompt.assert_called_once()

    def test_conflicting_explicit_client_and_json_are_not_silently_mixed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "synthetic-client.json"
            path.write_text(json.dumps({"installed": {"client_id": "json-client", "client_secret": "hidden-fixture-secret"}}))
            args = SimpleNamespace(client_id="different-client", client_json=path)
            with patch.dict(self.desktop.os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, "conflicts") as raised:
                self.desktop.google_oauth_client(args)
            self.assertNotIn("hidden-fixture-secret", str(raised.exception))

    def test_client_json_rejects_web_or_malformed_data_without_echoing_contents(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "synthetic-client.json"
            for content in ['{"web":{"client_secret":"hidden-fixture-secret"}}', '{"installed":{"client_id":7,"client_secret":"hidden-fixture-secret"}}', '{"installed": "hidden-fixture-secret"', '["hidden-fixture-secret"]']:
                path.write_text(content)
                args = SimpleNamespace(client_id=None, client_json=path)
                with patch.dict(self.desktop.os.environ, {}, clear=True), self.assertRaises(ValueError) as raised:
                    self.desktop.google_oauth_client(args)
                self.assertNotIn("hidden-fixture-secret", str(raised.exception))

    def test_folder_validation_rejects_names_and_explains_drive_url_component(self):
        for value in ["AxiomVault", "", "Axiom Vault", "name/child", "https://drive.google.com/drive/folders/fixture"]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "/folders/"):
                self.desktop.validate_folder_id(value)
        self.assertEqual(self.desktop.validate_folder_id("  1Synthetic_Folder-ID_1234567890  "), "1Synthetic_Folder-ID_1234567890")

    def test_missing_token_setup_keeps_supplied_client_and_uses_specific_folder_prompt(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            args = SimpleNamespace(name="fixture", mount_point=str(home / "mount"), local_path=None, password_file=None, folder_id=None, tokens=str(home / "tokens.json"), client_id="flag-client", client_json=None, no_start=True)
            environment = {"XDG_CONFIG_HOME": str(home / ".config"), "XDG_DATA_HOME": str(home / ".local/share"), "AXIOMVAULT_GOOGLE_CLIENT_SECRET": "fixture-secret"}
            with patch.object(Path, "home", return_value=home), patch.dict(self.desktop.os.environ, environment, clear=True), patch("builtins.input", return_value="1Synthetic_Folder-ID_1234567890") as prompt, patch("getpass.getpass", side_effect=AssertionError("unexpected secret prompt")), patch.object(self.desktop.subprocess, "run") as run, patch.object(self.desktop, "exclude_baloo"):
                self.desktop.setup(args)
            prompt.assert_called_once_with("Google Drive vault folder ID (the part after /folders/ in the Drive URL): ")
            auth = next(call for call in run.call_args_list if "auth" in call.args[0])
            self.assertIn("flag-client", auth.args[0])
            self.assertEqual(auth.kwargs["env"]["AXIOM_GOOGLE_CLIENT_SECRET"], "fixture-secret")
            profile = (home / ".config/axiomvault/desktop-profiles/fixture.json").read_text()
            self.assertNotIn("fixture-secret", profile)

    def test_places_preserves_existing_nodes_and_backs_up_exact_preimage(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "places.xbel"
            before = b'<?xml version="1.0"?><xbel xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks"><bookmark href="file:///fixture-old"><title>Keep me</title><info><metadata owner="fixture"><bookmark:icon name="folder"/></metadata></info></bookmark></xbel>'
            path.write_bytes(before)
            backup = self.desktop.merge_places(path, Path(root) / "mount", "Axiom fixture")
            self.assertEqual(backup.read_bytes(), before)
            doc = minidom.parse(str(path))
            bookmarks = doc.getElementsByTagName("bookmark")
            self.assertEqual(len(bookmarks), 2)
            self.assertEqual(bookmarks[0].toxml(), minidom.parseString(before).getElementsByTagName("bookmark")[0].toxml())
            self.desktop.merge_places(path, Path(root) / "mount", "Axiom fixture")
            self.assertEqual(len(minidom.parse(str(path)).getElementsByTagName("bookmark")), 2)

    def test_concurrent_update_is_preserved_and_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "state"
            path.write_bytes(b"newer user state")
            with self.assertRaises(RuntimeError):
                self.desktop.replace_checked(path, b"old state", b"our state")
            self.assertEqual(path.read_bytes(), b"newer user state")

    def test_mount_command_keeps_password_out_of_argv_and_defaults_to_gui(self):
        command = self.desktop.mount_command({
            "folder_id": "synthetic-folder", "tokens": "/fixture/tokens.json",
            "mount_point": "/fixture/mount",
        }, Path("/fixture/axiom"))
        self.assertEqual(command, ["/fixture/axiom", "mount", "fuse", "--folder-id", "synthetic-folder", "--tokens", "/fixture/tokens.json", "--gui-password", "/fixture/mount"])

    def test_profile_name_rejects_unit_and_path_injection(self):
        for bad in ["../desktop", "desktop.service", "x%h", "x\nRestart=no", ""]:
            with self.assertRaises(ValueError):
                self.desktop.validate_name(bad)

    def test_removing_owned_place_preserves_other_bookmarks(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "places.xbel"
            path.write_bytes(b'<xbel><bookmark href="file:///keep"><title>Keep</title></bookmark></xbel>')
            mount = Path(root) / "mount"
            self.desktop.merge_places(path, mount, "Fixture")
            self.desktop.remove_place(path, mount)
            doc = minidom.parse(str(path))
            self.assertEqual([x.getAttribute("href") for x in doc.getElementsByTagName("bookmark")], ["file:///keep"])

    def test_install_collision_does_not_replace_the_original_binary(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            binary = home / "candidate"
            binary.write_bytes(b"candidate")
            installed = home / ".local/bin/axiom"
            installed.parent.mkdir(parents=True)
            installed.write_bytes(b"original")
            (home / ".local/share/axiomvault/mounts/desktop").mkdir(parents=True)
            with self.assertRaises((RuntimeError, FileExistsError)):
                self.desktop.install_files(binary, home)
            self.assertEqual(installed.read_bytes(), b"original")

    def test_install_preserves_original_and_older_backup(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            binary = home / "candidate"
            binary.write_bytes(b"candidate")
            installed = home / ".local/bin/axiom"
            installed.parent.mkdir(parents=True)
            installed.write_bytes(b"original")
            installed.with_name("axiom.bak").write_bytes(b"older backup")
            manifest = self.desktop.install_files(binary, home)
            import json
            records = json.loads(manifest.read_text())
            self.assertEqual(installed.read_bytes(), b"candidate")
            self.assertEqual(installed.with_name("axiom.bak").read_bytes(), b"original")
            self.assertEqual(Path(records[0]["older_backup"]).read_bytes(), b"older backup")

    def test_gtk_bookmark_merge_and_remove_preserves_unrelated_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "bookmarks"
            before = b"file:///fixture-old Keep this\n"
            path.write_bytes(before)
            mount = Path(root) / "mount with space"
            self.desktop.gtk_bookmark(path, mount, "Axiom fixture")
            self.desktop.gtk_bookmark(path, mount, "Axiom fixture")
            self.assertEqual(path.read_bytes(), before + (mount.as_uri() + " Axiom fixture\n").encode())
            self.desktop.gtk_bookmark(path, mount, None)
            self.assertEqual(path.read_bytes(), before)

    def test_preexisting_bookmarks_are_never_removed_as_ours(self):
        with tempfile.TemporaryDirectory() as root:
            mount = Path(root) / "mount"
            kde = Path(root) / "places.xbel"
            gtk = Path(root) / "bookmarks"
            kde.write_text('<xbel><bookmark href="' + mount.as_uri() + '"><title>User entry</title></bookmark></xbel>')
            gtk.write_text(mount.as_uri() + " User entry\n")
            self.desktop.merge_places(kde, mount, "AxiomVault")
            self.desktop.gtk_bookmark(gtk, mount, "AxiomVault")
            self.desktop.remove_place(kde, mount)
            self.desktop.gtk_bookmark(gtk, mount, None)
            self.assertEqual(len(minidom.parse(str(kde)).getElementsByTagName("bookmark")), 1)
            self.assertEqual(gtk.read_text(), mount.as_uri() + " User entry\n")

    def test_user_edited_owned_bookmarks_are_preserved_on_removal(self):
        with tempfile.TemporaryDirectory() as root:
            mount = Path(root) / "mount"
            kde = Path(root) / "places.xbel"
            gtk = Path(root) / "bookmarks"
            self.desktop.merge_places(kde, mount, "AxiomVault")
            self.desktop.gtk_bookmark(gtk, mount, "AxiomVault")
            kde.write_text(kde.read_text().replace("<title>AxiomVault</title>", "<title>My edited entry</title>"))
            gtk.write_text(gtk.read_text().replace(" AxiomVault\n", " My edited entry\n"))
            self.desktop.remove_place(kde, mount)
            self.desktop.gtk_bookmark(gtk, mount, None)
            self.assertIn("My edited entry", kde.read_text())
            self.assertIn("My edited entry", gtk.read_text())

    def test_undo_before_private_setup_removes_only_installed_bookmarks(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            mount = home / ".local/share/axiomvault/mounts/desktop"
            kde = home / ".local/share/user-places.xbel"
            gtk = home / ".config/gtk-3.0/bookmarks"
            self.desktop.merge_places(kde, mount, "AxiomVault")
            self.desktop.gtk_bookmark(gtk, mount, "AxiomVault")
            with patch.object(Path, "home", return_value=home), patch.dict(self.desktop.os.environ, {"XDG_CONFIG_HOME": str(home / ".config")}), patch.object(self.desktop.subprocess, "run"):
                self.desktop.remove("desktop")
            self.assertEqual(len(minidom.parse(str(kde)).getElementsByTagName("bookmark")), 0)
            self.assertEqual(gtk.read_bytes(), b"")

    def test_stale_cleanup_never_detaches_a_live_or_unrelated_mount(self):
        mount = Path("/synthetic/mount")
        for filesystem, failure, should_detach in [
            ("fuse.axiomvault", None, False),
            ("fuse.sshfs", errno.ENOTCONN, False),
            ("fuse.axiomvault", errno.EACCES, False),
            ("fuse.axiomvault", errno.ENOTCONN, True),
        ]:
            with self.subTest(filesystem=filesystem, failure=failure):
                entry = "1 0 0:1 / /synthetic/mount rw - " + filesystem + " fixture rw\n"
                effect = OSError(failure, "synthetic failure") if failure else None
                with patch.object(Path, "read_text", return_value=entry), patch.object(Path, "is_symlink", return_value=False), patch.object(Path, "stat", side_effect=effect), patch.object(self.desktop.subprocess, "run") as command:
                    if should_detach:
                        self.desktop.recover_stale_mount(mount)
                        command.assert_called_once_with(["/usr/bin/fusermount3", "-u", "/synthetic/mount"], check=True)
                    else:
                        with self.assertRaises((RuntimeError, OSError)):
                            self.desktop.recover_stale_mount(mount)
                        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
