"""Desktop integration uses only owned temporary state, never the user's profile."""
import importlib.util
import tempfile
import unittest
from unittest.mock import patch
import errno
from pathlib import Path
from xml.dom import minidom

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "axiom-desktop.py"


class DesktopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("desktop", SCRIPT)
        cls.desktop = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.desktop)

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
