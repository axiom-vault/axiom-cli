#!/usr/bin/python3
"""User-session FUSE integration. Passwords are never stored by this helper."""
import argparse
import errno
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from xml.dom import minidom


def validate_name(name):
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name):
        raise ValueError("Profile name must contain only letters, digits, _ or -")
    return name


def snapshot(path):
    if path.is_symlink():
        raise RuntimeError("Refusing to replace a symbolic link")
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def replace_checked(path, before, data):
    """Stage privately, then refuse to overwrite a changed preimage."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".axiom-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if snapshot(path) != before:
            raise RuntimeError("State changed concurrently; retry after the other writer finishes")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def backup_preimage(path, before):
    if before is None:
        return None
    backup = path.with_name(path.name + ".axiom-backup-" + str(time.time_ns()))
    with backup.open("xb") as stream:
        os.chmod(backup, 0o600)
        stream.write(before)
    return backup


def merge_places(path, mount_point, label):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_name(path.name + ".axiom-lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = snapshot(path)
        document = minidom.parseString(before or b'<xbel version="1.0"/>')
        url = mount_point.absolute().as_uri()
        if any(node.getAttribute("href") == url for node in document.getElementsByTagName("bookmark")):
            return None
        bookmark = document.createElement("bookmark")
        bookmark.setAttribute("href", url)
        title = document.createElement("title")
        title.appendChild(document.createTextNode(label))
        bookmark.appendChild(title)
        bookmark.setAttribute("id", "axiomvault-" + hashlib.sha256(url.encode()).hexdigest()[:16])
        bookmark.setAttribute("axiom-original", hashlib.sha256(bookmark.toxml().encode()).hexdigest())
        document.documentElement.appendChild(bookmark)
        backup = backup_preimage(path, before)
        replace_checked(path, before, document.toxml(encoding="UTF-8"))
        return backup


def remove_place(path, mount_point):
    with path.with_name(path.name + ".axiom-lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = snapshot(path)
        if before is None:
            return
        document = minidom.parseString(before)
        url = mount_point.absolute().as_uri()
        for node in list(document.getElementsByTagName("bookmark")):
            if node.getAttribute("href") == url:
                original = node.getAttribute("axiom-original")
                if not original:
                    continue
                candidate = node.cloneNode(True)
                candidate.removeAttribute("axiom-original")
                if hashlib.sha256(candidate.toxml().encode()).hexdigest() == original:
                    node.parentNode.removeChild(node)
        backup_preimage(path, before)
        replace_checked(path, before, document.toxml(encoding="UTF-8"))


def gtk_bookmark(path, mount_point, label):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_name(path.name + ".axiom-lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = snapshot(path)
        uri = mount_point.absolute().as_uri().encode()
        lines = (before or b"").splitlines(keepends=True)
        ownership_path = path.with_name(path.name + ".axiom-ownership.json")
        ownership_before = snapshot(ownership_path)
        ownership = json.loads(ownership_before) if ownership_before else {}
        if label is not None and any(line.split(b" ", 1)[0].rstrip(b"\n") == uri for line in lines):
            return None
        kept = before or b""
        if label is not None:
            added = uri + b" " + label.encode() + b"\n"
            kept += (b"\n" if kept and not kept.endswith(b"\n") else b"") + added
            ownership[uri.decode()] = added.decode()
        else:
            added = ownership.pop(uri.decode(), None)
            if added is None:
                return None
            # Preserve entries whose label/bytes the user changed after setup.
            expected = added.encode()
            if expected in lines:
                lines.remove(expected)
                kept = b"".join(lines)
        backup = backup_preimage(path, before)
        replace_checked(path, before, kept)
        replace_checked(ownership_path, ownership_before, json.dumps(ownership, indent=2).encode())
        return backup


def exclude_baloo(mount_point, home):
    if not shutil.which("balooctl6"):
        return None
    listed = subprocess.run(["balooctl6", "config", "list", "includeFolders"], check=True, capture_output=True, text=True).stdout
    roots = [Path(line.strip()).resolve() for line in listed.splitlines() if line.strip().startswith("/")]
    if not any(root == mount_point or root in mount_point.parents for root in roots):
        # Baloo prunes redundant exclusions outside its indexing roots. The
        # hidden default mount location is deliberately outside those roots.
        return None
    config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")) / "baloofilerc"
    before = snapshot(config)
    backup = backup_preimage(config, before)
    # KConfig's own writer preserves the other configuration values.
    subprocess.run(["balooctl6", "config", "add", "excludeFolders", str(mount_point)], check=True, stdout=subprocess.DEVNULL)
    excluded = subprocess.run(["balooctl6", "config", "list", "excludeFolders"], check=True, capture_output=True, text=True).stdout
    if str(mount_point).rstrip("/") not in [line.strip().rstrip("/") for line in excluded.splitlines()]:
        raise RuntimeError("Baloo exclusion did not become effective; mount was not started")
    return backup


def install_files(binary, home):
    content = binary.read_bytes()
    mount_point = home / ".local/share/axiomvault/mounts/desktop"
    if mount_point.exists() or mount_point.is_symlink():
        raise RuntimeError("Desktop mount directory already exists; refusing an ambiguous reinstall")
    places = home / ".local/share/user-places.xbel"
    minidom.parseString(snapshot(places) or b'<xbel version="1.0"/>')
    directory = home / ".local/bin"
    directory.mkdir(parents=True, exist_ok=True)
    records = []
    destination = directory / "axiom"
    before = snapshot(destination)
    if before is not None:
        previous = directory / "axiom.bak"
        old_backup = snapshot(previous)
        older = backup_preimage(previous, old_backup)
        replace_checked(previous, old_backup, before)
        os.chmod(previous, 0o700)
        records.append({"original_binary_backup": str(previous), "sha256": hashlib.sha256(before).hexdigest(), "older_backup": str(older) if older else None})
    targets = {
        destination: content,
        directory / "axiom-desktop": Path(__file__).read_bytes(),
        home / ".config/systemd/user/axiom-desktop@.service": unit_text(directory / "axiom-desktop").encode(),
    }
    for target, content in targets.items():
        preimage = snapshot(target)
        backup = backup_preimage(target, preimage)
        replace_checked(target, preimage, content)
        os.chmod(target, 0o700 if target.parent == directory else 0o600)
        records.append({"path": str(target), "backup": str(backup) if backup else None, "before_sha256": hashlib.sha256(preimage).hexdigest() if preimage is not None else None, "installed_sha256": hashlib.sha256(content).hexdigest()})
    # No existing vault or mount is inspected by the installation step.
    mount_point.mkdir(parents=True, exist_ok=False)
    backup = merge_places(places, mount_point, "AxiomVault")
    records.append({"places": str(places), "backup": str(backup) if backup else None, "owned_url": mount_point.as_uri()})
    gtk = home / ".config/gtk-3.0/bookmarks"
    backup = gtk_bookmark(gtk, mount_point, "AxiomVault")
    records.append({"gtk_bookmarks": str(gtk), "backup": str(backup) if backup else None, "owned_url": mount_point.as_uri()})
    # LocalSearch/Tracker honors this marker in the parent directory. It stays
    # outside the vault, including while the child directory is mounted.
    (mount_point.parent / ".trackerignore").touch(mode=0o600, exist_ok=True)
    if home == Path.home():
        backup = exclude_baloo(mount_point.parent, home)
        records.append({"baloo_config": str(home / ".config/baloofilerc"), "backup": str(backup) if backup else None, "owned_exclusion": str(mount_point.parent)})
    state = home / ".local/state/axiomvault"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    manifest = state / ("desktop-install-" + str(time.time_ns()) + ".json")
    with manifest.open("x") as stream:
        os.chmod(manifest, 0o600)
        json.dump(records, stream, indent=2)
    return manifest


def mount_command(profile, binary):
    command = [str(binary), "mount", "fuse"]
    if "local_path" in profile:
        command += ["--path", profile["local_path"]]
    else:
        command += ["--folder-id", profile["folder_id"], "--tokens", profile["tokens"]]
        if profile.get("client_id"):
            command += ["--client-id", profile["client_id"]]
    if profile.get("password_file"):
        command += ["--password-file", profile["password_file"]]
    else:
        command += ["--gui-password"]
    command.append(profile["mount_point"])
    return command


def unit_text(helper):
    # systemd performs specifier expansion even inside quotes.
    executable = str(helper).replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"')
    return f'''[Unit]
Description=AxiomVault desktop mount (%i)
After=graphical-session.target
PartOf=graphical-session.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart="{executable}" run %i
Restart=always
RestartSec=15
RestartPreventExitStatus=77 78
TimeoutStopSec=30
UMask=0077
LimitCORE=0

[Install]
WantedBy=graphical-session.target
'''


def profile_path(name):
    config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return config / "axiomvault/desktop-profiles" / (validate_name(name) + ".json")


def setup(args):
    path = profile_path(args.name)
    if path.exists() or path.is_symlink():
        raise RuntimeError("Profile already exists; stop and remove that profile before configuring it again")
    mount_point = Path(args.mount_point or Path.home() / ".local/share/axiomvault/mounts" / args.name).expanduser().absolute()
    # Never mount over an existing filesystem or hide an existing directory's files.
    if os.path.ismount(mount_point) or (mount_point.exists() and any(mount_point.iterdir())):
        raise RuntimeError("Mount point must be an empty, unmounted directory")
    mount_point.mkdir(parents=True, exist_ok=True)
    profile = {"mount_point": str(mount_point)}
    if args.local_path:
        profile["local_path"] = str(Path(args.local_path).expanduser().resolve(strict=True))
        if args.password_file:
            profile["password_file"] = str(Path(args.password_file).expanduser().resolve(strict=True))
    else:
        if args.password_file:
            raise ValueError("Desktop Google Drive profiles never persist a password-file reference")
        folder = args.folder_id or input("Google Drive vault folder ID: ").strip()
        if not folder:
            raise ValueError("Folder ID is required")
        default_tokens = Path.home() / ".config/axiomvault/gdrive-tokens.json"
        tokens = Path(args.tokens or input(f"OAuth token file [{default_tokens}]: ").strip() or default_tokens).expanduser().absolute()
        if not tokens.is_file():
            client_id = input("Google OAuth desktop client ID (for authentication): ").strip()
            if not client_id:
                raise ValueError("Client ID is required to authenticate")
            tokens.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run([str(Path.home() / ".local/bin/axiom"), "remote", "gdrive", "auth", "--client-id", client_id, "--output", str(tokens)], check=True)
        profile.update(folder_id=folder, tokens=str(tokens))
        if args.client_id:
            profile["client_id"] = args.client_id
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Exclusive creation prevents replacing another profile, including races.
    with path.open("x") as stream:
        os.chmod(path, 0o600)
        json.dump(profile, stream)
    places = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "user-places.xbel"
    gtk = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "gtk-3.0/bookmarks"
    profile["places_file"] = str(places)
    profile["gtk_bookmarks_file"] = str(gtk)
    # Update our exclusively created profile before touching either bookmark file.
    profile_preimage = snapshot(path)
    replace_checked(path, profile_preimage, json.dumps(profile).encode())
    backup = merge_places(places, mount_point, "AxiomVault" if args.name == "desktop" else "AxiomVault " + args.name)
    if backup:
        print("Places preimage backup:", backup)
    gtk_bookmark(gtk, mount_point, "AxiomVault" if args.name == "desktop" else "AxiomVault " + args.name)
    exclude_baloo(mount_point, Path.home())
    unit = "axiom-desktop@" + args.name + ".service"
    config = path.parents[2]
    if config != Path.home() / ".config":
        # Keep fixture/custom XDG profiles available to this instance without
        # changing the environment of any unrelated user service.
        dropin = Path.home() / ".config/systemd/user" / (unit + ".d") / "90-axiom-profile.conf"
        value = str(config).replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"')
        content = ('# Managed by axiom-desktop for this profile only\n[Service]\nEnvironment="XDG_CONFIG_HOME=' + value + '"\n').encode()
        if dropin.exists():
            raise RuntimeError("Instance configuration already exists; refusing to replace it")
        replace_checked(dropin, None, content)
        profile["instance_dropin"] = str(dropin)
        preimage = snapshot(path)
        replace_checked(path, preimage, json.dumps(profile).encode())
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "--user", "enable", unit], check=True)
    if not args.no_start:
        subprocess.run(["systemctl", "--user", "start", unit], check=True)
        # Active means the password dialog may be waiting. Report mount readiness.
        for _ in range(300):
            if os.path.ismount(mount_point):
                print("AxiomVault is mounted. Password is kept only in memory; login/remount prompts again.")
                return
            state = subprocess.run(["systemctl", "--user", "is-active", unit], stdout=subprocess.PIPE, check=False).stdout.strip()
            if state not in (b"active", b"activating", b"reloading"):
                raise RuntimeError("Mount did not start; use systemctl --user status " + unit)
            time.sleep(1)
        raise RuntimeError("Mount is still waiting; finish the unlock dialog or inspect the service")
    print("Profile configured and enabled; it will ask for the password when started.")


def run(name):
    with profile_path(name).open() as stream:
        profile = json.load(stream)
    mount_point = Path(profile["mount_point"])
    recover_stale_mount(mount_point)
    mount_point.mkdir(parents=True, exist_ok=True)
    # Do not detach an existing mount: it might belong to another process.
    if os.path.ismount(mount_point):
        raise RuntimeError("Mount point is already mounted; refusing to replace it")
    if any(mount_point.iterdir()):
        raise RuntimeError("Mount point contains files; refusing to hide them")
    binary = Path.home() / ".local/bin/axiom"
    os.execv(binary, mount_command(profile, binary))


def recover_stale_mount(mount_point):
    if mount_point.is_symlink():
        raise RuntimeError("Mount point must not be a symbolic link")
    # Inspect kernel metadata only. Never detach a live or unrelated mount.
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        decoded = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
        if decoded != str(mount_point):
            continue
        filesystem = fields[fields.index("-") + 1]
        try:
            mount_point.stat()
        except OSError as error:
            if error.errno == errno.ENOTCONN and filesystem == "fuse.axiomvault":
                subprocess.run(["/usr/bin/fusermount3", "-u", str(mount_point)], check=True)
                return
            raise
        raise RuntimeError("Mount point is already mounted; refusing to detach it")


def remove(name):
    path = profile_path(name)
    with path.open() as stream:
        profile = json.load(stream)
    subprocess.run(["systemctl", "--user", "disable", "--now", "axiom-desktop@" + name + ".service"], check=True)
    remove_place(Path(profile.get("places_file", Path.home() / ".local/share/user-places.xbel")), Path(profile["mount_point"]))
    gtk_bookmark(Path(profile.get("gtk_bookmarks_file", Path.home() / ".config/gtk-3.0/bookmarks")), Path(profile["mount_point"]), None)
    path.unlink()
    if profile.get("instance_dropin"):
        dropin = Path(profile["instance_dropin"])
        if dropin.read_text().startswith("# Managed by axiom-desktop for this profile only\n"):
            dropin.unlink()
            dropin.parent.rmdir()
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    # Keep the empty mount directory, encrypted vault and token file untouched.
    print("Desktop profile removed; vault data and OAuth token file were preserved.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    configure = commands.add_parser("setup", help="Privately configure and unlock your desktop mount")
    configure.add_argument("--name", default="desktop", type=validate_name)
    source = configure.add_mutually_exclusive_group()
    source.add_argument("--folder-id")
    source.add_argument("--local-path")
    configure.add_argument("--tokens")
    configure.add_argument("--client-id")
    configure.add_argument("--mount-point")
    configure.add_argument("--password-file", help="Local fixture profiles only")
    configure.add_argument("--no-start", action="store_true")
    runner = commands.add_parser("run")
    runner.add_argument("name", type=validate_name)
    remover = commands.add_parser("remove", help="Stop and remove only the selected desktop profile and Place")
    remover.add_argument("--name", default="desktop", type=validate_name)
    installer = commands.add_parser("install", help="Install a built FUSE binary and this integration for the current user")
    installer.add_argument("binary", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "setup":
            setup(args)
        elif args.command == "run":
            run(args.name)
        elif args.command == "remove":
            remove(args.name)
        else:
            subprocess.run([str(args.binary.absolute()), "mount", "fuse", "--help"], stdout=subprocess.DEVNULL, check=True)
            print("Install manifest:", install_files(args.binary, Path.home()))
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print("AxiomVault desktop:", error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
