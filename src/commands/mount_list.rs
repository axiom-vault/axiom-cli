//! `axiom mount list`: show the current user's running `axiom mount webdav`
//! servers and, on Linux, FUSE mounts. Reads live process state only;
//! nothing is persisted, so the output cannot go stale. Never prints a secret.

// The /proc parsers are used only on Linux; tests cover them everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::commands::vault_list::escape_display;
use anyhow::Result;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

#[derive(Debug, Serialize)]
pub(crate) struct MountRow {
    kind: &'static str,
    pid: Option<u32>,
    vault_path: Option<String>,
    address: Option<String>,
    state: &'static str,
}

#[derive(Debug, PartialEq)]
pub(crate) enum Kind {
    Webdav,
    Fuse,
}

/// What an `axiom` command line asks for, when it is `mount webdav` or `mount fuse`.
#[derive(Debug, PartialEq)]
pub(crate) struct Invocation {
    pub(crate) kind: Kind,
    pub(crate) vault_path: Option<String>,
    pub(crate) mount_point: Option<String>,
}

pub(crate) fn cmd_mount_list(json: bool) -> Result<()> {
    let mut rows = collect()?;
    rows.sort_by_key(|r| (r.kind, r.pid));
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    println!("KIND\tPID\tSTATE\tADDRESS\tVAULT");
    for r in &rows {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            r.kind,
            r.pid.map_or("-".to_string(), |p| p.to_string()),
            r.state,
            r.address.as_deref().unwrap_or("-"),
            r.vault_path.as_deref().unwrap_or("-"),
        );
    }
    if rows.is_empty() {
        eprintln!("No running axiom mounts found.");
    }
    if rows.iter().any(|r| r.state == "unidentified") {
        eprintln!(
            "note: \"unidentified\" is a FUSE mount under your home directory that \
             could not be attributed to axiom; it may belong to another program."
        );
    }
    Ok(())
}

/// Parse the arguments after `argv[0]`. Global flags may appear anywhere.
pub(crate) fn parse_args<'a>(args: impl IntoIterator<Item = &'a str>) -> Option<Invocation> {
    let mut it = args.into_iter();
    let mut positional = Vec::new();
    let mut vault_path = None;
    while let Some(arg) = it.next() {
        if arg == "--" {
            positional.extend(it.by_ref());
        } else if arg == "-p" || arg == "--path" {
            vault_path = it.next();
        } else if let Some(v) = arg.strip_prefix("--path=") {
            vault_path = Some(v);
        } else if arg == "--password-file" || arg == "--port" {
            it.next();
        } else if let Some(v) = arg.strip_prefix("-p").filter(|v| !v.starts_with('-')) {
            vault_path = Some(v.strip_prefix('=').unwrap_or(v));
        } else if !arg.starts_with('-') {
            positional.push(arg);
        }
    }
    let kind = match positional.get(..2)? {
        ["mount", "webdav"] => Kind::Webdav,
        ["mount", "fuse"] => Kind::Fuse,
        _ => return None,
    };
    let mount_point = match kind {
        Kind::Fuse => positional.get(2).map(|s| s.to_string()),
        Kind::Webdav => None,
    };
    Some(Invocation {
        kind,
        vault_path: vault_path.map(str::to_string),
        mount_point,
    })
}

fn is_axiom_binary(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .is_some_and(|n| n.to_string_lossy().starts_with("axiom"))
}

/// Split a NUL-separated `/proc/<pid>/cmdline`.
pub(crate) fn split_cmdline(raw: &[u8]) -> Vec<String> {
    raw.strip_suffix(&[0])
        .unwrap_or(raw)
        .split(|b| *b == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Parse a `/proc/net/tcp` or `tcp6` hex address such as `0100007F:1F90`.
/// The kernel prints each 32-bit word in host byte order.
pub(crate) fn parse_hex_addr(s: &str) -> Option<SocketAddr> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        Some(
            u32::from_str_radix(ip.get(i * 8..i * 8 + 8)?, 16)
                .ok()?
                .to_ne_bytes(),
        )
    };
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// LISTEN rows of a `/proc/net/tcp{,6}` table as (address, socket inode).
pub(crate) fn parse_proc_net_tcp(text: &str) -> Vec<(SocketAddr, u64)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.get(3) != Some(&"0A") {
                return None;
            }
            Some((parse_hex_addr(f.get(1)?)?, f.get(9)?.parse().ok()?))
        })
        .collect()
}

#[derive(Debug, PartialEq)]
pub(crate) struct FuseMount {
    pub(crate) mount_point: String,
    pub(crate) fstype: String,
    pub(crate) source: String,
}

/// FUSE entries of `/proc/<pid>/mountinfo` (`fuse`, `fuse.*`, `fuseblk`).
pub(crate) fn parse_mountinfo(text: &str) -> Vec<FuseMount> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(' ').collect();
            let sep = f.iter().position(|x| *x == "-")?;
            let fstype = *f.get(sep + 1)?;
            if !(fstype == "fuse" || fstype == "fuseblk" || fstype.starts_with("fuse.")) {
                return None;
            }
            Some(FuseMount {
                mount_point: unescape_octal(f.get(4)?),
                fstype: fstype.to_string(),
                source: unescape_octal(f.get(sep + 2)?),
            })
        })
        .collect()
}

/// Undo the kernel's `\ooo` escaping of space, tab, newline and backslash.
fn unescape_octal(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let oct = b.get(i + 1..i + 4).and_then(|d| {
            std::str::from_utf8(d)
                .ok()
                .and_then(|d| u8::from_str_radix(d, 8).ok())
        });
        match (b[i], oct) {
            (b'\\', Some(v)) => {
                out.push(v);
                i += 4;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `ps -o pid=,uid=,args=` output into (pid, uid, args).
#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_ps(text: &str) -> Vec<(u32, u32, String)> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let pid = f.next()?.parse().ok()?;
            let uid = f.next()?.parse().ok()?;
            Some((pid, uid, f.collect::<Vec<_>>().join(" ")))
        })
        .collect()
}

/// Addresses from `lsof -Fn` output (`n127.0.0.1:8080`, `n[::1]:8080`).
#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_lsof_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix('n'))
        .map(str::to_string)
        .collect()
}

fn webdav_row(pid: u32, vault_path: Option<String>, addrs: Vec<String>) -> MountRow {
    MountRow {
        kind: "webdav",
        pid: Some(pid),
        vault_path: vault_path.map(|p| escape_display(&p)),
        state: if addrs.is_empty() {
            "starting"
        } else {
            "listening"
        },
        address: (!addrs.is_empty()).then(|| escape_display(&addrs.join(","))),
    }
}

#[cfg(target_os = "linux")]
fn collect() -> Result<Vec<MountRow>> {
    linux::collect()
}

#[cfg(target_os = "macos")]
fn collect() -> Result<Vec<MountRow>> {
    macos::collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect() -> Result<Vec<MountRow>> {
    anyhow::bail!("mount list is supported only on Linux and macOS")
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::HashSet;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    pub(super) fn collect() -> Result<Vec<MountRow>> {
        let procs = axiom_processes()?;
        let mut rows = Vec::new();
        let mut fuse_procs = Vec::new();
        for (pid, inv) in procs {
            match inv.kind {
                Kind::Webdav => {
                    let addrs = listening_addrs(pid).iter().map(|a| a.to_string()).collect();
                    rows.push(webdav_row(pid, inv.vault_path, addrs));
                }
                Kind::Fuse => fuse_procs.push((pid, inv)),
            }
        }

        let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let home = dirs::home_dir();
        for m in parse_mountinfo(&mountinfo) {
            let owner = fuse_procs
                .iter()
                .position(|(_, inv)| inv.mount_point.as_deref() == Some(m.mount_point.as_str()))
                .map(|i| fuse_procs.remove(i));
            let identified = m.fstype.starts_with("fuse.axiom")
                || m.source.starts_with("axiom")
                || owner.is_some();
            let under_home = home
                .as_ref()
                .is_some_and(|h| Path::new(&m.mount_point).starts_with(h));
            if !identified && !under_home {
                continue;
            }
            let (pid, vault_path) =
                owner.map_or((None, None), |(p, inv)| (Some(p), inv.vault_path));
            rows.push(MountRow {
                kind: "fuse",
                pid,
                vault_path: vault_path.map(|p| escape_display(&p)),
                address: Some(escape_display(&m.mount_point)),
                state: if identified {
                    "mounted"
                } else {
                    "unidentified"
                },
            });
        }
        // A FUSE process with no mount yet is still waiting for its password.
        for (pid, inv) in fuse_procs {
            rows.push(MountRow {
                kind: "fuse",
                pid: Some(pid),
                vault_path: inv.vault_path.map(|p| escape_display(&p)),
                address: None,
                state: "starting",
            });
        }
        Ok(rows)
    }

    /// `mount webdav` and `mount fuse` processes of the current uid, with
    /// relative paths resolved against each process's working directory.
    fn axiom_processes() -> Result<Vec<(u32, Invocation)>> {
        let my_uid = fs::metadata("/proc/self")?.uid();
        let me = std::process::id();
        let mut out = Vec::new();
        for entry in fs::read_dir("/proc")?.filter_map(|e| e.ok()) {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == me || entry.metadata().map(|m| m.uid()).ok() != Some(my_uid) {
                continue;
            }
            let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            let args = split_cmdline(&raw);
            let exe = fs::read_link(format!("/proc/{pid}/exe"))
                .map(|p| p.to_string_lossy().into_owned())
                .ok()
                .or_else(|| args.first().cloned())
                .unwrap_or_default();
            if !is_axiom_binary(&exe) {
                continue;
            }
            let Some(mut inv) = parse_args(args.iter().skip(1).map(String::as_str)) else {
                continue;
            };
            let cwd = fs::read_link(format!("/proc/{pid}/cwd")).ok();
            inv.vault_path = inv.vault_path.map(|p| resolve(cwd.as_ref(), p));
            inv.mount_point = inv.mount_point.map(|p| resolve(cwd.as_ref(), p));
            out.push((pid, inv));
        }
        Ok(out)
    }

    fn resolve(cwd: Option<&PathBuf>, path: String) -> String {
        match cwd {
            Some(cwd) if Path::new(&path).is_relative() => cwd
                .join(path.trim_start_matches("./"))
                .display()
                .to_string(),
            _ => path,
        }
    }

    /// Listening TCP sockets owned by `pid`, from its own network namespace.
    pub(super) fn listening_addrs(pid: u32) -> Vec<SocketAddr> {
        let inodes: HashSet<u64> = fs::read_dir(format!("/proc/{pid}/fd"))
            .into_iter()
            .flatten()
            .filter_map(|e| fs::read_link(e.ok()?.path()).ok())
            .filter_map(|l| {
                l.to_str()?
                    .strip_prefix("socket:[")?
                    .strip_suffix(']')?
                    .parse()
                    .ok()
            })
            .collect();
        ["tcp", "tcp6"]
            .iter()
            .filter_map(|t| fs::read_to_string(format!("/proc/{pid}/net/{t}")).ok())
            .flat_map(|text| parse_proc_net_tcp(&text))
            .filter(|(_, inode)| inodes.contains(inode))
            .map(|(addr, _)| addr)
            .collect()
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use anyhow::Context;
    use std::process::Command;

    /// macOS has no mountinfo, so only WebDAV servers are reported.
    pub(super) fn collect() -> Result<Vec<MountRow>> {
        let ps = Command::new("ps")
            .args(["-axww", "-o", "pid=,uid=,args="])
            .output()
            .context("Failed to run ps")?;
        let procs = parse_ps(&String::from_utf8_lossy(&ps.stdout));
        let me = std::process::id();
        let my_uid = procs
            .iter()
            .find(|(pid, _, _)| *pid == me)
            .map(|(_, uid, _)| *uid)
            .context("Could not find the current process in ps output")?;
        let mut rows = Vec::new();
        for (pid, uid, args) in procs {
            let mut tokens = args.split_whitespace();
            if uid != my_uid || pid == me || !tokens.next().is_some_and(is_axiom_binary) {
                continue;
            }
            let Some(inv) = parse_args(tokens).filter(|i| i.kind == Kind::Webdav) else {
                continue;
            };
            let lsof = Command::new("lsof")
                .args([
                    "-nP",
                    "-iTCP",
                    "-sTCP:LISTEN",
                    "-a",
                    "-p",
                    &pid.to_string(),
                    "-Fn",
                ])
                .output()
                .context("Failed to run lsof")?;
            let addrs = parse_lsof_names(&String::from_utf8_lossy(&lsof.stdout));
            rows.push(webdav_row(pid, inv.vault_path, addrs));
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Option<Invocation> {
        parse_args(s.split(' '))
    }

    #[test]
    fn parses_webdav_cmdline_with_global_flags() {
        let raw =
            b"/usr/bin/axiom\0--password-file\0/home/u/.pw\0mount\0webdav\0-p\0./v\0--port\09090\0";
        let argv = split_cmdline(raw);
        assert_eq!(argv[0], "/usr/bin/axiom");
        let inv = parse_args(argv.iter().skip(1).map(String::as_str)).unwrap();
        assert_eq!(inv.kind, Kind::Webdav);
        assert_eq!(inv.vault_path.as_deref(), Some("./v"));
        assert_eq!(inv.mount_point, None);
    }

    #[test]
    fn parses_path_forms_and_rejects_other_commands() {
        let p = |s| args(s).unwrap().vault_path;
        assert_eq!(p("mount webdav --path=/a b").as_deref(), Some("/a"));
        assert_eq!(
            p("-v mount webdav --path /x --password-file f").as_deref(),
            Some("/x")
        );
        assert_eq!(p("mount webdav -p/y").as_deref(), Some("/y"));
        assert_eq!(p("mount webdav -p=/z").as_deref(), Some("/z"));
        assert!(args("mount list").is_none());
        assert!(args("vault open -p /v").is_none());
        assert!(args("--password-file mount webdav").is_none());
    }

    #[test]
    fn parses_fuse_mount_point() {
        let inv = args("mount fuse -p /v --read-only /home/u/mnt").unwrap();
        assert_eq!(inv.kind, Kind::Fuse);
        assert_eq!(inv.mount_point.as_deref(), Some("/home/u/mnt"));
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn parses_proc_net_tcp_addresses() {
        assert_eq!(
            parse_hex_addr("0100007F:1F90"),
            Some("127.0.0.1:8080".parse().unwrap())
        );
        assert_eq!(
            parse_hex_addr("00000000000000000000000001000000:1F90"),
            Some("[::1]:8080".parse().unwrap())
        );
        assert_eq!(parse_hex_addr("zz:1F90"), None);

        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
            0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0 100 0 0 10 0\n   \
            1: 0100007F:A1B2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 4343 1 0 20 4 30 10 -1\n";
        assert_eq!(
            parse_proc_net_tcp(table),
            vec![("127.0.0.1:8080".parse().unwrap(), 4242)]
        );
    }

    #[test]
    fn parses_fuse_entries_from_mountinfo() {
        let text = "\
22 1 0:21 / /proc rw,nosuid shared:5 - proc proc rw
45 22 0:40 / /sys/fs/fuse/connections rw - fusectl fusectl rw
98 30 0:52 / /home/u/my\\040mnt rw,nosuid,nodev shared:60 - fuse.axiomvault axiomvault rw,user_id=1000
99 30 0:53 / /home/u/other rw - fuse.sshfs host:/ rw
";
        assert_eq!(
            parse_mountinfo(text),
            vec![
                FuseMount {
                    mount_point: "/home/u/my mnt".into(),
                    fstype: "fuse.axiomvault".into(),
                    source: "axiomvault".into(),
                },
                FuseMount {
                    mount_point: "/home/u/other".into(),
                    fstype: "fuse.sshfs".into(),
                    source: "host:/".into(),
                },
            ]
        );
    }

    #[test]
    fn parses_ps_and_lsof_output() {
        let ps =
            "  412   501 /usr/local/bin/axiom mount webdav -p /Users/u/v\n  1 0 /sbin/launchd\n";
        assert_eq!(
            parse_ps(ps)[0],
            (
                412,
                501,
                "/usr/local/bin/axiom mount webdav -p /Users/u/v".to_string()
            )
        );
        assert_eq!(
            parse_lsof_names("p412\nf7\nn127.0.0.1:8080\nf8\nn[::1]:8080\n"),
            vec!["127.0.0.1:8080", "[::1]:8080"]
        );
    }

    #[test]
    fn row_json_shape_and_states() {
        let starting = webdav_row(7, Some("/v\u{1b}".into()), vec![]);
        let listening = webdav_row(8, None, vec!["127.0.0.1:8080".into()]);
        let v = serde_json::to_value([&starting, &listening]).unwrap();
        assert_eq!(
            v[0],
            serde_json::json!({
                "kind": "webdav", "pid": 7, "vault_path": "/v\\u{1b}",
                "address": null, "state": "starting"
            })
        );
        assert_eq!(v[1]["state"], "listening");
        assert_eq!(v[1]["address"], "127.0.0.1:8080");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finds_own_listening_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(linux::listening_addrs(std::process::id()).contains(&addr));
    }
}
