# Dolphin mount implementation plan

Goal: ordinary Dolphin read/write access to a Google Drive vault using FUSE,
started by the user session and recoverable after transient provider failure.
Spec: complete owner brief in /home/christian/.openrig/shared-docs/briefs/axiom-dolphin-mount.md.
Execution and sensible defaults are preapproved; lead writes CLI, core partner owns core,
independent review checks exact heads, installation and fixture effects.

## Decisions and constraints

- Reuse the existing Google Drive credential resolver and generic FUSE VaultSession.
  WebDAV also currently opens only local vaults and is less like a normal folder.
- No dependencies, vault-format changes, remote publication or original-meta mutations.
- Privacy override from operator-person at 15:04Z: do not persist passwords in
  KWallet/Secret Service. Prompt with kdialog on login/remount, keep only in memory.
  No unattended unlock after reboot is claimed. Cancellation must suppress retries.
- Only synthetic vaults, private worktree fixture paths and targeted fixture GUI access.
- Builds/tests/checks through lessor, worktree target and TMPDIR; final build must
  explicitly patch all Git-pinned core packages to the paired local candidate.

## Work

- [x] Add failing CLI tests: local vs Drive source exclusivity, required folder,
  tokens/client flags only with Drive, GUI password vs password-file conflict.
- [x] Add smallest FUSE source selection; reuse gdrive open helper. Retain signal
  handling and owner-only access. Test GUI output failure/cancel/empty handling
  without exposing secret stdout/stderr, and mount-list parsing for new flags.
- [x] Add user-level desktop helper and unit: setup privately collects identifiers,
  runs GUI password prompt in native mount process, merges a named Places entry
  with backup and concurrent-update checks. No real profile/unit starts by agent.
  Use Restart=always for external unmount; cancellation exits with a dedicated
  non-restarting status. Retry provider failures without tight loops.
- [x] Test helper with controlled state and synthetic fixture. Preserve all Places,
  unrelated profile/unit state and older binary backups. Install fuse binary as
  ~/.local/bin/axiom with axiom.bak and recoverable preimage manifest.
- [ ] Prove synthetic user-unit start/readiness, Dolphin read/write/rename and
  unmount/remount bytes; simulate provider failure only inside fixture.
- [ ] Run fmt, clippy, check, full tests; record exact source pairing and artifact
  hash. Obtain independent exact candidate and installed-effect review, fix defects.
- [ ] Commit locally with Lore decisions. Deliver one human-only setup command,
  installation paths/hashes, undo instructions and honest limits to operator queue.

## Review focus

Cancellation must not cause repeated password dialogs; unit active is not mount
readiness; failed writes must not silently lose data; external unmount must restart;
Places and binary backups must preserve concurrent and prior user state.
