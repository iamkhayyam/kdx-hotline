# Changelog

All notable changes to KDX. Versions follow [Semantic Versioning](https://semver.org/);
while the major version is 0, a minor bump may break compatibility.

## [0.2.0] - 2026-11-05

A security and robustness release: the server, protocol, client library and
desktop app were audited end to end and hardened, and the gaps the audit left
open were closed.

> **Breaking:** wire protocol **v2**. 0.2.0 clients and servers can't talk to
> 0.1.x. Upgrade both sides. Existing account databases are converted
> automatically on first start.

### Security
- **Login is now a SCRAM-style proof bound to the TLS session.**
  - The password never crosses the wire: not at login, password change, admin
    reset or account creation.
  - A login can't be relayed to another server.
  - The client verifies a server signature before trusting the result.
  - The server stores only a salted, Argon2id-derived verifier, so a copy of
    the database can't be used to log in.
- **Login throttling** per IP address and per address+username, a username
  length cap, and keyed decoy salts so unknown usernames can't be detected.
- **Authorization:**
  - Delegated admins can no longer escalate themselves or demote admins, and
    the last admin can't be demoted.
  - Privilege changes disconnect the affected user.
  - A login still in progress is re-checked against demotions, bans and IP
    rules when it completes.
- **File tree:**
  - Access rules are inherited from parent folders.
  - Drop boxes can't be emptied by moving or deleting their contents.
  - Recursive deletes check every item they remove.
  - Deep folder chains can't crash the server.
  - Uploading into a folder you can't list no longer reveals which file names
    exist there.
- **Availability:**
  - Oversized messages are fragmented instead of disconnecting everyone.
  - Session cleanup always runs.
  - Connection caps (global and per IP), plus TLS handshake, idle and write
    timeouts.
  - Per-connection pacing and per-command rate limits.
  - Bounded rooms, history and transfers.
- **At rest:**
  - The database, the dev TLS key and uploaded files are owner-only (0600/0700).
  - kdxd refuses to run as root unless given `--allow-root`.
  - TLS 1.3 only, with ALPN `kdx/1`.
- **Desktop app:**
  - One HTML escaper used everywhere, enforced by a lint.
  - A strict CSP and a navigation guard.
  - Per-window command permissions.
  - File dialogs run in Rust.
  - A changed server key needs a typed confirmation before you can connect.
  - Bookmark passwords are kept in the OS keychain.
  - Delete and shutdown confirmations that actually block (they were silently
    skipped before).
  - macOS: the app runs in the App Sandbox.

### Added
- Password change for users and password reset for admins.
- Ban list with unban; newsgroup edit and delete.
- The login result carries the session's effective privileges. The app shows
  each control only to sessions that have the privilege it needs.
- Transfer cancel; uploads finish crash-safely and recover at startup.
  Orphaned files are moved to quarantine, then purged after
  `orphan_retention_days` (default 30).
- Release builds: macOS Developer ID signing and notarization once the Apple
  repository secrets are set (see `docs/packaging.html#macos`), the `kdxd`
  binary is signed on macOS, `SHA256SUMS` is published, and CI checks every
  pull request.

### Changed
- Config: relative `database` and `files_root` paths now resolve against the
  config file's directory. kdxd refuses to start if it finds data at the old
  working-directory location. Use absolute paths in service configs.
- `session_ttl_secs` is now an idle timeout. Sessions no longer expire by age.
- `kdxd useradd` reads the password from a prompt or `--password-stdin`. A
  password given on the command line still works but prints a warning.
- Server certificate pins are now hashes of the server's public key (SPKI).
  Existing pins are migrated automatically.
- Downloads keep partial data in the app's own data directory, not next to
  the destination file. In-progress downloads from 0.1.x restart.

### Upgrade notes
1. Stop the server, back up `kdx.db` and `files/`, and install 0.2.0. The
   first start converts stored passwords to the new format.
2. Use absolute paths for `database` and `files_root` in your config.
3. Upgrade every client: 0.1.x clients can't log in to a 0.2.0 server.

## [0.1.0]

Initial development builds. Never tagged.

[0.2.0]: https://github.com/iamkhayyam/kdx-hotline/releases/tag/v0.2.0
