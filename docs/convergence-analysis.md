# Convergence Analysis — Hotline Connect × KDX Haxial × kdx-hotline

**Date:** 2026-08-21 · **Status:** research complete; gap list is the next-build backlog

Sources: `docs/original-kdx-reference.md` (authoritative, distilled from the official
KDX 1.520 manuals + screenshots), `docs/legacy/*.txt` (protocol/class model), the
original binaries in `docs/legacy/`, `_github/` (Haxial protocol RE + Dockerized
original server), web sources for Hotline Connect ([How to use Hotline — preterhuman wiki](https://wiki.preterhuman.net/index.php?title=How_to_use_Hotline&oldid=4301),
[Hotline Connect at Macintosh Repository](https://www.macintoshrepository.org/6691-hotline-connect-client-server-tracker-),
[Hotline client basics PDF](https://beta.the-eye.eu/public/Books/cdn.preterhuman.net/texts/computing/hotline_info/HLClientBasics.pdf)),
and the current kdx-hotline codebase (verified against the actual implementation).

## Verdict

kdx-hotline has converged on **~85% of the original KDX 1.520 feature surface** and
the core of Hotline Connect. Everything Hotline/KDX *users actually lived in* is
present: chat, news, files with dropboxes/uploads, resumable transfers, private
messages, tracker, address book, full server administration, the four-class model,
bans, broadcast, shutdown. The gaps are the long tail: admin/UX depth items (per-
account privilege overrides, folder access items, remote server ports), a few
client conveniences (Get Info, ETA, type-to-filter everywhere), and features we
**deliberately** do not carry (voice chat, remote process/view control, remote
"Launch Program", DCC/UPnP).

## Feature matrix

Legend: ✅ shipped · ◐ partial · ❌ missing · ⛔ deliberately dropped · ⏳ deferred

### Client — windows & UI

| Hotline Connect | KDX Haxial | kdx-hotline | Notes |
|---|---|---|---|
| Connect window | Connect (Client/Server/Tracker/Auto-detect) | ✅ Connect | ours: client + TOFU; no tracker/auto-detect modes |
| Chat rooms | Public/Private Chat + topic bar | ✅ Chat (+invite) | ❌ topic bar timestamps, "Last Chat", /name /desc |
| News (threaded) | News (tree + threads, archive-size, self-delete) | ✅ News | ❌ archive rotation, ❌ post self-delete |
| Files browser | Files (search catalog, move/alias) | ✅ Files | ⛔ "Launch Program" (remote exec) |
| — | Create Folder (Normal/Uploads/Drop Box + owner) | ✅ kinds | ◐ dropbox owner login not modeled |
| Transfers | File Transfers (queue, ETA, reorder, per-server queues) | ✅ Transfers | ◐ no ETA / reorder / per-server queue |
| Private messages | Private Messages (unread red bars) | ✅ Messages | ✅ |
| User list | User List (verbs: msg/info/invite/disconnect) | ✅ User List | ✅ |
| User info | User Info (idle, live transfer list) | ✅ User Info | ◐ no live transfer list |
| Address book | Address Book (connects count, last connect) | ✅ Address Book | ✅ |
| — | Invite To Chat | ✅ | ✅ |
| — | Disconnect User (ban menu, force) | ✅ | ✅ |
| — | Accounts (class + **tri-state override ticks**) | ✅ Accounts+Roles | ◐ we use roles instead of tri-state overrides |
| — | Server History (journal-to-disk) | ✅ History | ◐ no journal-to-disk |
| — | Connection Monitor (auto-refresh) | ✅ Connections | ◐ no auto-refresh toggle |
| — | Server Settings (remote) | ✅ Server | ◐ no alt / file-transfer port config |
| — | Get Server Info | ❌ | — |
| — | Voice Controls / Voice Info | ⏳ deferred | — |
| — | Process Monitor / View-Control | ⛔ remote-admin surface | — |
| — | Broadcast / Shutdown Server | ✅ | ✅ exit-only shutdown (matches plan) |
| Prefs | Settings (identity/sound/queue/startup/DCC/UPnP) | ✅ Settings | ◐ subset; ⏳ DCC/UPnP |
| — | Button Bar (Small mode, banner, counts) | ✅ launcher | ◐ no Small mode |
| — | WonderLight LED | ✅ Messages LED | ✅ |
| — | Window Switcher F1 / Ctrl-W close | ✅ F1 windows menu | ◐ no Ctrl-W close |

### Server — model & admin

| Concept | Hotline/KDX | kdx-hotline |
|---|---|---|
| Account classes (guest/user/power/admin) | ✅ | ✅ |
| Per-account **tri-state privilege overrides** (On/Off/Inherit) | ✅ KDX | ❌ (roles are an additive bundle instead) |
| Folder **access items** ([Default]/[UL]/[DB] named bundles, `Name [item]` suffix) | ✅ KDX | ❌ (per-node min-class ACLs only) |
| Drop boxes (write-only, owner) | ✅ | ◐ write-only; no owner |
| Chat room flags: join class, interview mode, voice, **IRC gateway** | ✅ KDX | ◐ join class + interview; ❌ voice; ❌ IRC |
| Flood protection: per-class strictness, warn → ban | ✅ | ◐ per-member token bucket; ❌ IP connection-rate ban |
| Bans = expiring allow/deny rules | ✅ | ✅ |
| Search catalog (admin Generate Catalog) | ✅ KDX | ✅ |
| News archiving (rotation by size) | ✅ KDX | ❌ |
| Greeting + "Don't Show Greeting" privilege | ✅ KDX | ◐ greeting; ❌ privilege |
| Speed limit: shared total cap, divided among transfers | ✅ | ◐ per-transfer throttle only |
| Tracker registration (up to 6 groups) | ✅ KDX | ◐ self-registration; ❌ group names |
| Alt port / separate file-transfer port | ✅ KDX | ❌ (single 10700) |
| Server "web pages" (serve HTML in-client) | ✅ Hotline-only | ❌ |
| Post signatures in news | ✅ Hotline | ❌ |
| Per-file "Get Info" (size/type/date…) | ✅ both | ❌ |

### Security & protocol (deliberate divergence, documented)

Original KDX/Hotline used app-layer crypto (Blowfish + SHA-1, PXTP packets, max 2048 B
per packet). kdx-hotline intentionally does **not** chase wire compatibility:
TLS 1.3 + Argon2id + SCRAM-style challenge-response + TOFU pinning, 20-byte framed
packets. The Haxial RE project's error-code taxonomy and tracker-port hints are the
only borrowable facts. This divergence is approved and will not be "fixed back".

## Round log (overnight)

- **Round 2 (P2):** shipped File **Get Info** (wire 0x2D/0x2E, server
  `tree.info()` gated by read ACL, Files window context-menu panel with
  sha256/ACL classes/owner/access item), **Ctrl-W** close, and **/name /desc**
  (wire `SetIdentity` 0x3A, presence roster carries display name +
  description with live rebroadcast; User List + User Info surface them).
  Tests: 250 → 262 green. Two wire bugs caught by integration tests: new
  packet types were missing from `PacketType::try_from` (connection drop) and
  `FileInfoResponse`'s decode length check assumed sha256 always present.
  Stack rebuilt and running.

- **Round 1 (P1-1/P1-2/P1-4):** verified P1-1 already complete end-to-end
  (accounts table `granted`/`revoked` + Accounts-window tri-state editor +
  revoke-wins resolver). Implemented folder access items (`AccessItem` parsed
  from `[db]`/`[ul]`/`[default]` name suffixes, privilege-aware ACLs) and the
  dropbox owner (migration `0009_access_items.sql`, `FileCreateFolder.owner`
  on the wire + client dialog). Threaded the session (class + effective
  privileges + username) through the file tree so overrides now affect files.
  Tests: 243 → 250 green. Stack rebuilt and running; migration applied.

## Gap list — prioritized for convergence

**P1 — admin-model depth:**
1. **Per-account tri-state privilege overrides** — ✅ already shipped (Accounts
   window: Inherit/Grant/Revoke per privilege, `+N/−N` summaries; server
   `effective_privileges = (class | roles | granted) − revoked`, revoke wins).
2. **Folder access items** — ✅ shipped (round 1): `[DB]`/`[UL]`/`[Default]` name
   suffixes parsed at load; `[UL]` = anyone up+down, admin-class delete only;
   `[DB]` = write-only unless owner/admin; ACLs are now privilege-aware so
   account overrides reach the file tree. Tests: acl unit + tree integration.
3. **Remote Server Settings ports** — ❌ still open: alternate port + separate
   file-transfer port (needs listener + config + protocol plumbing).
4. **Dropbox owner** — ✅ shipped (round 1): `owner` column (migration 0009),
   set via the Files → Create Folder dialog, enforced on read/delete for
   drop boxes / `[DB]` folders.

**P2 — client conveniences:**
5. **File "Get Info"** — ✅ shipped (round 2): new `FileInfoRequest/Response`
   wire pair (0x2D/0x2E) + server `tree.info()` + Files context-menu "Get Info"
   panel showing size, sha256, read/write classes, access item, owner. User
   Info **live transfer list** — ❌ still open.
6. **Type-to-filter everywhere** — ◐ partial; **Ctrl-W close** — ✅ (round 2,
   chrome keydown); **/name /desc** — ✅ (round 2): `SetIdentity` wire message
   (0x3A) → session identity in the presence roster → live rebroadcast;
   display name shows in User List + User Info; chat commands wired.
7. **Transfers**: ETA, reorder (Ctrl-arrows), per-server queues — ❌ still open.
8. **Connection Monitor auto-refresh** toggle; **Server History journal-to-disk**
   — ❌ still open.

**P3 — server depth:**
9. Shared total speed cap (divided across active transfers).
10. News archive rotation + post self-delete; post signatures.
11. IP connection-rate banning (flood escalation) — complements the per-member gate.
12. Tracker registration under up to 6 group names.

**Hotline-only extras worth a decision:**
- **Server "web pages"** (serving HTML pages from the file tree, browsable in-client) —
  the one genuinely distinctive Hotline feature neither original KDX nor ours has.
  This is the natural pairing with the Google-Drive-style mounted-folder feature:
  a mounted drive could also serve a `web/` subtree as pages.

**Deliberately not converging (keep as-is):**
- Voice chat / DCC / UPnP (deferred) · remote process/view control, remote
  "Launch Program", restart/shutdown-computer (dropped, remote-admin attack surface)
  · wire-format compatibility with original clients/servers (TLS-1.3-native).

## Next step

Pick P1 items 1–2 (privilege overrides + folder access items) as the next build
milestone — they are the largest remaining *original-KDX* semantics. The mounted-
drive feature (discussed separately) slots in beside them as a new node kind with
folder-item ACLs.
