# Original Haxial KDX 1.520 — Design Reference

Distilled from the official `Documentation.pdf` (32 pp) and `Generic Documentation.pdf` (13 pp)
found in `Haxial-KDX-main.zip` (github.com/profdrluigi/haxial-kdx). The archive contains the
original closed-source binaries (Win/Linux), the two manuals, ~100 `.hap` appearance themes,
and 11 `.fnt` bitmap fonts. **No source code** — its value is as a feature/UX/visual spec.

Unlike the contradictory legacy spec docs in `docs/legacy/`, this is the *actual shipped
product's* manual, with screenshots. Treat it as the authority on what original KDX did.

---

## 1. Visual language (from screenshots)

- **Chrome:** dark blood-red title bars and window frames over near-black panel interiors.
  Grey/silver beveled buttons. Input fields are pure black with **green monospace text**
  (terminal style) and a red border when focused (keyboard focus = red outline).
- **Window anatomy:** title bar contains `X` (close, left), a hatched **Window Menu** button
  (left of title; also opened by right-clicking the title bar), `+` (maximize) and `−`
  (minimize/dock) on the right. Resize grip is a hatched triangle in the bottom-right corner.
  Minimized windows collect into a small **Dock** window (title + one row per window).
- **Default button:** one button per dialog drawn with an extra outline; Enter activates it,
  Escape activates Cancel.
- **WonderLight™:** a small status LED. On the Button Bar (next to "Messages") it blinks on
  unread messages. In Voice Controls: grey = mic off, red = mic on but silence, green = sending.
- **User list rows:** [class color bar (vertical, ~4px)] [32×32 user icon] [name in user's
  chosen color] `▶` [description]. Row background can be user-colored too. Class colors by
  convention: black = guest, blue = user, red = admin.
- **Server icon:** 152×40 banner pasted by admin, displayed at top of Button Bar when connected.
- **Theming:** entire GUI is themeable via `.hap` appearance files (custom Haxial GUI engine,
  binary format). Theme names worth stealing for palette presets: TRON, Amber CRT, Matrix Ice,
  Terminal-MONO/NEO/TRON, BeOS, MacOS Classic, Night-Vision, Blue Print, Cybernet.

## 2. Window inventory (client)

| Window | Purpose | Our status (2026-07) |
|---|---|---|
| **Button Bar** | Main vertical launcher: Commands, Connect, Address Book, Messages (+WonderLight), File Transfers, News, User List, Exit. Footer: connection count + active transfer count. Server banner on top when connected. Has "Small Button Bar" horizontal icons-only mode. | partial (menubar approach) |
| **Connect** | Type (Server/Client/Tracker/Auto-Detect), Name (label), Address, Login, Password. Blank login = guest. | ✅ have |
| **User List** | All users on server; context menu: Send Message, Get Info, Copy Description, Invite To New Chat, Disconnect. | partial (in chat window) |
| **Public/Private Chat** | Transcript + input + user-list side pane + Topic bar (topic setter + timestamp shown). Window menu: Show Files/News/User List, Invite Users, Clear Text, Save Window Location/Size, Last Chat. | ✅ have (no topic bar) |
| **News** | Tree pane (servers → newsgroups) + message pane. Post Message; admins create/edit newsgroups (name, description, archive-size KB, per-class read/post access). Self-delete of own most-recent message allowed. | ❌ |
| **Files** | Hierarchy pane (folders only) + file list pane. Context: Get Info, Copy Name, Download, Launch Program (remote exec!), Select for Move/Alias → Move into / Alias into, Upload into, Refresh, Create Folder, Delete. Window menu adds **Search** (server-side catalog, instant). Item count shown as `[N]`. | partial (no move/alias/search/info) |
| **Create Folder** | Name + radio: Normal / Uploads / Drop Box (+ DB owner login). | ❌ |
| **Address Book** | Bookmarks: name, address, login/pw, comments, Connect-At-Startup, per-bookmark window-open prefs, Encrypt File Transfers toggle. Columns incl. **Connects** count and **Last Connect** time. Type-to-filter. | ❌ (we have last-server memory only) |
| **File Transfers** | Queue rows: file icon, LED, name @ server, progress bar with % , `speed (Lmt X), done/total, ETA`. Start/Stop (Esc), Re-queue, Show/Open Local File, reorder (Ctrl-arrows), Remove. Per-server download+upload queues (option: single global queue). Auto-clear finished option. | ✅ have (simpler) |
| **Private Messages** | One window, multi-conversation: left pane = people, right = transcript per person, bottom input. Left bar turns RED on unread from that user, black once read. | ❌ (chat only) |
| **User Info** | Account name/login/class, login time, idle since (with `[DD:HH:MM:SS]` ago), address:port, live list of the user's transfers (speed, done, total, ETA). Refresh button. | ❌ |
| **Invite To Chat** | Multi-select users + message; invitees get accept/ignore popup. | ❌ |
| **Disconnect User** | Message to victim + ban duration menu (bans expire) + Disconnect / Force Disconnect. | ❌ |
| **Settings** | Panels: **Identity** (name, description, fg/bg colors, 32×32 icon via clipboard paste), **General** (sound lists, volume, auto-sort downloads by type, single-click lists, broadcast-to-messages, ping, queue mode, auto-clear, auto-switch user list, small button bar), **More** (windows-at-startup ticks, DCC port, UPnP, start hidden), **Appearance** (.hap picker, small icons toggles), **Voice** (devices, push-to-talk key, volume overdrive to 400%). Save/Apply/Cancel. | partial |
| **Get Server Info** | Server name/description/etc; more detail for admins. | ❌ |
| **Voice Controls / Voice Info** | DCC-based voice chat: rate menu (5512 Hz…44100 Hz w/ bandwidth), latency ms, silence sensitivity, per-person volume 0–200%, data sent/recv counters. Conference = full mesh (everyone DCCs everyone). | ❌ (out of scope for now) |
| **Accounts** | Admin: list of accounts *or* classes (Show toggle + Create Account). Account editor: class dropdown, color, **two columns of tri-state ticks** (account-override vs class value; On/Off/No-Change) over grouped privileges (File System, …). List shows `+`/`−`/`+/−` override indicators next to class name. | ❌ (CLI useradd only) |
| **Server History** | Live event log table: Date/Time, Type (Get File List, Join Chat…), User Name, User Login. Optional journal-to-disk (tab-separated files in `History/`). | ❌ client-side (server logs exist) |
| **Connection Monitor** | All raw connections + status (a user = N rows). Optional auto-refresh every X s. | ❌ |
| **Process Monitor / View-Control Display** | Remote process list + remote screen view/control. **Skip — remote-admin surface we don't want.** | — |
| **Server Settings** | *Edited from the client* (remote admin): name, description, DNS address, server icon, total outgoing speed limit (shared/divided), greeting text; Port panel (main 10700, alternate port, separate file-transfer port); Allow/Deny IP rules (wildcards, ordered first-match, auto-expiry; bans land here); History journaling; Trackers panel (register with trackers: address, login, up to 6 group names). | ❌ (config file only) |
| **Broadcast** | Admin message popup to everyone (option to route into Messages window instead). | ❌ |
| **Shutdown Server** | Remote: message-to-all + Exit / Restart computer / Shutdown computer. Support Exit only. | ❌ |

## 3. UX conventions (Haxial house style)

- **Context menus are the primary verb surface** — nearly every list row has one
  ("second-click"). Also used on non-selectable text → "Copy Text To Clipboard".
- **Window Menu** per window for window-scoped commands (incl. "Save Window Location/Size"
  which persists geometry + pane sizes + column layout as the default for future windows).
- **Type-to-filter:** typing into a focused list opens a filter box, hides non-matching rows.
- **Columns:** click header = sort (selected column tinted), drag divider = resize,
  context menu = reorder.
- **Window Switcher:** F1 / Ctrl-Shift-W popup listing all windows.
- **Keyboard:** Ctrl-W close, Esc = clear chat input / stop transfer / Cancel,
  Enter = send / default button, Delete = remove transfer row, Ctrl-Delete = clear finished.
- **Single-click lists by default** ("Haxial is opposed to the abuse of mice") — double-click
  is an opt-in setting.
- All timestamps shown in **local time**, converted per-viewer.

## 4. Chat slash-commands

`/me <text>` (action, `*** Name text`), `/me's <text>` (possessive action), `/name` `/n`,
`/desc` `/d`, `/away` `/a` (Zzz badge), `/back` `/b`, `/afk`. Both `/` and `\` accepted.

## 5. Server-side concepts worth adopting

- **Account Classes** with per-account tri-state overrides (On/Off/Inherit) — our class
  column is a string today; this is the natural evolution for S-side accounts + a client
  Accounts window.
- **Folder Access Items:** named privilege bundles; a folder opts in via `Name [item]`
  suffix. Defaults: `[Default]` (admin-write, world-read, inherited down the tree),
  `[UL]` uploads (anyone up+down, only admin delete), `[DB]` dropbox (write-only unless
  owner/admin; optional owner login). Effective permission = account/class privilege AND
  folder item (both must allow).
- **Chat room flags:** per-class access, Interview Mode (suppress join/leave/rename spam),
  voice flag, IRC gateway (bridge a room to an IRC channel). Temporary private chats
  auto-vanish when empty.
- **Flood protection:** per-class strictness; warn → disconnect+ban. Also connection-rate
  banning by IP.
- **Search catalog:** search hits a pre-generated catalog, not the live FS
  (admin "Generate Catalog" command; fails on alias loops).
- **Bans = expiring deny rules** in the Allow/Deny list (ordered, wildcard, first-match).
- **News archiving:** old messages rotate into text files by size threshold.
- **Greeting** message on connect (+ "Don't Show Greeting" privilege).
- **Speed limit:** one total outgoing cap divided evenly among active downloads.
- **Tracker registration:** server pushes itself to trackers under up to 6 group names;
  client tracker flow = connect → group list ("General") → server list → click to connect.
- Default port **10700**; optional alternate port and separate file-transfer port.

## 6. What we deliberately do differently (do not "fix" back)

- TLS 1.3 (rustls) instead of the original app-layer crypto; 20-byte header; SCRAM-style
  auth — approved decisions, see memory/plan.
- No remote process control, no View/Control Display, no remote "Launch Program",
  no restart/shutdown-computer — remote-admin attack surface intentionally dropped.
- Voice chat / DCC / UPnP: deferred, not planned.

## 7. Companion repos in `_github/`

### Haxial-ref-main.zip — clean-room protocol RE project (C, Ghidra)
A third-party effort to rebuild KDX *binary-compatible* by reverse-engineering
`KDXServer.lexe`. Early-stage: a small `libhaxial` C library (SHA-1, Blowfish, FNV-1a,
Pascal strings, RNG cloned from the binary) plus `docs/protocol/findings/` from Ghidra.
**Licensing: LGPL-3.0/GPL-3.0 — do not copy code into this repo.** The *facts* it
establishes about the original wire protocol:

- Packet magic `PXTP` (0x50585450), max packet size 2048 bytes, Pascal strings
  (u8 length prefix) throughout.
- Handshake states 1=initial, 3=retry, 4=authenticated, 8=failed; handshake encrypted
  with 16-round Blowfish (constant 0x4878); passwords hashed with **SHA-1**.
- Error-code taxonomy: `0x1xxxx` system, `0x2xxxx` memory, `0x3xxxx` filesystem,
  `0x4xxxx` network; many-to-one errno coalescing (27-code catalog).
- Ports: server 10700; tracker port reported as 10800 in one doc, 11177 in another
  (unresolved by them — verify empirically if we ever care).

Relevance to us is **confirmatory, not prescriptive**: it proves the original crypto was
SHA-1 + Blowfish (weak — validates our decision to discard compat and go TLS 1.3 + SCRAM).
We are *intentionally* wire-incompatible, so PXTP framing details don't bind us. The error
taxonomy and the tracker-port hint are the only design nuggets worth borrowing.

### docker-kdx-server-master.zip — original server in Docker
Tiny repo: Ubuntu 24.04 image with i386 multi-arch (incl. arm64 path via libstdc++5 deb)
that downloads and runs the **original KDXServer 1.620** Linux binary, with preloaded
`KDXServer.stg`/`Accounts.dat` (default login `admin`/`admin`), port 10700. Its value is
as a **live behavioral oracle**: `docker build && docker run -p 10700:10700` gives a real
KDX server to poke at with the original client from `Haxial-KDX-main.zip` (via Wine/i386)
whenever we need ground truth on semantics the manual leaves vague (folder access
resolution, news archiving, account-class overrides, flood-protection thresholds).
Note it fetches v1.620 — slightly newer than the 1.520 manual.

## 8. Binary assets — status

`.hap` (appearance), `.fnt` (font), `KDX.stg` (settings incl. registration) are undocumented
Haxial binary formats. Reverse-engineering them is **not** worth it for the rebuild; instead,
mine the theme *names/screenshots* for CSS palette presets. The archive's binaries could be
run (32-bit, or Wine) as a live behavioral reference if a protocol question ever needs
ground truth — but our protocol is intentionally incompatible, so this is rarely useful.
