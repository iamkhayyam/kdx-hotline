# KDX

A modern, from-scratch Rust rebuild of KDX — an early-2000s Hotline-style
TCP chat and file-sharing system. Custom binary protocol over TLS 1.3, a
challenge-response login where the password never leaves the client, chat
rooms with flood protection, a virtual file tree with drop boxes, and
resumable chunked file transfers in both directions. The desktop client is a
Tauri app in the classic KDX black / blood-red / phosphor-green aesthetic.

A full GUI & feature walkthrough — every window, the command/event bridge,
and the machinery behind each feature — lives in
[docs/handoff.html](docs/handoff.html) (open it in a browser).

## Workspace

```
crates/
  kdx-protocol      wire format: 20-byte framed packets, codec, fragmentation, typed messages
  kdx-crypto        Argon2id + channel-bound SCRAM-style login proofs
  kdx-server-core   connection state machine, auth, chat rooms, file tree, transfers, tracker
  kdx-storage       sqlx/SQLite persistence
  kdx-client-core   async client library (zero UI deps), TOFU trust, transfer engines
  kdxd              the server daemon
apps/
  kdx-client        Tauri v2 desktop client (Rust shell + vanilla-JS webview)
```

## Build & test

```sh
cargo build --workspace
cargo test  --workspace     # ~600 tests, no external services needed
```

The Tauri client crate (`apps/kdx-client/src-tauri`) needs the platform
webview SDK to build — on Linux the GTK/WebKit dev packages
(`libwebkit2gtk-4.1-dev libgtk-3-dev`); add `--exclude kdx-client` to build
and test only the server, protocol and client library. The webview's JS has
its own checks:

```sh
node apps/kdx-client/scripts/check-escaping.mjs
node --test apps/kdx-client/tests/*.test.mjs
```

## Run the server

```sh
# Create an account (guest | user | power | admin; default user). The
# password is prompted for without echo; scripts can pipe it in instead
# with --password-stdin:
cargo run -p kdxd -- useradd phraq --prompt power
printf '%s\n' "$PASS" | cargo run -p kdxd -- useradd phraq --password-stdin power

# Start the server (defaults to 0.0.0.0:10700 with a self-signed dev cert):
cargo run -p kdxd
```

Both commands default to a `kdx.db` SQLite file and a `files/` directory in
the working directory (`useradd` prints the database it wrote to). Pass a
TOML config path to either to override — relative paths in it are resolved
against the config file's directory. (Upgrading: earlier versions resolved a
relative `database` / `files_root` against the working directory instead. If
such a path now points at nothing while the old location holds data, kdxd
refuses to start and names both paths; make the setting absolute.) See
`crates/kdxd/kdxd.example.toml` for every field with its default value, or
`Config` in `crates/kdxd/src/config.rs` for the definitions (bind address, TLS cert
paths, session TTL, upload/download throttles, connection limits,
`public_host`). kdxd refuses to run as root unless given `--allow-root`.

## Run the client

```sh
cargo run -p kdx-client
```

A small **KDX launcher** window opens — a floating control strip that opens
every feature window. Each feature (Connect, Public Chat, Files, Transfers,
News, …) lives in its **own floating window**: drag it anywhere on the
desktop, resize from any edge (look for the corner triangle), minimize to
the Dock, or close it independently. In the **Connect** window enter the
server host (`127.0.0.1`), port (`10700`), and your account. On first contact
you'll get a **trust-on-first-use** prompt showing the server's certificate
fingerprint — this is expected against a self-signed dev server. The dev
certificate is cached next to the database (`dev-cert.der` / `dev-key.der`),
so the fingerprint stays the same across restarts until you delete those
files. Trust it to continue.
After login you're placed in `#lobby`; use the **Files** window to browse,
upload, and download, and the **Transfers** window shows a live per-chunk
bitmap.

`cargo run -p kdx-client` serves the bundled `apps/kdx-client/dist` frontend
directly — no Node toolchain required.

## Package & distribute

Both products are packaged per-OS by the CI workflow
(`.github/workflows/release.yml`): a GitHub Release (tag `v*`) or manual run
attaches a client installer and a server zip for **macOS, Windows, and Linux**
(all built on their native runners).

### Client installers (Tauri)

| Platform | Artifact |
|---|---|
| macOS | `KDX_0.1.0_*.dmg` (drag the app to Applications) |
| Windows | `KDX_0.1.0_x64-setup.exe` (NSIS, per-user install) |
| Linux | `kdx_0.1.0_amd64.deb` + `kdx_0.1.0_amd64.AppImage` |

Build locally (requires the target OS):

```sh
cargo install tauri-cli --version '^2'
cd apps/kdx-client/src-tauri
cargo tauri icon icons/source-1024.png   # regenerate the icon set
cargo tauri build                        # .app + .dmg on macOS; NSIS on Windows; deb/AppImage on Linux
```

Note (macOS): if the dmg step fails with `Not enough arguments. Run
'create-dmg --help'` — a tauri-bundler quirk in its embedded create-dmg
script — the `.app` is already built; finish the dmg manually:

```sh
cd target/release/bundle/dmg
sh bundle_dmg.sh --volname "KDX" KDX_0.1.0_aarch64.dmg ../macos/KDX.app
```

#### macOS: App Sandbox, signing, notarization

The macOS app runs in the **App Sandbox** (`entitlements.plist`: sandbox,
outbound network, and the file picked in the Open/Save dialog — nothing
else). Everything KDX stores — pinned server keys, partial downloads and
their resume state (`transfers/`), the webview's bookmarks/settings — lives
in its container (`~/Library/Containers/net.kdx.hotline.client/`);
Address Book passwords are in the login keychain. A download is written to
the chosen file only once its whole-file hash verifies. A first sandboxed
launch moves an earlier unsandboxed build's state into the container
(`container-migration.plist`).

Entitlements only apply to a **signed** bundle. `tauri.conf.json` sets
`signingIdentity: "-"`, so every `cargo tauri build` is ad-hoc signed (with
the hardened runtime) and sandboxed; `cargo tauri dev` / `cargo run` are
not. For distribution, sign with a Developer ID and notarize by setting
`APPLE_SIGNING_IDENTITY` (plus `APPLE_CERTIFICATE` /
`APPLE_CERTIFICATE_PASSWORD` in CI) and `APPLE_ID` / `APPLE_PASSWORD` /
`APPLE_TEAM_ID`; until then, users open the downloaded app once via System
Settings → Privacy & Security → *Open Anyway*. Details, verification
commands and the manual macOS test checklist:
[docs/packaging.html](docs/packaging.html#macos).

### Server (kdxd)

Each release carries `kdxd-<os>.zip`: the release binary, `kdxd.example.toml`,
and the matching service file (`net.kdx.hotline.server.plist` on macOS,
`kdxd.service` on Linux). Install:

- **macOS**: `sudo cp kdxd /usr/local/bin/` — run manually
  (`kdxd kdxd.toml`) or as a launchd daemon with the included plist, which
  runs it as the `_kdx` role account (the comment at the top of the plist
  has the one-time account and `/var/kdx` setup).
- **Linux**: `sudo cp kdxd /usr/local/bin/` + the systemd unit
  (`sudo cp kdxd.service /etc/systemd/system/`), create the `kdx` user
  (`useradd --system --home-dir /var/lib/kdx --no-create-home --shell
  /usr/sbin/nologin kdx`; systemd creates `/var/lib/kdx` itself, mode 0700)
  and `/etc/kdx/kdxd.toml` from the example with `database =
  "/var/lib/kdx/kdx.db"` and `files_root = "/var/lib/kdx/files"`, then
  `systemctl enable --now kdxd`. Add accounts as the service user:
  `sudo -u kdx kdxd useradd NAME --prompt admin /etc/kdx/kdxd.toml`.
- **Windows**: copy `kdxd.exe` anywhere; run `kdxd kdxd.toml` (the example
  config documents every option).

Local server build: `cargo build -p kdxd --release` → `target/release/kdxd`.



## Security notes

- Transport is TLS 1.3 only (rustls, ALPN `kdx/1`). The client pins each
  server's public key trust-on-first-use; a changed key needs explicit,
  typed confirmation and never logs in automatically.
- Login (protocol v2) is a SCRAM-SHA-256-style proof over an Argon2id-salted
  password, bound to the TLS session with a TLS exporter value. The password
  never crosses the wire, a relayed proof fails on any other connection, and
  the client verifies a server signature before trusting the login. The
  server stores only the salt, KDF parameters, `StoredKey` and `ServerKey`:
  a copy of the database is not enough to log in (it still permits offline
  guessing at Argon2id cost, so keep it private — kdxd creates it `0600`).
  Failed logins are throttled per address and per address+username.
- The server bounds every client-controlled size and rate (frame and
  reassembly caps, input lengths, per-connection pacing, connection caps,
  handshake/idle/write timeouts, room and transfer limits) and runs as an
  unprivileged user (it refuses to start as root without `--allow-root`).
- The self-signed dev certificate is for local testing only; supply real
  certificates via config for any real deployment. The cached dev key is
  written `0600` and refused if its permissions are loosened.

## Status

The full KDX feature list — tracker directory, account management, news,
file ops, transfers — is implemented and tested. A GUI & feature
walkthrough lives in [docs/handoff.html](docs/handoff.html); the
distribution work-order (packaging metadata, icon set, entitlements,
service files) is tracked in [docs/packaging.html](docs/packaging.html).
