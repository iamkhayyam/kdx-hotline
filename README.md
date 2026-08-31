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
  kdx-crypto        Argon2id password hashing + challenge-response
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
cargo test  --workspace     # 243 tests, no external services needed
```

## Run the server

```sh
# Create an account (guest | user | power | admin; default user):
cargo run -p kdxd -- useradd phraq s3cret power

# Start the server (defaults to 0.0.0.0:10700 with a self-signed dev cert):
cargo run -p kdxd
```

Both commands default to a `kdx.db` SQLite file and a `files/` directory in
the working directory. Pass a TOML config path to either to override — see
`crates/kdxd/kdxd.example.toml` for every field with its default value, or
`Config` in `crates/kdxd/src/config.rs` for the definitions (bind address,
TLS cert paths, session TTL, upload/download throttles).

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
fingerprint — this is expected against a self-signed dev server; the
fingerprint changes each time the dev server restarts. Trust it to continue.
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

### Server (kdxd)

Each release carries `kdxd-<os>.zip`: the release binary, `kdxd.example.toml`,
and the matching service file (`net.kdx.hotline.server.plist` on macOS,
`kdxd.service` on Linux). Install:

- **macOS**: `sudo cp kdxd /usr/local/bin/` — run manually
  (`kdxd kdxd.toml`) or as a launchd agent with the included plist.
- **Linux**: `sudo cp kdxd /usr/local/bin/` + the systemd unit
  (`sudo cp kdxd.service /etc/systemd/system/`), create the `kdx` user and
  `/etc/kdx/kdxd.toml` from the example, then `systemctl enable --now kdxd`.
- **Windows**: copy `kdxd.exe` anywhere; run `kdxd kdxd.toml` (the example
  config documents every option).

Local server build: `cargo build -p kdxd --release` → `target/release/kdxd`.



## Security notes

- Transport is TLS 1.3 (rustls). The client pins server certificates
  trust-on-first-use, warning loudly if a previously-trusted key changes.
- Passwords are stored as Argon2id hashes. Login is challenge-response: the
  client answers `SHA-256(challenge ‖ argon2id-verifier)`, so the plaintext
  password never crosses the wire.
- The self-signed dev certificate is for local testing only; supply real
  certificates via config for any real deployment.

## Status

The full KDX feature list — tracker directory, account management, news,
file ops, transfers — is implemented and tested. A GUI & feature
walkthrough lives in [docs/handoff.html](docs/handoff.html); the
distribution work-order (packaging metadata, icon set, entitlements,
service files) is tracked in [docs/packaging.html](docs/packaging.html).
