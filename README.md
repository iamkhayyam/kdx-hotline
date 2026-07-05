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
cargo test  --workspace     # ~110 tests, no external services needed
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
`Config` in `crates/kdxd/src/config.rs` for the fields (bind address, TLS cert
paths, session TTL, upload/download throttles).

## Run the client

```sh
cargo run -p kdx-client
```

A KDX desktop window opens. In the **Connect** window enter the server host
(`127.0.0.1`), port (`10700`), and your account. On first contact you'll get a
**trust-on-first-use** prompt showing the server's certificate fingerprint —
this is expected against a self-signed dev server; the fingerprint changes each
time the dev server restarts. Trust it to continue. After login you're placed
in `#lobby`; use the **Files** window to browse, upload, and download, and the
**Transfers** window shows a live per-chunk bitmap.

`cargo run -p kdx-client` serves the bundled `apps/kdx-client/dist` frontend
directly — no Node toolchain required.

## Package the client (macOS)

```sh
cargo install tauri-cli --version '^2'
cd apps/kdx-client/src-tauri
cargo tauri icon icons/icon.png      # generate the full icon set incl. .icns
cargo tauri build                    # produces a .app and .dmg
```

The repo ships a placeholder icon so `cargo run` works out of the box; run
`cargo tauri icon` before `cargo tauri build` for a full icon set.

## Security notes

- Transport is TLS 1.3 (rustls). The client pins server certificates
  trust-on-first-use, warning loudly if a previously-trusted key changes.
- Passwords are stored as Argon2id hashes. Login is challenge-response: the
  client answers `SHA-256(challenge ‖ argon2id-verifier)`, so the plaintext
  password never crosses the wire.
- The self-signed dev certificate is for local testing only; supply real
  certificates via config for any real deployment.

## Not yet implemented

- The tracker (server directory) exists in `kdx-server-core` but has no
  client-facing wire protocol yet, so there's no Tracker window in the client.
- Account management beyond the `kdxd useradd` CLI (no in-app admin UI).
