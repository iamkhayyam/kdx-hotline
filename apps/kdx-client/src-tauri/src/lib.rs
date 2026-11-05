//! KDX Tauri shell. Keeps the Rust side dumb: every command forwards to the
//! client-core `ClientHandle`, and a per-connection task forwards core events
//! to the webview.

mod commands;
mod events;
mod sanitize;
mod secrets;
mod state;

use state::AppState;
use tauri::plugin::TauriPlugin;
use tauri::{Runtime, Url};

/// Whether `url` is the app's own bundled frontend. Every KDX window loads
/// `index.html` from the embedded assets; nothing else may ever be shown in
/// a window (injected markup must not be able to swap a borderless KDX
/// window for a look-alike phishing page).
fn is_app_url(url: &Url) -> bool {
    match url.scheme() {
        // macOS / Linux custom protocol.
        "tauri" => url.host_str() == Some("localhost"),
        // Windows / Android serve the custom protocol as http(s)://tauri.localhost.
        "http" | "https" => {
            url.host_str() == Some("tauri.localhost")
                // `tauri dev` serves the frontend from a local dev server.
                || (cfg!(dev) && matches!(url.host_str(), Some("localhost" | "127.0.0.1")))
        }
        _ => false,
    }
}

/// Refuse every navigation away from the app's own origin, in every window.
fn navigation_guard<R: Runtime>() -> TauriPlugin<R> {
    tauri::plugin::Builder::new("kdx-nav-guard")
        .on_navigation(|_webview, url| {
            let allowed = is_app_url(url);
            if !allowed {
                tracing::warn!("blocked navigation to {url}");
            }
            allowed
        })
        .build()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    app_builder(tauri::Builder::default())
        .run(tauri::generate_context!())
        .expect("error while running KDX");
}

/// Plugins, state and commands (shared with the ACL tests).
fn app_builder<R: Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    // Every command below must also be listed in build.rs (the ACL app
    // manifest) and granted to the windows that use it in capabilities/.
    builder
        .plugin(navigation_guard())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::trust,
            commands::login,
            commands::get_session,
            commands::save_secret,
            commands::delete_secret,
            commands::join_room,
            commands::leave_room,
            commands::send_chat,
            commands::set_topic,
            commands::list_files,
            commands::create_folder,
            commands::delete_path,
            commands::move_path,
            commands::alias_path,
            commands::generate_catalog,
            commands::search_files,
            commands::list_users,
            commands::list_servers,
            commands::get_server_settings,
            commands::update_server_settings,
            commands::broadcast,
            commands::shutdown_server,
            commands::list_history,
            commands::list_ip_rules,
            commands::create_ip_rule,
            commands::delete_ip_rule,
            commands::list_connections,
            commands::set_room_flags,
            commands::get_user_info,
            commands::send_private,
            commands::invite_to_chat,
            commands::upload,
            commands::download,
            commands::cancel_transfer,
            commands::disconnect,
            commands::list_roles,
            commands::create_role,
            commands::update_role,
            commands::delete_role,
            commands::assign_role,
            commands::unassign_role,
            commands::account_roles,
            commands::disconnect_user,
            commands::list_accounts,
            commands::create_account,
            commands::update_account,
            commands::list_newsgroups,
            commands::create_newsgroup,
            commands::list_thread,
            commands::create_post,
            commands::delete_post,
            commands::get_file_info,
            commands::set_identity,
            commands::change_password,
            commands::set_account_password,
        ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn app_origin_is_allowed() {
        assert!(is_app_url(&url("tauri://localhost/index.html?win=chat")));
        assert!(is_app_url(&url("http://tauri.localhost/index.html")));
        assert!(is_app_url(&url("https://tauri.localhost/")));
    }

    #[test]
    fn everything_else_is_blocked() {
        for u in [
            "https://evil.example/kdx-login",
            "http://tauri.localhost.evil.example/",
            "tauri://evil.example/",
            "file:///etc/passwd",
            "data:text/html,<h1>hi</h1>",
            "javascript:alert(1)",
            "about:blank",
            "ftp://localhost/",
        ] {
            assert!(!is_app_url(&url(u)), "{u} must be blocked");
        }
    }
}

/// The real ACL (build.rs app manifest + capabilities/) exercised through
/// Tauri's mock runtime: each window may invoke exactly the commands it
/// needs, so script in (say) the Chat window can't download over a file,
/// upload ~/.ssh, pin a key or run admin commands.
#[cfg(test)]
mod acl_tests {
    use super::*;
    use tauri::ipc::{CallbackFn, InvokeBody};
    use tauri::webview::InvokeRequest;
    use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime};
    use tauri::{WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    /// window label → app commands it may invoke (besides `get_session`,
    /// which every window has for hydration).
    const POLICY: &[(&str, &[&str])] = &[
        ("main", &["disconnect", "list_users", "save_secret"]),
        ("connect", &["connect", "trust", "login", "join_room", "change_password"]),
        (
            "chat",
            &[
                "join_room",
                "leave_room",
                "send_chat",
                "set_topic",
                "set_room_flags",
                "set_identity",
                "invite_to_chat",
            ],
        ),
        (
            "files",
            &[
                "list_files",
                "create_folder",
                "delete_path",
                "move_path",
                "alias_path",
                "generate_catalog",
                "search_files",
                "get_file_info",
                "upload",
                "download",
                "cancel_transfer",
            ],
        ),
        ("transfers", &["cancel_transfer"]),
        ("addressbook", &["save_secret", "delete_secret"]),
        ("settings", &[]),
        ("about", &[]),
        ("userlist", &["list_users"]),
        ("userinfo", &["get_user_info"]),
        ("messages", &["send_private"]),
        (
            "admin",
            &[
                "list_roles",
                "create_role",
                "update_role",
                "delete_role",
                "assign_role",
                "unassign_role",
                "account_roles",
                "disconnect_user",
            ],
        ),
        (
            "accounts",
            &["list_accounts", "create_account", "update_account", "set_account_password"],
        ),
        (
            "server",
            &[
                "get_server_settings",
                "update_server_settings",
                "broadcast",
                "shutdown_server",
            ],
        ),
        ("history", &["list_history"]),
        ("iprules", &["list_ip_rules", "create_ip_rule", "delete_ip_rule"]),
        ("connections", &["list_connections"]),
        (
            "news",
            &[
                "list_newsgroups",
                "create_newsgroup",
                "list_thread",
                "create_post",
                "delete_post",
            ],
        ),
        ("trackers", &["list_servers"]),
    ];

    fn mock_app() -> tauri::App<MockRuntime> {
        let mut ctx = mock_context(noop_assets());
        let mut real: tauri::Context<MockRuntime> = tauri::generate_context!(test = true);
        std::mem::swap(ctx.runtime_authority_mut(), real.runtime_authority_mut());
        app_builder(mock_builder()).build(ctx).expect("mock app")
    }

    /// Invoke `cmd` with no arguments. Allowed commands then fail argument
    /// parsing (or "not connected") without touching the network, the disk
    /// or the keychain; denied ones fail the ACL check first.
    fn acl_denied(w: &WebviewWindow<MockRuntime>, cmd: &str) -> bool {
        let url = if cfg!(any(windows, target_os = "android")) {
            "http://tauri.localhost"
        } else {
            "tauri://localhost"
        };
        let res = get_ipc_response(
            w,
            InvokeRequest {
                cmd: cmd.into(),
                callback: CallbackFn(0),
                error: CallbackFn(1),
                url: url.parse().unwrap(),
                body: InvokeBody::Json(serde_json::json!({})),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.to_string(),
            },
        );
        matches!(res, Err(e) if e.to_string().contains("not allowed"))
    }

    #[test]
    fn each_window_gets_exactly_its_commands() {
        let app = mock_app();
        let all: Vec<&str> = POLICY.iter().flat_map(|(_, c)| c.iter().copied()).collect();
        for (label, mine) in POLICY {
            let w = WebviewWindowBuilder::new(&app, *label, WebviewUrl::App("index.html".into()))
                .build()
                .unwrap();
            assert!(!acl_denied(&w, "get_session"), "{label} must hydrate");
            for cmd in &all {
                let expect_allowed = mine.contains(cmd);
                assert_eq!(
                    !acl_denied(&w, cmd),
                    expect_allowed,
                    "window {label:?} command {cmd:?}: expected allowed={expect_allowed}"
                );
            }
        }
    }

    #[test]
    fn unknown_window_gets_nothing() {
        let app = mock_app();
        let w = WebviewWindowBuilder::new(&app, "evil", WebviewUrl::App("index.html".into()))
            .build()
            .unwrap();
        for cmd in [
            "get_session",
            "download",
            "upload",
            "cancel_transfer",
            "trust",
            "connect",
            "shutdown_server",
        ] {
            assert!(acl_denied(&w, cmd), "{cmd} must be denied to an unknown window");
        }
    }
}
