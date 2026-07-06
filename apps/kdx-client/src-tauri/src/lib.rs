//! KDX Tauri shell. Keeps the Rust side dumb: every command forwards to the
//! client-core `ClientHandle`, and a single spawned task forwards core events
//! to the webview.

mod commands;
mod state;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::trust,
            commands::login,
            commands::join_room,
            commands::leave_room,
            commands::send_chat,
            commands::set_topic,
            commands::list_files,
            commands::list_users,
            commands::get_user_info,
            commands::send_private,
            commands::upload,
            commands::download,
            commands::disconnect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running KDX");
}
