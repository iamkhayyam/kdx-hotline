//! STORE-14: server settings an admin saves survive a restart, overriding
//! the config file's defaults.

use kdxd::config::Config;
use kdxd::serve;

fn config(dir: &tempfile::TempDir) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        database: dir.path().join("kdx.db"),
        files_root: dir.path().join("files"),
        ..Config::default()
    }
}

#[tokio::test]
async fn saved_settings_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();

    let first = serve(config(&dir)).await.unwrap();
    first
        .ctx
        .settings
        .update("The Underground".into(), "warez".into(), "welcome back".into(), 42)
        .await
        .unwrap();
    first.handle.abort();

    let second = serve(config(&dir)).await.unwrap();
    let snap = second.ctx.settings.snapshot().await;
    assert_eq!(snap.name, "The Underground");
    assert_eq!(snap.description, "warez");
    assert_eq!(snap.greeting, "welcome back");
    assert_eq!(snap.max_users, 42);
    second.handle.abort();
}
