//! Live-editable server identity: the subset of configuration a SysOp can
//! change remotely without a restart (name, description, login greeting,
//! advertised capacity). Everything else — bind address, TLS, database path,
//! transfer throttles — is fixed at process start, same as `port` here, which
//! is carried only for display in the Server Settings window.
//!
//! Settings built with [`ServerSettings::load`] are persisted: values saved
//! by an admin override the config file's defaults and survive a restart
//! (STORE-14). [`ServerSettings::new`] is memory-only, for tests.

use kdx_storage::SqlitePool;
use tokio::sync::RwLock;
use tracing::warn;

use crate::limits;

const KEY_NAME: &str = "name";
const KEY_DESCRIPTION: &str = "description";
const KEY_GREETING: &str = "greeting";
const KEY_MAX_USERS: &str = "max_users";

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    /// A value failed validation; the text is safe to show the client.
    #[error("{0}")]
    Invalid(String),
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
}

#[derive(Debug, Clone)]
pub struct SettingsSnapshot {
    pub name: String,
    pub description: String,
    pub greeting: String,
    pub max_users: u32,
}

struct Inner {
    name: String,
    description: String,
    greeting: String,
    max_users: u32,
}

pub struct ServerSettings {
    inner: RwLock<Inner>,
    /// Where updates are persisted; `None` for memory-only settings.
    pool: Option<SqlitePool>,
}

impl ServerSettings {
    /// Memory-only settings (nothing persisted).
    pub fn new(name: String, description: String, max_users: u32) -> Self {
        Self {
            inner: RwLock::new(Inner {
                name,
                description,
                greeting: String::new(),
                max_users,
            }),
            pool: None,
        }
    }

    /// Settings backed by the database: start from the config defaults, then
    /// apply whatever an admin saved earlier. A stored value that no longer
    /// validates is ignored (with a warning) in favor of the default.
    pub async fn load(
        pool: SqlitePool,
        name: String,
        description: String,
        max_users: u32,
    ) -> Result<Self, SettingsError> {
        let mut inner = Inner {
            name,
            description,
            greeting: String::new(),
            max_users,
        };
        for (key, value) in kdx_storage::settings::all(&pool).await? {
            let valid = match key.as_str() {
                KEY_NAME => validate_name(&value).map(|()| inner.name = value),
                KEY_DESCRIPTION => limits::check_len(
                    "server description",
                    &value,
                    limits::MAX_SERVER_DESCRIPTION_LEN,
                )
                .map(|()| inner.description = value),
                KEY_GREETING => limits::check_len("greeting", &value, limits::MAX_GREETING_LEN)
                    .map(|()| inner.greeting = value),
                KEY_MAX_USERS => value
                    .parse::<u32>()
                    .map(|n| inner.max_users = n)
                    .map_err(|e| e.to_string()),
                _ => Ok(()),
            };
            if let Err(reason) = valid {
                warn!(key = %key, reason = %reason, "ignoring stored server setting");
            }
        }
        Ok(Self {
            inner: RwLock::new(inner),
            pool: Some(pool),
        })
    }

    /// Check the text fields of a settings update (OPS-11): a name is
    /// required and every field is length-capped, so no setting can push the
    /// login greeting or a settings reply past what the wire can carry.
    pub fn validate(name: &str, description: &str, greeting: &str) -> Result<(), String> {
        validate_name(name)?;
        limits::check_len("server description", description, limits::MAX_SERVER_DESCRIPTION_LEN)?;
        limits::check_len("greeting", greeting, limits::MAX_GREETING_LEN)?;
        Ok(())
    }

    pub async fn snapshot(&self) -> SettingsSnapshot {
        let inner = self.inner.read().await;
        SettingsSnapshot {
            name: inner.name.clone(),
            description: inner.description.clone(),
            greeting: inner.greeting.clone(),
            max_users: inner.max_users,
        }
    }

    /// The login greeting only (the hot path on every successful auth,
    /// so it skips building an unused snapshot).
    pub async fn greeting(&self) -> String {
        self.inner.read().await.greeting.clone()
    }

    /// Replace all four live-editable fields at once (a settings-dialog Save,
    /// not a partial patch). Validates first; persists before changing the
    /// live values, holding the write lock throughout so concurrent saves
    /// land in the same order in memory and on disk.
    pub async fn update(
        &self,
        name: String,
        description: String,
        greeting: String,
        max_users: u32,
    ) -> Result<(), SettingsError> {
        Self::validate(&name, &description, &greeting).map_err(SettingsError::Invalid)?;
        let mut inner = self.inner.write().await;
        if let Some(pool) = &self.pool {
            let max_users_text = max_users.to_string();
            kdx_storage::settings::put_all(
                pool,
                &[
                    (KEY_NAME, name.as_str()),
                    (KEY_DESCRIPTION, description.as_str()),
                    (KEY_GREETING, greeting.as_str()),
                    (KEY_MAX_USERS, max_users_text.as_str()),
                ],
            )
            .await?;
        }
        inner.name = name;
        inner.description = description;
        inner.greeting = greeting;
        inner.max_users = max_users;
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("server name is required".into());
    }
    limits::check_len("server name", name, limits::MAX_SERVER_NAME_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshot_reflects_updates() {
        let settings = ServerSettings::new("Original".into(), "desc".into(), 100);
        let before = settings.snapshot().await;
        assert_eq!(before.name, "Original");
        assert_eq!(before.greeting, "");

        settings
            .update("Renamed".into(), "new desc".into(), "hi".into(), 50)
            .await
            .unwrap();
        let after = settings.snapshot().await;
        assert_eq!(after.name, "Renamed");
        assert_eq!(after.description, "new desc");
        assert_eq!(after.greeting, "hi");
        assert_eq!(after.max_users, 50);
        assert_eq!(settings.greeting().await, "hi");
    }

    #[tokio::test]
    async fn oversized_or_empty_values_are_refused_and_nothing_changes() {
        let settings = ServerSettings::new("Original".into(), String::new(), 10);
        let huge = "g".repeat(limits::MAX_GREETING_LEN + 1);
        assert!(matches!(
            settings.update("Name".into(), String::new(), huge, 10).await,
            Err(SettingsError::Invalid(_))
        ));
        assert!(settings.update("  ".into(), String::new(), String::new(), 10).await.is_err());
        let long_name = "n".repeat(limits::MAX_SERVER_NAME_LEN + 1);
        assert!(settings.update(long_name, String::new(), String::new(), 10).await.is_err());
        let long_desc = "d".repeat(limits::MAX_SERVER_DESCRIPTION_LEN + 1);
        assert!(settings.update("Name".into(), long_desc, String::new(), 10).await.is_err());
        assert_eq!(settings.snapshot().await.name, "Original");
    }

    #[tokio::test]
    async fn persisted_settings_survive_a_reload_and_override_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db")).await.unwrap();

        let first = ServerSettings::load(pool.clone(), "Default".into(), "cfg".into(), 100)
            .await
            .unwrap();
        // Nothing saved yet: the config defaults stand.
        assert_eq!(first.snapshot().await.name, "Default");
        first
            .update("Underground".into(), "warez".into(), "welcome back".into(), 42)
            .await
            .unwrap();

        // A "restart": fresh settings from the same database.
        let second = ServerSettings::load(pool, "Default".into(), "cfg".into(), 100)
            .await
            .unwrap();
        let snap = second.snapshot().await;
        assert_eq!(snap.name, "Underground");
        assert_eq!(snap.description, "warez");
        assert_eq!(snap.greeting, "welcome back");
        assert_eq!(snap.max_users, 42);
    }

    #[tokio::test]
    async fn invalid_stored_values_fall_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db")).await.unwrap();
        let huge = "g".repeat(limits::MAX_GREETING_LEN + 1);
        kdx_storage::settings::put_all(
            &pool,
            &[(KEY_GREETING, huge.as_str()), (KEY_MAX_USERS, "lots"), (KEY_NAME, "")],
        )
        .await
        .unwrap();
        let settings = ServerSettings::load(pool, "Default".into(), String::new(), 7)
            .await
            .unwrap();
        let snap = settings.snapshot().await;
        assert_eq!(snap.greeting, "");
        assert_eq!(snap.max_users, 7);
        assert_eq!(snap.name, "Default");
    }
}
