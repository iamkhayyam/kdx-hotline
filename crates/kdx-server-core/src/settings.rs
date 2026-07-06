//! Live-editable server identity: the subset of configuration a SysOp can
//! change remotely without a restart (name, description, login greeting,
//! advertised capacity). Everything else — bind address, TLS, database path,
//! transfer throttles — is fixed at process start, same as `port` here, which
//! is carried only for display in the Server Settings window.

use tokio::sync::RwLock;

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
}

impl ServerSettings {
    pub fn new(name: String, description: String, max_users: u32) -> Self {
        Self {
            inner: RwLock::new(Inner {
                name,
                description,
                greeting: String::new(),
                max_users,
            }),
        }
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
    /// not a partial patch).
    pub async fn update(&self, name: String, description: String, greeting: String, max_users: u32) {
        let mut inner = self.inner.write().await;
        inner.name = name;
        inner.description = description;
        inner.greeting = greeting;
        inner.max_users = max_users;
    }
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
            .await;
        let after = settings.snapshot().await;
        assert_eq!(after.name, "Renamed");
        assert_eq!(after.description, "new desc");
        assert_eq!(after.greeting, "hi");
        assert_eq!(after.max_users, 50);
        assert_eq!(settings.greeting().await, "hi");
    }
}
