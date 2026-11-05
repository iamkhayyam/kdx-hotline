//! Address Book passwords, kept in the OS credential store (macOS Keychain,
//! Windows Credential Manager, Secret Service on Linux) instead of the
//! webview's plaintext localStorage.
//!
//! The webview can save or delete a bookmark's secret but never read it back:
//! `login` loads it on the Rust side, and only for the server and login it
//! was saved for, so a bookmark's password can't be replayed against another
//! host by re-pointing the Connect form.

use serde::{Deserialize, Serialize};

const SERVICE: &str = "net.kdx.hotline.client";

/// What we store per bookmark: the password plus the server/login it belongs
/// to.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct SecretRecord {
    pub host: String,
    pub port: u16,
    pub login: String,
    pub password: String,
}

impl SecretRecord {
    /// Only usable for the exact server and login it was saved for.
    pub fn password_for(self, host: &str, port: u16, login: &str) -> Result<String, String> {
        if self.host.eq_ignore_ascii_case(host) && self.port == port && self.login == login {
            Ok(self.password)
        } else {
            Err("the saved password belongs to a different server or login — type it instead"
                .to_string())
        }
    }
}

/// Bookmark ids come from the webview: keep them to a boring shape so they
/// can't collide with or address anything else in the credential store.
pub fn valid_bookmark_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn entry(id: &str) -> Result<keyring::Entry, String> {
    if !valid_bookmark_id(id) {
        return Err("invalid bookmark id".to_string());
    }
    keyring::Entry::new(SERVICE, &format!("bookmark:{id}")).map_err(|e| e.to_string())
}

/// Store a bookmark's password. `Err` means the system credential store is
/// unavailable (or refused); the caller reports "not saved".
pub fn save(id: &str, record: &SecretRecord) -> Result<(), String> {
    let json = serde_json::to_string(record).map_err(|e| e.to_string())?;
    entry(id)?.set_password(&json).map_err(|e| e.to_string())
}

/// Load a bookmark's record; `Ok(None)` if nothing is stored.
pub fn load(id: &str) -> Result<Option<SecretRecord>, String> {
    match entry(id)?.get_password() {
        Ok(json) => serde_json::from_str(&json)
            .map(Some)
            .map_err(|_| "the saved password is unreadable — type it instead".to_string()),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Forget a bookmark's password (missing is fine).
pub fn delete(id: &str) -> Result<(), String> {
    match entry(id)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> SecretRecord {
        SecretRecord {
            host: "kdx.example".into(),
            port: 10700,
            login: "phraq".into(),
            password: "s3cret".into(),
        }
    }

    #[test]
    fn password_only_for_its_own_server_and_login() {
        assert_eq!(record().password_for("KDX.example", 10700, "phraq").unwrap(), "s3cret");
        assert!(record().password_for("evil.example", 10700, "phraq").is_err());
        assert!(record().password_for("kdx.example", 10701, "phraq").is_err());
        assert!(record().password_for("kdx.example", 10700, "admin").is_err());
    }

    #[test]
    fn bookmark_ids_are_constrained() {
        assert!(valid_bookmark_id("3f2a9c1e-0b7d-4c1a-9e55-1d2b3c4d5e6f"));
        assert!(!valid_bookmark_id(""));
        assert!(!valid_bookmark_id("a:b"));
        assert!(!valid_bookmark_id("../x"));
        assert!(!valid_bookmark_id(&"a".repeat(65)));
        assert!(entry("bad id").is_err());
    }

    /// Touches the real OS credential store, so it's opt-in
    /// (`cargo test -p kdx-client -- --ignored`): saving either works and
    /// round-trips, or fails cleanly (no Secret Service, locked keychain) —
    /// never panics or hangs.
    #[test]
    #[ignore]
    fn real_store_round_trips_or_degrades() {
        let id = "kdx-selftest-0000";
        match save(id, &record()) {
            Ok(()) => {
                assert_eq!(load(id).unwrap(), Some(record()));
                delete(id).unwrap();
                assert_eq!(load(id).unwrap(), None);
            }
            Err(e) => {
                eprintln!("credential store unavailable (degrades to 'not saved'): {e}");
                assert!(load(id).is_err() || load(id).unwrap().is_none());
            }
        }
    }

    #[test]
    fn record_round_trips_as_json() {
        let json = serde_json::to_string(&record()).unwrap();
        assert_eq!(serde_json::from_str::<SecretRecord>(&json).unwrap(), record());
    }
}
