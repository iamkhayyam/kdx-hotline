-- Protocol v2 login: accounts store a SCRAM-style credential (salt, Argon2
-- params, StoredKey, ServerKey; see kdx-crypto::scram) instead of the
-- password-equivalent Argon2 PHC string. Rows written before this migration
-- keep `password_phc` until the server converts them at startup, after which
-- `password_phc` is '' and `credential` is set.
ALTER TABLE accounts ADD COLUMN credential TEXT;

-- Per-server random secrets (e.g. the key for unknown-user decoy salts).
-- Generated once, never sent to clients.
CREATE TABLE server_secrets (
    name  TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
