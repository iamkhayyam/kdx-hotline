CREATE TABLE accounts (
    id            TEXT    PRIMARY KEY,               -- UUID v4
    username      TEXT    NOT NULL UNIQUE,
    password_phc  TEXT    NOT NULL,                  -- Argon2id PHC string
    base_class    INTEGER NOT NULL DEFAULT 1,        -- 0 guest, 1 user, 2 power user, 3 admin
    granted       INTEGER NOT NULL DEFAULT 0,        -- privilege bits granted beyond class
    revoked       INTEGER NOT NULL DEFAULT 0,        -- privilege bits revoked from class
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
