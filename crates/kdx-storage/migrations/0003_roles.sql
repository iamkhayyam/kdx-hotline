CREATE TABLE roles (
    id          TEXT    PRIMARY KEY,               -- UUID v4
    name        TEXT    NOT NULL UNIQUE,
    privileges  INTEGER NOT NULL DEFAULT 0,        -- Privileges bitmask granted by this role
    rank        INTEGER NOT NULL DEFAULT 0,        -- display order, higher = closer to admin
    color       TEXT,                              -- optional hex color for GUI display
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE account_roles (
    account_id  TEXT    NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role_id     TEXT    NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (account_id, role_id)
);
