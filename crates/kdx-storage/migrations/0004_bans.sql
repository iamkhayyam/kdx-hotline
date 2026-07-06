-- Expiring account bans. A ban is active while now < `until` (unix seconds);
-- the login path refuses matching accounts and live sessions are dropped when
-- the ban is applied. One row per account (a new ban overwrites the old).
CREATE TABLE bans (
    account_id  TEXT    PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    until       INTEGER NOT NULL,               -- unix seconds; active while now < until
    reason      TEXT    NOT NULL DEFAULT '',
    banned_by   TEXT    NOT NULL DEFAULT '',     -- username of the admin who set it
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
