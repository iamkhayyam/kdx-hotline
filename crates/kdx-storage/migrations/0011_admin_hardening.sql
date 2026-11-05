-- Admin / authorization hardening.

-- News replies are looked up, and cascade-deleted, by parent. Without an
-- index every cascaded delete scans the whole table.
CREATE INDEX idx_news_posts_parent ON news_posts (parent_id);

-- A reply must live in its parent's newsgroup; inserts enforce that from now
-- on. Detach any older cross-group replies (they become thread roots in their
-- own group) so deleting a post can never cascade into another group.
UPDATE news_posts
SET parent_id = NULL
WHERE parent_id IS NOT NULL
  AND newsgroup_id IS NOT (
      SELECT p.newsgroup_id FROM news_posts p WHERE p.id = news_posts.parent_id
  );

-- Class thresholds are 0 (guest) to 3 (admin). A larger value made a group
-- invisible to everyone, admins included; clamp so admins can see it again.
UPDATE newsgroups SET min_read_class = 3 WHERE min_read_class > 3;
UPDATE newsgroups SET min_post_class = 3 WHERE min_post_class > 3;

-- Class of the account that set a ban, so a lower-ranked banner can extend a
-- ban but never shorten one set by a higher rank. Existing bans count as
-- admin-set.
ALTER TABLE bans ADD COLUMN banned_by_class INTEGER NOT NULL DEFAULT 3;

-- Live-editable server settings (name, description, greeting, max users),
-- persisted so a restart doesn't revert them. Rows here override the config
-- file's defaults.
CREATE TABLE server_settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- Role holders are looked up by role when a role is edited or deleted.
CREATE INDEX idx_account_roles_role ON account_roles (role_id);
