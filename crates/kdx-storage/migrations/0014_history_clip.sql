-- History hardening. Rows written before actor/detail were capped at record
-- time can hold attacker-sized strings (e.g. ~16 KB usernames from failed
-- logins), which bloat the table and can make the admin history window too
-- large to send. Clip them to the record-time policy limits (64 / 512).
-- substr() counts characters, not bytes, so a clipped value is at most 64 /
-- 512 characters (256 / 2048 bytes) and is never cut inside a character.
UPDATE history SET actor = substr(actor, 1, 64) WHERE length(actor) > 64;
UPDATE history SET detail = substr(detail, 1, 512) WHERE length(detail) > 512;
