-- Allow-Deny IP rules: an ordered list of allow/deny rules checked at
-- connection accept, before TLS. `cidr` is a canonical `IpNet` string
-- ("1.2.3.4/32" for a single host, "10.0.0.0/8" for a range; IPv6
-- likewise). A rule matches iff the peer's IP is contained in `cidr`.
--
-- Match order is by `position` ascending (lower wins), so admins can
-- insert an allow-exception ahead of a broader deny. The default when
-- nothing matches is allow (fail-open) — matching the shipped behavior
-- of the reference server and the intent that this is a targeted
-- ban/exception tool, not a firewall.
CREATE TABLE ip_rules (
    id          TEXT    PRIMARY KEY,               -- UUID v4
    position    INTEGER NOT NULL,                  -- lower = higher priority
    action      TEXT    NOT NULL CHECK (action IN ('allow', 'deny')),
    cidr        TEXT    NOT NULL,                  -- canonical IpNet string
    note        TEXT    NOT NULL DEFAULT '',
    created_by  TEXT    NOT NULL,
    created_at  INTEGER NOT NULL                   -- unix seconds
);

CREATE INDEX idx_ip_rules_position ON ip_rules (position);
