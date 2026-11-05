// Pure helpers behind the moderation UI: the Bans window and the News
// window's newsgroup Edit/Delete controls. No DOM, no Tauri — unit-tested
// in tests/moderation.test.mjs. The server enforces every rule here; these
// only decide what the UI offers.

/** Base class of an Admin (0 guest, 1 user, 2 power user, 3 admin). */
export const ADMIN_CLASS = 3;

/** Server caps (crates/kdx-server-core/src/limits.rs), in UTF-8 bytes. */
export const MAX_NEWSGROUP_NAME_BYTES = 64;
export const MAX_NEWSGROUP_DESCRIPTION_BYTES = 1024;

/**
 * Whether to show newsgroup admin controls (Edit / Delete) to `session`.
 * The login result carries only the account's class, not its privileges,
 * so USER_ADMIN is approximated by the Admin class (which holds it unless
 * revoked). A delegated USER_ADMIN below Admin doesn't get the controls;
 * the server checks the real privilege either way.
 */
export function canManageNewsgroups(session) {
  return !!session && session.class === ADMIN_CLASS;
}

/**
 * Whether `session` may lift `ban` — the mirror of the server's rule
 * (auth::policy::may_lift_ban): any Admin; a class strictly above the one
 * that set the ban; or whoever set it, at the same class or above. (The
 * server also refuses to act on an account above the caller's class, which
 * the ban list doesn't show; a refusal then comes back as an error.)
 */
export function canLiftBan(session, ban) {
  if (!session || !ban) return false;
  const mine = session.class;
  const theirs = ban.banned_by_class;
  if (!Number.isInteger(mine) || !Number.isInteger(theirs)) return false;
  return (
    mine === ADMIN_CLASS ||
    mine > theirs ||
    (session.username === ban.banned_by && mine >= theirs)
  );
}

/** Time left on a ban that runs until `until` (unix seconds), at `nowSecs`:
 * "45s", "12m", "3h", "5d". A lapsed ban reads "0s". */
export function banRemaining(until, nowSecs) {
  const left = Math.max(0, Math.floor(Number(until) - Number(nowSecs)) || 0);
  if (left < 60) return `${left}s`;
  if (left < 3600) return `${Math.floor(left / 60)}m`;
  if (left < 86400) return `${Math.floor(left / 3600)}h`;
  return `${Math.floor(left / 86400)}d`;
}

/** Bans whose user, banner or reason contains `needle` (case-insensitive). */
export function filterBans(bans, needle) {
  const n = String(needle ?? "").trim().toLowerCase();
  if (!n) return bans.slice();
  return bans.filter((b) =>
    [b.username, b.banned_by, b.reason].some((f) => String(f ?? "").toLowerCase().includes(n))
  );
}

/** A note when the server cut the ban list (`{ total, bans }`), else "". */
export function truncationNote(list) {
  const shown = list && Array.isArray(list.bans) ? list.bans.length : 0;
  const total = list && Number.isInteger(list.total) ? list.total : shown;
  if (total <= shown) return "";
  return `showing the ${shown} longest of ${total} bans — the rest lapse soonest; unban others by name below`;
}

function utf8Length(s) {
  return new TextEncoder().encode(s).length;
}

/**
 * Check the newsgroup editor's fields the way the server will, so the
 * obvious mistakes get an immediate message. Returns null when they're
 * fine, otherwise the problem. Classes are the select values (0–3).
 */
export function newsgroupFormError({ name, description = "", readClass, postClass }) {
  const n = String(name ?? "");
  if (!n.trim()) return "a newsgroup name is required";
  if (utf8Length(n) > MAX_NEWSGROUP_NAME_BYTES) {
    return `the name is too long (max ${MAX_NEWSGROUP_NAME_BYTES} bytes)`;
  }
  if (utf8Length(String(description ?? "")) > MAX_NEWSGROUP_DESCRIPTION_BYTES) {
    return `the description is too long (max ${MAX_NEWSGROUP_DESCRIPTION_BYTES} bytes)`;
  }
  for (const c of [readClass, postClass]) {
    if (!Number.isInteger(c) || c < 0 || c > ADMIN_CLASS) return "class thresholds must be between 0 and 3";
  }
  return null;
}
