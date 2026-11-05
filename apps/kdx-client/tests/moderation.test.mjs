// Moderation UI logic (dist/js/moderation.js): who is offered Unban and the
// newsgroup admin controls, and the client-side checks before a request.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ADMIN_CLASS,
  canManageNewsgroups,
  canLiftBan,
  banRemaining,
  filterBans,
  truncationNote,
  newsgroupFormError,
} from "../dist/js/moderation.js";

const ban = (banned_by, banned_by_class, extra = {}) => ({
  username: "lamer",
  until: 2_000,
  reason: "flood",
  banned_by,
  banned_by_class,
  ...extra,
});

test("unban is offered by the same rule the server applies", () => {
  const mod = { username: "mod", class: 2 };
  // A higher class's ban, or a peer's, is out of reach.
  assert.equal(canLiftBan(mod, ban("sysop", 3)), false);
  assert.equal(canLiftBan(mod, ban("othermod", 2)), false);
  // One's own ban, or a lower class's, is not.
  assert.equal(canLiftBan(mod, ban("mod", 2)), true);
  assert.equal(canLiftBan(mod, ban("helper", 1)), true);
  // A banner since demoted below the ban's class can't undo it.
  assert.equal(canLiftBan({ username: "mod", class: 1 }, ban("mod", 2)), false);
  // Admins lift anything, other admins' bans included.
  assert.equal(canLiftBan({ username: "sysop", class: ADMIN_CLASS }, ban("root", 3)), true);
  // No session (not hydrated yet) or junk data: never offered.
  assert.equal(canLiftBan(null, ban("x", 0)), false);
  assert.equal(canLiftBan(mod, null), false);
  assert.equal(canLiftBan({ username: "mod" }, ban("x", 0)), false);
  assert.equal(canLiftBan(mod, ban("x", "0")), false);
});

test("newsgroup admin controls follow the Admin class", () => {
  assert.equal(canManageNewsgroups({ username: "sysop", class: 3 }), true);
  assert.equal(canManageNewsgroups({ username: "helpdesk", class: 2 }), false);
  assert.equal(canManageNewsgroups(null), false);
  assert.equal(canManageNewsgroups(undefined), false);
});

test("time left on a ban is short and never negative", () => {
  assert.equal(banRemaining(1_045, 1_000), "45s");
  assert.equal(banRemaining(1_000 + 12 * 60 + 5, 1_000), "12m");
  assert.equal(banRemaining(1_000 + 3 * 3600, 1_000), "3h");
  assert.equal(banRemaining(1_000 + 5 * 86400 + 7, 1_000), "5d");
  assert.equal(banRemaining(900, 1_000), "0s");
  assert.equal(banRemaining("junk", 1_000), "0s");
});

test("the ban filter matches user, banner and reason", () => {
  const bans = [
    ban("sysop", 3, { username: "Lamer", reason: "Flooding" }),
    ban("mod", 2, { username: "zero", reason: "spam" }),
  ];
  assert.equal(filterBans(bans, "").length, 2);
  assert.deepEqual(filterBans(bans, "lam").map((b) => b.username), ["Lamer"]);
  assert.deepEqual(filterBans(bans, "MOD").map((b) => b.username), ["zero"]);
  assert.deepEqual(filterBans(bans, "flood").map((b) => b.username), ["Lamer"]);
  assert.deepEqual(filterBans(bans, "nobody"), []);
  const copy = filterBans(bans, "  ");
  assert.notEqual(copy, bans, "always a new array");
});

test("a cut ban list says so", () => {
  assert.equal(truncationNote({ total: 2, bans: [ban("a", 3), ban("b", 3)] }), "");
  assert.equal(truncationNote({ total: 0, bans: [] }), "");
  assert.match(truncationNote({ total: 900, bans: [ban("a", 3)] }), /1 longest of 900/);
  assert.equal(truncationNote(null), "");
});

test("newsgroup fields are checked like the server does", () => {
  const ok = { name: "general", description: "", readClass: 0, postClass: 1 };
  assert.equal(newsgroupFormError(ok), null);
  assert.match(newsgroupFormError({ ...ok, name: "   " }), /required/);
  assert.equal(newsgroupFormError({ ...ok, name: "n".repeat(64) }), null);
  assert.match(newsgroupFormError({ ...ok, name: "n".repeat(65) }), /too long/);
  // Bytes, not characters: 22 three-byte characters are 66 bytes.
  assert.match(newsgroupFormError({ ...ok, name: "€".repeat(22) }), /too long/);
  assert.match(newsgroupFormError({ ...ok, description: "d".repeat(1025) }), /description/);
  assert.match(newsgroupFormError({ ...ok, readClass: 4 }), /between 0 and 3/);
  assert.match(newsgroupFormError({ ...ok, postClass: -1 }), /between 0 and 3/);
  assert.match(newsgroupFormError({ ...ok, postClass: NaN }), /between 0 and 3/);
});
