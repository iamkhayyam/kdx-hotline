// Privilege gating (dist/js/privileges.js): the bit constants, the can()
// helpers, and what each window offers a session. The constants' values are
// checked against the Rust `Privileges` bitflags by
// crates/kdx-server-core/tests/privileges_js.rs; here, that the module is
// self-consistent and the gates follow the server's handler checks.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as P from "../dist/js/privileges.js";

const {
  CHAT_SEND,
  CHAT_PRIVATE,
  CHAT_CREATE_ROOM,
  CHAT_SET_TOPIC,
  FILE_LIST,
  FILE_DOWNLOAD,
  FILE_UPLOAD,
  FILE_DELETE,
  FILE_MANAGE_TREE,
  USER_KICK,
  USER_BAN,
  USER_ADMIN,
  SERVER_ADMIN,
  ALL,
  PRIVILEGES,
  can,
  canAny,
  missing,
  privilegesOf,
  canUseWindow,
  WINDOW_PRIVILEGES,
  adminTools,
  peerActions,
  fileTools,
  chatRefusal,
} = P;

// The server's class defaults (kdx-server-core auth::classes::BaseClass).
const GUEST = CHAT_SEND | FILE_LIST;
const USER = GUEST | CHAT_PRIVATE | FILE_DOWNLOAD | FILE_UPLOAD;
const POWER = USER | CHAT_CREATE_ROOM | CHAT_SET_TOPIC | FILE_DELETE | FILE_MANAGE_TREE;

const as = (privileges, extra = {}) => ({ username: "me", class: 1, privileges, ...extra });

test("the privilege list covers every bit constant exactly once", () => {
  const isBit = (v) => typeof v === "number" && v > 0 && (v & (v - 1)) === 0;
  const exported = Object.entries(P)
    .filter(([, v]) => isBit(v))
    .map(([name]) => name)
    .sort();
  assert.deepEqual(PRIVILEGES.map((p) => p.name).sort(), exported);
  for (const p of PRIVILEGES) {
    assert.equal(P[p.name], p.bit, p.name);
    assert.ok(p.label && typeof p.label === "string", p.name);
  }
  assert.equal(new Set(PRIVILEGES.map((p) => p.bit)).size, PRIVILEGES.length, "bits are distinct");
  assert.equal(ALL, PRIVILEGES.reduce((a, p) => a | p.bit, 0));
  assert.equal(ALL, 0x000f01ff, "bits 0–8 and 16–19");
  assert.ok(Object.isFrozen(PRIVILEGES) && Object.isFrozen(PRIVILEGES[0]));
});

test("can() needs every bit, and fails closed", () => {
  const s = as(CHAT_SEND | USER_KICK);
  assert.equal(can(s, CHAT_SEND), true);
  assert.equal(can(s, USER_KICK), true);
  assert.equal(can(s, USER_BAN), false);
  assert.equal(can(s, USER_KICK | USER_BAN), false, "all bits, not any");
  assert.equal(canAny(s, USER_KICK | USER_BAN), true);
  assert.equal(canAny(s, USER_BAN | USER_ADMIN), false);
  // A typo'd constant (undefined) or an empty mask is never granted.
  assert.equal(can(as(ALL), undefined), false);
  assert.equal(can(as(ALL), 0), false);
  assert.equal(canAny(as(ALL), undefined), false);
  // No session, no privileges field (an old login), or junk: nothing.
  for (const bad of [null, undefined, {}, as(undefined), as("524288"), as(-1), as(1.5), as(2 ** 33)]) {
    assert.equal(privilegesOf(bad), 0, JSON.stringify(bad));
    assert.equal(can(bad, CHAT_SEND), false);
    assert.equal(canAny(bad, ALL), false);
  }
  // Every u32 value is accepted as sent.
  assert.equal(privilegesOf(as(0xffffffff)), 0xffffffff);
  assert.equal(can(as(0xffffffff), SERVER_ADMIN), true);
});

test("missing() names the first privilege lacking", () => {
  assert.equal(missing(as(CHAT_SEND), CHAT_SEND), null);
  assert.equal(missing(as(CHAT_SEND), CHAT_SET_TOPIC), "CHAT_SET_TOPIC");
  assert.equal(missing(as(CHAT_SET_TOPIC), CHAT_SET_TOPIC | SERVER_ADMIN), "SERVER_ADMIN");
  assert.equal(missing(null, USER_KICK), "USER_KICK");
  assert.equal(missing(null, 0), null, "nothing needed, nothing missing");
});

test("admin windows open for the privilege their requests need", () => {
  const ids = [...readFileSync(new URL("../dist/js/windows/registry.js", import.meta.url), "utf8").matchAll(/\{ id: "(\w+)"/g)].map(
    (m) => m[1]
  );
  for (const id of Object.keys(WINDOW_PRIVILEGES)) assert.ok(ids.includes(id), `${id} is a real window`);

  const need = {
    accounts: USER_ADMIN,
    server: SERVER_ADMIN,
    history: SERVER_ADMIN,
    iprules: SERVER_ADMIN,
    connections: USER_KICK,
    bans: USER_BAN,
    files: FILE_LIST,
  };
  for (const [id, bit] of Object.entries(need)) {
    assert.equal(canUseWindow(as(bit), id), true, `${id} with its privilege`);
    assert.equal(canUseWindow(as(ALL & ~bit), id), false, `${id} without it`);
  }
  // Administration is a hub: any moderation privilege opens it.
  for (const bit of [USER_KICK, USER_BAN, USER_ADMIN, SERVER_ADMIN]) {
    assert.equal(canUseWindow(as(bit), "admin"), true);
  }
  assert.equal(canUseWindow(as(POWER), "admin"), false, "a power user has no admin tools");
  // Everything else needs nothing (connect, settings, chat, news, …).
  for (const id of ["connect", "chat", "news", "userlist", "messages", "settings", "transfers"]) {
    assert.equal(canUseWindow(as(0), id), true, id);
    assert.equal(canUseWindow(null, id), true, id);
  }
});

test("the Administration window shows each tool to its privilege", () => {
  const none = {
    roles: false,
    accounts: false,
    server: false,
    history: false,
    iprules: false,
    connections: false,
    bans: false,
    kick: false,
    ban: false,
  };
  assert.deepEqual(adminTools(null), none);
  assert.deepEqual(adminTools(as(POWER)), none);
  assert.deepEqual(adminTools(as(ALL)), {
    roles: true,
    accounts: true,
    server: true,
    history: true,
    iprules: true,
    connections: true,
    bans: true,
    kick: true,
    ban: true,
  });
  // A kick-only moderator: Disconnect and Connections, no bans.
  assert.deepEqual(adminTools(as(USER | USER_KICK)), { ...none, kick: true, connections: true });
  // Banning rides the disconnect request: USER_BAN alone lists bans only.
  assert.deepEqual(adminTools(as(USER_BAN)), { ...none, bans: true });
  assert.deepEqual(adminTools(as(USER_KICK | USER_BAN)), {
    ...none,
    kick: true,
    ban: true,
    connections: true,
    bans: true,
  });
  // A delegated account administrator (helpdesk): roles and accounts.
  assert.deepEqual(adminTools(as(POWER | USER_ADMIN)), { ...none, roles: true, accounts: true });
  // An Admin whose SERVER_ADMIN was revoked loses the server tools only.
  const t = adminTools(as(ALL & ~SERVER_ADMIN, { class: 3 }));
  assert.equal(t.server || t.history || t.iprules, false);
  assert.equal(t.accounts && t.roles && t.kick && t.ban && t.bans, true);
});

test("user verbs follow CHAT_PRIVATE and USER_KICK", () => {
  assert.deepEqual(peerActions(as(GUEST)), { message: false, invite: false, disconnect: false });
  assert.deepEqual(peerActions(as(USER)), { message: true, invite: true, disconnect: false });
  assert.deepEqual(peerActions(as(GUEST | USER_KICK)), { message: false, invite: false, disconnect: true });
  assert.deepEqual(peerActions(as(USER & ~CHAT_PRIVATE)), { message: false, invite: false, disconnect: false });
  assert.deepEqual(peerActions(null), { message: false, invite: false, disconnect: false });
});

test("file tools follow the file privileges", () => {
  assert.deepEqual(fileTools(as(GUEST)), {
    download: false,
    upload: false,
    delete: false,
    newFolder: false,
    move: false,
    alias: false,
    catalog: false,
  });
  assert.deepEqual(fileTools(as(USER)), {
    download: true,
    upload: true,
    delete: false,
    newFolder: false,
    move: false,
    alias: false,
    catalog: false,
  });
  const power = fileTools(as(POWER));
  assert.ok(Object.values(power).every(Boolean), "a power user has every file tool");
  // Grants and revokes, not the class, decide.
  assert.equal(fileTools(as(USER | FILE_DELETE)).delete, true);
  assert.equal(fileTools(as(POWER & ~FILE_UPLOAD, { class: 2 })).upload, false);
  assert.deepEqual(
    Object.entries(fileTools(as(FILE_MANAGE_TREE)))
      .filter(([, on]) => on)
      .map(([k]) => k),
    ["newFolder", "move", "alias", "catalog"]
  );
});

test("chat commands are refused locally only for a missing privilege", () => {
  const guest = as(GUEST);
  // Talking needs CHAT_SEND; the server refuses it otherwise.
  for (const cmd of ["", "me", "away", "back", "afk"]) {
    assert.equal(chatRefusal(guest, cmd), null, cmd);
    assert.match(chatRefusal(as(FILE_LIST), cmd), /needs CHAT_SEND/, cmd);
  }
  // Topic and room flags need CHAT_SET_TOPIC.
  assert.match(chatRefusal(guest, "topic"), /needs CHAT_SET_TOPIC/);
  assert.match(chatRefusal(guest, "roomflags"), /needs CHAT_SET_TOPIC/);
  assert.equal(chatRefusal(as(POWER), "topic"), null);
  assert.equal(chatRefusal(as(POWER), "roomflags"), null);
  // The lobby's flags are a server admin's call.
  assert.match(chatRefusal(as(POWER), "roomflags", { lobby: true }), /needs SERVER_ADMIN/);
  assert.equal(chatRefusal(as(POWER | SERVER_ADMIN), "roomflags", { lobby: true }), null);
  assert.equal(chatRefusal(as(POWER), "topic", { lobby: true }), null);
  // Local commands need nothing; unknown ones are the chat window's to report.
  for (const cmd of ["clear", "help", "name", "n", "desc", "d", "nonsense"]) {
    assert.equal(chatRefusal(as(0), cmd), null, cmd);
  }
});
