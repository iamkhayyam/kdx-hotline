// Privileges — what the logged-in session may do, and what the UI offers
// because of it. The login result carries the session's effective privilege
// bits (class defaults, plus role and account grants, minus account
// revokes); windows gate each control on the specific privilege the server
// checks for it. The server stays the authority: this only spares users a
// click into an inevitable refusal.
//
// The bits are a login-time snapshot. That holds for the whole session:
// the server disconnects a session whose class or effective privileges
// change (overrides, roles, a role's bits), and the next login brings the
// new set.
//
// Pure: no DOM, no Tauri — unit-tested in tests/privileges.test.mjs.

// BEGIN privilege bits
// The server's `Privileges` bitflags (crates/kdx-server-core/src/auth/
// classes.rs), mirrored exactly: one `export const NAME = 1 << N;` per flag,
// same names and bits. crates/kdx-server-core/tests/privileges_js.rs parses
// this block and fails if it drifts from the Rust definition.
export const CHAT_SEND = 1 << 0;
export const CHAT_PRIVATE = 1 << 1;
export const CHAT_CREATE_ROOM = 1 << 2;
export const CHAT_SET_TOPIC = 1 << 3;
export const FILE_LIST = 1 << 4;
export const FILE_DOWNLOAD = 1 << 5;
export const FILE_UPLOAD = 1 << 6;
export const FILE_DELETE = 1 << 7;
export const FILE_MANAGE_TREE = 1 << 8;
export const USER_KICK = 1 << 16;
export const USER_BAN = 1 << 17;
export const USER_ADMIN = 1 << 18;
export const SERVER_ADMIN = 1 << 19;
// END privilege bits

/** Every privilege, in the order the account and role editors list them. */
export const PRIVILEGES = Object.freeze(
  [
    { name: "CHAT_SEND", bit: CHAT_SEND, label: "Chat: send" },
    { name: "CHAT_PRIVATE", bit: CHAT_PRIVATE, label: "Chat: private message" },
    { name: "CHAT_CREATE_ROOM", bit: CHAT_CREATE_ROOM, label: "Chat: create room" },
    { name: "CHAT_SET_TOPIC", bit: CHAT_SET_TOPIC, label: "Chat: set topic" },
    { name: "FILE_LIST", bit: FILE_LIST, label: "Files: list" },
    { name: "FILE_DOWNLOAD", bit: FILE_DOWNLOAD, label: "Files: download" },
    { name: "FILE_UPLOAD", bit: FILE_UPLOAD, label: "Files: upload" },
    { name: "FILE_DELETE", bit: FILE_DELETE, label: "Files: delete" },
    { name: "FILE_MANAGE_TREE", bit: FILE_MANAGE_TREE, label: "Files: manage tree" },
    { name: "USER_KICK", bit: USER_KICK, label: "Users: kick" },
    { name: "USER_BAN", bit: USER_BAN, label: "Users: ban" },
    { name: "USER_ADMIN", bit: USER_ADMIN, label: "Users: manage accounts/roles" },
    { name: "SERVER_ADMIN", bit: SERVER_ADMIN, label: "Server: config/shutdown" },
  ].map((p) => Object.freeze(p))
);

/** Every defined bit (what an Admin holds by default). */
export const ALL = PRIVILEGES.reduce((bits, p) => bits | p.bit, 0) >>> 0;

/** The session's privilege bits: 0 with no session (not logged in or not
 * hydrated yet) or a malformed value — never more than it holds. */
export function privilegesOf(session) {
  const p = session ? session.privileges : undefined;
  return Number.isInteger(p) && p >= 0 && p <= 0xffffffff ? p >>> 0 : 0;
}

/** Whether `session` holds every bit of `priv`. Fails closed: an empty or
 * undefined `priv` (a typo'd constant) is never granted. */
export function can(session, priv) {
  const want = Number.isInteger(priv) ? priv >>> 0 : 0;
  return want !== 0 && (privilegesOf(session) & want) >>> 0 === want;
}

/** Whether `session` holds at least one bit of `privs`. */
export function canAny(session, privs) {
  const want = Number.isInteger(privs) ? privs >>> 0 : 0;
  return (privilegesOf(session) & want) !== 0;
}

/** The name of the first privilege in `priv` that `session` lacks, or null. */
export function missing(session, priv) {
  const have = privilegesOf(session);
  const lacking = PRIVILEGES.find((p) => (priv & p.bit) !== 0 && (have & p.bit) === 0);
  return lacking ? lacking.name : null;
}

// ---- what each window offers (mirrors the server's handler gates) ----

/** Any of these makes the Administration window worth opening. */
export const ADMIN_TOOLS = USER_KICK | USER_BAN | USER_ADMIN | SERVER_ADMIN;

/** Windows that are only useful with a privilege: one of these bits must be
 * held. Windows not listed need none. */
export const WINDOW_PRIVILEGES = Object.freeze({
  files: FILE_LIST, // listing a folder
  admin: ADMIN_TOOLS, // a hub: roles, disconnect, and the windows below
  accounts: USER_ADMIN,
  server: SERVER_ADMIN, // settings, broadcast, shutdown
  history: SERVER_ADMIN,
  iprules: SERVER_ADMIN,
  connections: USER_KICK,
  bans: USER_BAN,
});

/** Whether window `id` is any use to `session`. */
export function canUseWindow(session, id) {
  const need = WINDOW_PRIVILEGES[id];
  return need === undefined || canAny(session, need);
}

/** The Administration window's tools. Banning rides the disconnect request,
 * so it needs USER_KICK as well as USER_BAN. */
export function adminTools(session) {
  return {
    roles: can(session, USER_ADMIN),
    accounts: can(session, USER_ADMIN),
    server: can(session, SERVER_ADMIN),
    history: can(session, SERVER_ADMIN),
    iprules: can(session, SERVER_ADMIN),
    connections: can(session, USER_KICK),
    bans: can(session, USER_BAN),
    kick: can(session, USER_KICK),
    ban: can(session, USER_KICK | USER_BAN),
  };
}

/** Verbs on another user (User List and chat roster menus). */
export function peerActions(session) {
  return {
    message: can(session, CHAT_PRIVATE),
    invite: can(session, CHAT_PRIVATE), // starting a private chat
    disconnect: can(session, USER_KICK),
  };
}

/** The Files window's tools. Per-folder class limits still apply server-side. */
export function fileTools(session) {
  return {
    download: can(session, FILE_DOWNLOAD),
    upload: can(session, FILE_UPLOAD),
    delete: can(session, FILE_DELETE),
    newFolder: can(session, FILE_MANAGE_TREE),
    move: can(session, FILE_MANAGE_TREE),
    alias: can(session, FILE_MANAGE_TREE),
    catalog: can(session, FILE_MANAGE_TREE),
  };
}

/** Chat input (a plain line is cmd "") and slash commands that need a
 * privilege; anything else needs none. */
const CHAT_NEEDS = Object.freeze({
  "": CHAT_SEND,
  me: CHAT_SEND,
  away: CHAT_SEND,
  back: CHAT_SEND,
  afk: CHAT_SEND,
  topic: CHAT_SET_TOPIC,
  roomflags: CHAT_SET_TOPIC,
});

const CHAT_REFUSALS = Object.freeze({
  [CHAT_SEND]: "you can't send chat messages",
  [CHAT_SET_TOPIC]: "you can't change room settings",
  [SERVER_ADMIN]: "only a server admin can change the lobby's settings",
});

/**
 * Why `session` can't run chat command `cmd` (lower-case, "" for a plain
 * line) in the room on screen — `{ lobby }` says whether that's the lobby —
 * or null when it can. The lobby's flags additionally need SERVER_ADMIN.
 */
export function chatRefusal(session, cmd, { lobby = false } = {}) {
  let need = CHAT_NEEDS[cmd] || 0;
  if (cmd === "roomflags" && lobby) need |= SERVER_ADMIN;
  const lacking = missing(session, need);
  if (!lacking) return null;
  const bit = PRIVILEGES.find((p) => p.name === lacking).bit;
  return `${CHAT_REFUSALS[bit] || "you can't do that"} (needs ${lacking})`;
}
