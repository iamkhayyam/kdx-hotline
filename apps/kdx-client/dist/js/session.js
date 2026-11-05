// Session facts shared by every window. Each window has its own store.js, so
// a window opened after login hydrates from Rust (get_session) on mount, and
// open windows learn of a new login from the "session" broadcast.

import { invoke, noteGeneration } from "./bridge.js";
import { update } from "./store.js";

/** Apply a "session" broadcast: { gen, session: {username, class}, server }. */
export function applySession(msg) {
  noteGeneration(msg.gen);
  update({ connection: "online", session: msg.session, server: msg.server });
}

/** Load the current session from the Rust side; resolves to it (or null). */
export async function hydrateSession() {
  let s = null;
  try {
    s = await invoke("get_session");
  } catch (_) {
    return null;
  }
  if (!s) return null;
  noteGeneration(s.gen);
  const patch = { server: { host: s.host, port: s.port } };
  if (s.user) {
    patch.connection = "online";
    patch.session = { username: s.user.username, class: s.user.class };
  }
  update(patch);
  return s;
}
