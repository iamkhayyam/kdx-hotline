// Chat-room bookkeeping for the Chat window (pure logic).
//
// The Chat window shows ONE room at a time, so chat/user_list/topic events
// for any other room the connection is still in must not land in it (they
// used to: an inviter saw the private room's roster and messages mixed into
// the lobby, and their replies went to the public lobby).
//
// Inviting someone makes the server join *you* to a fresh private room
// (`priv-<uuid>`) straight away; the client only learns its id from the
// room's first user_list. So after sending an invite we expect such a
// user_list and switch the view to that room.

export const INVITE_ADOPT_MS = 15000;

export function isPrivateRoom(room) {
  return typeof room === "string" && room.startsWith("priv-");
}

/** Does an event belong to the room currently on screen? */
export function inCurrentRoom(ev, currentRoom) {
  return !ev || ev.room === undefined || ev.room === currentRoom;
}

/**
 * Should a user_list for `room` (not the current room) be adopted as the
 * private chat we just created by inviting `pending.to`?
 */
export function shouldAdoptRoom(room, currentRoom, pending, now = Date.now()) {
  return (
    !!pending &&
    now <= pending.until &&
    room !== currentRoom &&
    isPrivateRoom(room)
  );
}

/** Most chat lines kept for a room whose join isn't confirmed yet. */
export const MAX_EARLY_LINES = 50;

/**
 * A room join in flight. The server confirms a join only after the room's
 * first events (its member list, topic, the join notice) may already have
 * arrived — while the view still shows the old room, which is left only
 * once the join is confirmed. Those events are kept here and applied when
 * the view switches.
 */
export function createJoinTracker() {
  let pending = null; // { room, users, topic, lines }
  return {
    begin(room) {
      pending = { room, users: null, topic: null, lines: [] };
    },
    /** Keep `ev` if it belongs to the room being joined; true if kept. */
    offer(ev) {
      if (!pending || !ev || ev.room !== pending.room) return false;
      if (ev.type === "user_list") pending.users = ev.users;
      else if (ev.type === "topic") pending.topic = ev.topic;
      else if (ev.type === "chat") {
        pending.lines.push(ev);
        if (pending.lines.length > MAX_EARLY_LINES) pending.lines.shift();
      } else return false;
      return true;
    },
    /** The join of `room` was confirmed: what arrived for it meanwhile
     * (null if another join replaced it). */
    finish(room) {
      const p = pending && pending.room === room ? pending : null;
      if (p) pending = null;
      return p;
    },
    /** The join of `room` failed: drop what was kept for it. */
    abort(room) {
      if (pending && pending.room === room) pending = null;
    },
    get room() {
      return pending ? pending.room : null;
    },
  };
}
