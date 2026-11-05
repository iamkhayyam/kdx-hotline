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
