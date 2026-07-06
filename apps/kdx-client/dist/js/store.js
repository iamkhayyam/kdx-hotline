// Tiny shared state with pub/sub. Windows subscribe to the slices they care
// about; the event bridge dispatches server events into here.

const state = {
  connection: "offline", // offline | connecting | online
  server: null, // { host, port }
  session: null, // { class }
  room: "lobby",
  users: [], // current room's roster (chat window's user-list pane)
  presenceCount: 0, // server-wide online count (Button Bar footer)
  topic: "",
  files: { path: "/", entries: [] },
  transfers: {}, // id -> { direction, done, total, bitmap, name, status }
};

const listeners = new Set();

export function getState() {
  return state;
}

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function update(patch) {
  Object.assign(state, patch);
  emit();
}

/** Update a nested transfer record. */
export function updateTransfer(id, patch) {
  state.transfers[id] = { ...(state.transfers[id] || {}), ...patch };
  emit();
}

function emit() {
  for (const fn of listeners) fn(state);
}
