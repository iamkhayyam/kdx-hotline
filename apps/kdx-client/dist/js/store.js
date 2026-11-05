// Tiny shared state with pub/sub. Windows subscribe to the slices they care
// about; the event bridge dispatches server events into here.

const state = {
  connection: "offline", // offline | connecting | online
  server: null, // { host, port }
  session: null, // { username, class, privileges } — see privileges.js
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

/** Wire status of a transfer that ended without verifying. */
export const TRANSFER_ABORTED = 2;

/** Update a nested transfer record. */
export function updateTransfer(id, patch) {
  state.transfers[id] = { ...(state.transfers[id] || {}), ...patch };
  emit();
}

/** How many transfers are still running (no final status yet). */
export function activeTransferCount(s = state) {
  return s.transfers ? Object.values(s.transfers).filter((t) => t && t.status === undefined).length : 0;
}

/** The connection ended: every transfer still running ended with it (its
 * own abort event can't arrive any more). */
export function abortUnfinishedTransfers() {
  let changed = false;
  for (const [id, t] of Object.entries(state.transfers)) {
    if (t && t.status === undefined) {
      state.transfers[id] = { ...t, status: TRANSFER_ABORTED };
      changed = true;
    }
  }
  if (changed) emit();
}

/** Keep the transfer records in step with server event `ev` (progress,
 * completion, and the connection ending mid-transfer). */
export function trackTransfers(ev) {
  switch (ev && ev.type) {
    case "transfer_progress":
      // Running (again, for a resume that kept its id): no final status.
      updateTransfer(ev.id, { direction: ev.direction, done: ev.done, total: ev.total, status: undefined });
      break;
    case "transfer_complete":
      updateTransfer(ev.id, { status: ev.status });
      break;
    case "disconnected":
      abortUnfinishedTransfers();
      break;
  }
}

function emit() {
  for (const fn of listeners) fn(state);
}
