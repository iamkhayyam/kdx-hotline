// Launcher-side queue for UI commands addressed to windows that aren't
// listening yet (pure logic; main.js wires it).
//
// A window opened on demand needs a moment before its listeners exist, so a
// command sent right after open() used to vanish (the first private message,
// "Get Info" on a closed User Info window, …). Each feature window announces
// "ready" once its listeners are registered; until then commands for it are
// held here, and flushed in order on "ready".

export const MAX_QUEUED_PER_WINDOW = 200;

export function createDeliveryQueue({ maxPerWindow = MAX_QUEUED_PER_WINDOW } = {}) {
  const ready = new Set();
  const queues = new Map(); // label -> [{ cmd, args }]

  return {
    isReady(label) {
      return ready.has(label);
    },
    /** Hold a command for `label`; the oldest is dropped past the cap. */
    enqueue(label, cmd, args) {
      if (!queues.has(label)) queues.set(label, []);
      const q = queues.get(label);
      q.push({ cmd, args });
      while (q.length > maxPerWindow) q.shift();
    },
    /** `label` is listening: returns (and forgets) everything held for it. */
    markReady(label) {
      ready.add(label);
      const q = queues.get(label) || [];
      queues.delete(label);
      return q;
    },
    /** `label` closed: hold commands again until it re-announces. */
    markClosed(label) {
      ready.delete(label);
    },
    pending(label) {
      return (queues.get(label) || []).length;
    },
  };
}
