// Filter for the "kdx" server-event stream (pure logic; bridge.js wires it).
//
// Every event the Rust forwarder emits carries
//   gen — the connection generation (bumped on every connect), and
//   seq — an app-wide sequence number.
// Events from an older generation are stragglers from a connection that has
// been replaced: dropped. An event seen twice (live, and again as a replay
// the launcher queued while this window was opening) is dropped the second
// time.

const MAX_SEEN = 4096;

export function createKdxFilter() {
  let generation = 0;
  const seen = new Set();

  return {
    get generation() {
      return generation;
    },
    /** Learn the current generation (from connect / get_session). */
    setGeneration(gen) {
      if (Number.isSafeInteger(gen) && gen > generation) generation = gen;
    },
    /** Should this event be applied? Updates state as a side effect. */
    accept(ev) {
      if (!ev || typeof ev !== "object" || typeof ev.type !== "string") return false;
      if (Number.isSafeInteger(ev.gen)) {
        if (ev.gen < generation) return false;
        generation = ev.gen;
      }
      if (Number.isSafeInteger(ev.seq)) {
        if (seen.has(ev.seq)) return false;
        seen.add(ev.seq);
        if (seen.size > MAX_SEEN) seen.delete(seen.values().next().value);
      }
      return true;
    },
  };
}
