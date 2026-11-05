// Bounded private-message store for the Messages window (pure logic).
//
// A flood of PMs — or a server inventing thousands of senders — must not grow
// the window without bound: each conversation keeps its last MAX_LINES lines,
// and past MAX_CONVERSATIONS the least recently active conversation (never
// the one on screen) is dropped.

export const MAX_LINES = 500;
export const MAX_CONVERSATIONS = 200;

export function createConversations({ maxLines = MAX_LINES, maxConversations = MAX_CONVERSATIONS } = {}) {
  const convos = new Map(); // user -> { lines: [], unread: bool, touched: n }
  let clock = 0;

  function evictFor(protect) {
    const evicted = [];
    while (convos.size >= maxConversations) {
      let victim = null;
      let oldest = Infinity;
      for (const [user, c] of convos) {
        if (user !== protect && c.touched < oldest) {
          oldest = c.touched;
          victim = user;
        }
      }
      if (victim === null) break;
      convos.delete(victim);
      evicted.push(victim);
    }
    return evicted;
  }

  return {
    get size() {
      return convos.size;
    },
    has(user) {
      return convos.has(user);
    },
    get(user) {
      return convos.get(user);
    },
    users() {
      return [...convos.keys()];
    },
    /** Make sure a conversation exists. `active` is never evicted. */
    ensure(user, active) {
      if (convos.has(user)) return { created: false, evicted: [] };
      const evicted = evictFor(active);
      convos.set(user, { lines: [], unread: false, touched: ++clock });
      return { created: true, evicted };
    },
    /** Append a line; returns { created, evicted, trimmed }. */
    add(user, line, { unread = false, active = null } = {}) {
      const { created, evicted } = this.ensure(user, active);
      const c = convos.get(user);
      c.lines.push(line);
      c.touched = ++clock;
      let trimmed = 0;
      while (c.lines.length > maxLines) {
        c.lines.shift();
        trimmed++;
      }
      if (unread) c.unread = true;
      return { created, evicted, trimmed };
    },
    markRead(user) {
      const c = convos.get(user);
      if (c) c.unread = false;
    },
    unreadCount() {
      let n = 0;
      for (const c of convos.values()) if (c.unread) n++;
      return n;
    },
  };
}
