// Pure-logic modules behind the window plumbing:
// eventfilter (UI-6), delivery (UI-8), convos (UI-11), rooms (UI-2, C-2),
// transfers' grid (UI-10), transfer bookkeeping (C-5), bookmarks (C-3).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createKdxFilter } from "../dist/js/eventfilter.js";
import { createDeliveryQueue } from "../dist/js/delivery.js";
import { createConversations } from "../dist/js/convos.js";
import {
  isPrivateRoom,
  inCurrentRoom,
  shouldAdoptRoom,
  createJoinTracker,
  MAX_EARLY_LINES,
} from "../dist/js/rooms.js";
import { cellsFor, MAX_CELLS, unfinishedIds } from "../dist/js/windows/transfers.js";
import { getState, trackTransfers, activeTransferCount, TRANSFER_ABORTED } from "../dist/js/store.js";
import { bookmarkConnectCommands, canAutoSubmit } from "../dist/js/bookmarks.js";

test("events from a replaced connection are dropped", () => {
  const f = createKdxFilter();
  assert.ok(f.accept({ type: "chat", gen: 1, seq: 1 }));
  assert.ok(f.accept({ type: "chat", gen: 2, seq: 2 }), "new connection");
  assert.ok(!f.accept({ type: "chat", gen: 1, seq: 3 }), "straggler from gen 1");
  assert.ok(!f.accept({ type: "disconnected", gen: 1, seq: 4 }), "old Disconnected can't flip the UI offline");
  f.setGeneration(5);
  assert.ok(!f.accept({ type: "chat", gen: 4, seq: 5 }));
  f.setGeneration(3); // never goes backwards
  assert.equal(f.generation, 5);
});

test("a replayed event is applied once", () => {
  const f = createKdxFilter();
  const ev = { type: "private_message", gen: 1, seq: 7 };
  assert.ok(f.accept(ev));
  assert.ok(!f.accept({ ...ev }), "same seq again (replay after live)");
  assert.ok(!f.accept(null));
  assert.ok(!f.accept({ gen: 1 }), "no type");
});

test("commands for a window wait until it is ready, in order", () => {
  const q = createDeliveryQueue({ maxPerWindow: 3 });
  assert.ok(!q.isReady("messages"));
  q.enqueue("messages", "kdx-replay", { n: 1 });
  q.enqueue("messages", "open-with", { n: 2 });
  assert.equal(q.pending("messages"), 2);
  assert.deepEqual(q.markReady("messages").map((i) => i.args.n), [1, 2]);
  assert.ok(q.isReady("messages"));
  assert.equal(q.pending("messages"), 0);
  q.markClosed("messages");
  assert.ok(!q.isReady("messages"));
  for (let n = 0; n < 10; n++) q.enqueue("messages", "kdx-replay", { n });
  assert.deepEqual(q.markReady("messages").map((i) => i.args.n), [7, 8, 9], "bounded, newest kept");
});

test("conversations are bounded in lines and count", () => {
  const c = createConversations({ maxLines: 3, maxConversations: 2 });
  for (let i = 0; i < 5; i++) c.add("bob", { text: String(i) });
  assert.deepEqual(c.get("bob").lines.map((l) => l.text), ["2", "3", "4"]);

  c.add("carol", { text: "x" }, { unread: true, active: "bob" });
  assert.equal(c.unreadCount(), 1);
  // A third sender evicts the least recently active conversation — but
  // never the one on screen.
  c.add("bob", { text: "5" });
  const r = c.add("mallory", { text: "spam" }, { active: "carol" });
  assert.deepEqual(r.evicted, ["bob"]);
  assert.ok(c.has("carol") && c.has("mallory") && !c.has("bob"));
  assert.equal(c.size, 2);
  c.markRead("carol");
  assert.equal(c.unreadCount(), 0);
});

test("chat events are scoped to the room on screen", () => {
  assert.ok(isPrivateRoom("priv-1234"));
  assert.ok(!isPrivateRoom("lobby"));
  assert.ok(inCurrentRoom({ room: "lobby" }, "lobby"));
  assert.ok(!inCurrentRoom({ room: "priv-1" }, "lobby"));
  assert.ok(inCurrentRoom({ text: "server info, no room" }, "lobby"));
});

test("the inviter adopts the private room the server created", () => {
  const now = 1000;
  const pending = { to: "bob", until: now + 15000 };
  assert.ok(shouldAdoptRoom("priv-abc", "lobby", pending, now));
  assert.ok(!shouldAdoptRoom("priv-abc", "lobby", null, now), "no invite outstanding");
  assert.ok(!shouldAdoptRoom("priv-abc", "lobby", pending, now + 20000), "expired");
  assert.ok(!shouldAdoptRoom("lobby2", "lobby", pending, now), "not a private room");
  assert.ok(!shouldAdoptRoom("priv-abc", "priv-abc", pending, now), "already there");
});

test("transfer grid is capped whatever total the server claims", () => {
  assert.deepEqual(cellsFor({ buckets: [0, 1, 2, 7] }), [0, 1, 2, 0]);
  assert.equal(cellsFor({ buckets: new Array(50000).fill(2) }).length, MAX_CELLS);
  // Fallback from a raw bitmap: 5 chunks, 0/1/3 done.
  assert.deepEqual(cellsFor({ total: 5, bitmap: [0b01011] }), [2, 2, 0, 2, 0]);
  const start = Date.now();
  const huge = cellsFor({ total: 50_000_000, bitmap: [0xff] });
  assert.equal(huge.length, MAX_CELLS);
  assert.equal(huge[0], 1);
  assert.ok(Date.now() - start < 1000);
});

test("a room being joined keeps its early events until the join is confirmed", () => {
  const j = createJoinTracker();
  assert.equal(j.room, null);
  assert.ok(!j.offer({ type: "user_list", room: "priv-x", users: ["a"] }), "nothing being joined");

  j.begin("priv-x");
  assert.equal(j.room, "priv-x");
  assert.ok(j.offer({ type: "user_list", room: "priv-x", users: ["alice", "bob"] }));
  assert.ok(j.offer({ type: "topic", room: "priv-x", topic: "hi" }));
  for (let i = 0; i < MAX_EARLY_LINES + 5; i++) assert.ok(j.offer({ type: "chat", room: "priv-x", text: String(i) }));
  assert.ok(!j.offer({ type: "chat", room: "lobby", text: "other room" }));
  assert.ok(!j.offer({ type: "server_info", text: "no room" }));

  assert.equal(j.finish("lobby"), null, "a different room's confirmation");
  const early = j.finish("priv-x");
  assert.deepEqual(early.users, ["alice", "bob"]);
  assert.equal(early.topic, "hi");
  assert.equal(early.lines.length, MAX_EARLY_LINES);
  assert.equal(early.lines.at(-1).text, String(MAX_EARLY_LINES + 4));
  assert.equal(j.room, null);

  // A refused join drops what it kept.
  j.begin("priv-gone");
  j.offer({ type: "topic", room: "priv-gone", topic: "x" });
  j.abort("priv-gone");
  assert.equal(j.room, null);
  assert.equal(j.finish("priv-gone"), null);
});

test("a disconnect mid-transfer clears the running-transfer counter", () => {
  const before = activeTransferCount();
  trackTransfers({ type: "transfer_progress", id: "t-done", direction: "upload", done: 4, total: 4 });
  trackTransfers({ type: "transfer_complete", id: "t-done", status: 0 });
  trackTransfers({ type: "transfer_progress", id: "t-cut", direction: "download", done: 1, total: 9 });
  trackTransfers({ type: "transfer_progress", id: "t-cut", direction: "download", done: 3, total: 9 });
  assert.equal(activeTransferCount(), before + 1, "the Button Bar shows [1]");

  trackTransfers({ type: "disconnected", reason: "disconnected" });
  assert.equal(activeTransferCount(), 0);
  assert.equal(getState().transfers["t-cut"].status, TRANSFER_ABORTED);
  assert.equal(getState().transfers["t-done"].status, 0, "a finished one keeps its outcome");
  // Unrelated events change nothing.
  trackTransfers({ type: "chat", room: "lobby" });
  trackTransfers(null);
  assert.equal(activeTransferCount(), 0);
  // Resumed later under the same id: running again, then finished.
  trackTransfers({ type: "transfer_progress", id: "t-cut", direction: "download", done: 4, total: 9 });
  assert.equal(activeTransferCount(), 1);
  trackTransfers({ type: "transfer_complete", id: "t-cut", status: 0 });
  assert.equal(activeTransferCount(), 0);
});

test("the Transfers window knows which cards are still running", () => {
  const cards = new Map([
    ["a", { done: true }],
    ["b", { done: false }],
    ["c", { done: false }],
  ]);
  assert.deepEqual(unfinishedIds(cards), ["b", "c"]);
});

test("a bookmark without a saved password is not submitted blind", () => {
  const b = { id: "bm1", host: "h", port: 10700, login: "phraq" };
  const blind = bookmarkConnectCommands({ ...b, hasSecret: false });
  assert.deepEqual(
    blind.map(([action]) => action),
    ["fill"],
    "no submit, so no login with an empty password"
  );
  assert.equal(blind[0][1].askPassword, true);
  assert.equal(blind[0][1].hasSecret, false);

  const saved = bookmarkConnectCommands({ ...b, hasSecret: true });
  assert.deepEqual(saved.map(([action]) => action), ["fill", "submit"]);
  assert.equal(saved[0][1].bookmarkId, "bm1");
  assert.ok(!("password" in saved[0][1]), "only the id travels");

  // The Connect window's own guard for an automatic submit.
  assert.ok(!canAutoSubmit({ password: "", bookmarkId: null }));
  assert.ok(canAutoSubmit({ password: "", bookmarkId: "bm1" }));
  assert.ok(canAutoSubmit({ password: "pw", bookmarkId: null }));
});
