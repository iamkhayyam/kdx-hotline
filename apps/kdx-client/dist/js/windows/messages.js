// Messages — private (direct) messages. One window, many conversations: a
// left pane of people (the bar turns red on unread) and a right transcript +
// input for the selected person. Mirrors the original KDX Messages window.
//
// Bounded (convos.js) and incremental: a PM appends one row/line instead of
// rebuilding the window, so a flood can't freeze it.
//
// Anyone can receive messages; sending needs CHAT_PRIVATE, so without it the
// input stays disabled (privileges.js).

import { invoke, emitUi } from "../bridge.js";
import { getState, subscribe } from "../store.js";
import { errorText } from "../html.js";
import { createConversations, MAX_LINES } from "../convos.js";
import { can, CHAT_PRIVATE } from "../privileges.js";

const ENTRY_HINT = "private message…";
const NO_PM_HINT = "you can't send private messages (needs CHAT_PRIVATE)";

export function buildMessages() {
  const body = document.createElement("div");
  body.className = "messages-win";
  body.innerHTML = `
    <div class="msg-people" id="msg-people"></div>
    <div class="msg-thread">
      <div class="msg-thread-head" id="msg-with">select a conversation</div>
      <div class="msg-scroll" id="msg-scroll"></div>
      <div class="chat-input">
        <span class="prompt">&gt;</span>
        <input id="msg-entry" autocomplete="off" disabled />
      </div>
    </div>`;

  const $ = (s) => body.querySelector(s);
  const peopleEl = $("#msg-people");
  const scrollEl = $("#msg-scroll");
  const withEl = $("#msg-with");
  const entry = $("#msg-entry");

  const convos = createConversations();
  const rows = new Map(); // user -> row element
  let active = null;
  let lastUnread = -1;

  function me() {
    const s = getState().session;
    return s && s.username;
  }

  /** The input is live with a conversation open, unless the session can't
   * send private messages. (Not logged in, a send says "not connected".) */
  function syncEntry() {
    const s = getState().session;
    const mayPm = !s || can(s, CHAT_PRIVATE);
    entry.disabled = !active || !mayPm;
    entry.placeholder = mayPm ? ENTRY_HINT : NO_PM_HINT;
  }
  syncEntry();
  subscribe(syncEntry);

  function syncLed() {
    const n = convos.unreadCount();
    if (n !== lastUnread) {
      lastUnread = n;
      emitUi("main", "set-led", { unread: n });
    }
  }

  function rowFor(user) {
    let row = rows.get(user);
    if (!row) {
      row = document.createElement("div");
      row.className = "msg-person";
      const bar = document.createElement("span");
      bar.className = "msg-bar";
      const who = document.createElement("span");
      who.className = "msg-who";
      who.textContent = user;
      row.append(bar, who);
      row.addEventListener("click", () => select(user));
      peopleEl.appendChild(row);
      rows.set(user, row);
    }
    return row;
  }

  function paintRow(user) {
    const c = convos.get(user);
    if (!c) return;
    const row = rowFor(user);
    row.classList.toggle("unread", c.unread);
    row.classList.toggle("active", user === active);
  }

  function dropRows(users) {
    for (const u of users) {
      const row = rows.get(u);
      if (row) row.remove();
      rows.delete(u);
    }
  }

  function lineEl(l) {
    const div = document.createElement("div");
    div.className = "chat-line" + (l.from === me() ? " pm-mine" : "");
    const ts = document.createElement("span");
    ts.className = "ts";
    ts.textContent = hhmm(l.ts);
    const nick = document.createElement("span");
    nick.className = "nick";
    nick.textContent = `<${l.from}>`;
    div.append(ts, nick, document.createTextNode(" " + l.text));
    return div;
  }

  function appendLine(l) {
    scrollEl.appendChild(lineEl(l));
    while (scrollEl.children.length > MAX_LINES) scrollEl.removeChild(scrollEl.firstChild);
    scrollEl.scrollTop = scrollEl.scrollHeight;
  }

  function renderThread() {
    scrollEl.textContent = "";
    if (!active) return;
    const c = convos.get(active);
    if (!c) return;
    const frag = document.createDocumentFragment();
    for (const l of c.lines) frag.appendChild(lineEl(l));
    scrollEl.appendChild(frag);
    scrollEl.scrollTop = scrollEl.scrollHeight;
  }

  function select(user) {
    const previous = active;
    active = user;
    dropRows(convos.ensure(user, user).evicted);
    convos.markRead(user);
    withEl.textContent = "conversation with " + user;
    syncEntry();
    if (previous && previous !== user) paintRow(previous);
    paintRow(user);
    renderThread();
    syncLed();
    entry.focus();
  }

  function addLine(user, line, unread) {
    const r = convos.add(user, line, { unread, active });
    dropRows(r.evicted);
    paintRow(user);
    if (user === active) appendLine(line);
    syncLed();
  }

  entry.addEventListener("keydown", async (e) => {
    if (e.key !== "Enter" || !active) return;
    const text = entry.value;
    if (!text.trim()) return;
    entry.value = "";
    const to = active;
    try {
      await invoke("send_private", { to, text });
    } catch (err) {
      addLine(to, { from: "!", text: "failed: " + errorText(err), ts: Date.now() / 1000 }, false);
    }
  });

  return {
    body,
    /** Handle an incoming/echoed private message event. */
    onMessage(ev) {
      const self = me();
      // The other party: for the echo of our own message, the recipient.
      const mine = !!self && ev.from === self;
      const other = mine ? ev.to : ev.from;
      if (typeof other !== "string" || !other) return;
      addLine(other, { from: ev.from, text: String(ev.text ?? ""), ts: ev.timestamp }, !mine && other !== active);
    },
    /** Open (or focus) a conversation with `user` — used from User List. */
    openWith(user) {
      if (typeof user === "string" && user) select(user);
    },
    get unread() {
      return convos.unreadCount();
    },
  };
}

function hhmm(ts) {
  const d = new Date(ts * 1000);
  return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
}
