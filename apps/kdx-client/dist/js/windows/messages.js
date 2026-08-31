// Messages — private (direct) messages. One window, many conversations: a
// left pane of people (the bar turns red on unread) and a right transcript +
// input for the selected person. Mirrors the original KDX Messages window.

import { invoke, emitUi } from "../bridge.js";
import { getState } from "../store.js";

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
        <input id="msg-entry" placeholder="private message…" autocomplete="off" disabled />
      </div>
    </div>`;

  const $ = (s) => body.querySelector(s);
  const peopleEl = $("#msg-people");
  const scrollEl = $("#msg-scroll");
  const withEl = $("#msg-with");
  const entry = $("#msg-entry");

  // username -> { lines: [{from, text, ts}], unread: bool }
  const convos = new Map();
  let active = null;

  function ensure(user) {
    if (!convos.has(user)) convos.set(user, { lines: [], unread: false });
    return convos.get(user);
  }

  function totalUnread() {
    let n = 0;
    for (const c of convos.values()) if (c.unread) n++;
    return n;
  }

  function renderPeople() {
    peopleEl.innerHTML = "";
    for (const [user, c] of convos) {
      const row = document.createElement("div");
      row.className = "msg-person" + (c.unread ? " unread" : "") + (user === active ? " active" : "");
      row.innerHTML = `<span class="msg-bar"></span><span class="msg-who">${esc(user)}</span>`;
      row.addEventListener("click", () => select(user));
      peopleEl.appendChild(row);
    }
    emitUi("main", "set-led", { unread: totalUnread() });
  }

  function renderThread() {
    scrollEl.innerHTML = "";
    if (!active) return;
    const me = getState().session && getState().session.username;
    for (const l of ensure(active).lines) {
      const div = document.createElement("div");
      const mine = l.from === me;
      div.className = "chat-line" + (mine ? " pm-mine" : "");
      div.innerHTML = `<span class="ts">${hhmm(l.ts)}</span><span class="nick">&lt;${esc(l.from)}&gt;</span> ${esc(l.text)}`;
      scrollEl.appendChild(div);
    }
    scrollEl.scrollTop = scrollEl.scrollHeight;
  }

  function select(user) {
    active = user;
    const c = ensure(user);
    c.unread = false;
    withEl.textContent = "conversation with " + user;
    entry.disabled = false;
    renderPeople();
    renderThread();
    entry.focus();
  }

  entry.addEventListener("keydown", async (e) => {
    if (e.key !== "Enter" || !active) return;
    const text = entry.value;
    if (!text.trim()) return;
    entry.value = "";
    try {
      await invoke("send_private", { to: active, text });
    } catch (err) {
      const c = ensure(active);
      c.lines.push({ from: "!", text: "failed: " + (err.message || err), ts: Date.now() / 1000 });
      renderThread();
    }
  });

  return {
    body,
    /** Handle an incoming/echoed private message event. */
    onMessage(ev) {
      const me = getState().session && getState().session.username;
      // The other party in this conversation.
      const other = ev.from === me ? ev.to : ev.from;
      const c = ensure(other);
      c.lines.push({ from: ev.from, text: ev.text, ts: ev.timestamp });
      if (other !== active && ev.from !== me) c.unread = true;
      renderPeople();
      if (other === active) renderThread();
    },
    /** Open (or focus) a conversation with `user` — used from User List. */
    openWith(user) {
      ensure(user);
      select(user);
    },
    get unread() {
      return totalUnread();
    },
  };
}

function hhmm(ts) {
  const d = new Date(ts * 1000);
  return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
}
function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}
