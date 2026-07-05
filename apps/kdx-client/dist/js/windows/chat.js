import { invoke } from "../bridge.js";
import { getState } from "../store.js";

const CHAT_ACTION = 1 << 0;
const CHAT_SYSTEM = 1 << 1;

export function buildChat() {
  const body = document.createElement("div");
  body.style.flex = "1";
  body.style.display = "flex";
  body.style.flexDirection = "column";
  body.style.minHeight = "0";
  body.innerHTML = `
    <div class="topicbar" id="chat-topic">topic: —</div>
    <div class="chat-layout">
      <div class="chat-scroll" id="chat-scroll"></div>
      <aside class="userlist"><div class="hdr">online</div><div id="chat-users"></div></aside>
    </div>
    <div class="chat-input">
      <span class="prompt">&gt;</span>
      <input id="chat-entry" placeholder="message, or /me action, or /topic ..." autocomplete="off" />
    </div>`;

  const scroll = body.querySelector("#chat-scroll");
  const usersEl = body.querySelector("#chat-users");
  const topicEl = body.querySelector("#chat-topic");
  const entry = body.querySelector("#chat-entry");

  function line(cls, html) {
    const div = document.createElement("div");
    div.className = "chat-line " + cls;
    div.innerHTML = html;
    scroll.appendChild(div);
    scroll.scrollTop = scroll.scrollHeight;
    while (scroll.children.length > 500) scroll.removeChild(scroll.firstChild);
  }

  const hhmm = (ts) => {
    const d = new Date(ts * 1000);
    return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
  };
  const esc = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);

  entry.addEventListener("keydown", async (e) => {
    if (e.key !== "Enter") return;
    const text = entry.value;
    if (!text.trim()) return;
    entry.value = "";
    const room = getState().room;
    try {
      if (text.startsWith("/me ")) {
        await invoke("send_chat", { room, flags: CHAT_ACTION, text: text.slice(4) });
      } else if (text.startsWith("/topic ")) {
        await invoke("set_topic", { room, topic: text.slice(7) });
      } else {
        await invoke("send_chat", { room, flags: 0, text });
      }
    } catch (err) {
      line("err", "! " + (err.message || err));
    }
  });

  const api = {
    body,
    onChat(ev) {
      const ts = hhmm(ev.timestamp);
      if (ev.flags & CHAT_SYSTEM) {
        line("sys", `<span class="ts">${ts}</span>*** ${esc(ev.text)}`);
      } else if (ev.flags & CHAT_ACTION) {
        line("action", `<span class="ts">${ts}</span>*** ${esc(ev.sender)} ${esc(ev.text)}`);
      } else {
        line("", `<span class="ts">${ts}</span><span class="nick">&lt;${esc(ev.sender)}&gt;</span> ${esc(ev.text)}`);
      }
    },
    onUsers(users) {
      usersEl.innerHTML = "";
      for (const u of users) {
        const d = document.createElement("div");
        d.className = "u";
        d.textContent = u;
        usersEl.appendChild(d);
      }
    },
    onTopic(topic) {
      topicEl.textContent = "topic: " + (topic || "—");
    },
    onWarning(text) {
      line("warn", "! " + esc(text));
    },
    onError(text) {
      line("err", "! " + esc(text));
    },
    focusEntry() {
      entry.focus();
    },
  };
  return api;
}
