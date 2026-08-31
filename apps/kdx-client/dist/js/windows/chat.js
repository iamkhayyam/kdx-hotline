import { invoke, emitUi } from "../bridge.js";
import { getState, update } from "../store.js";
import { open } from "../wm.js";
import { showMenu } from "../menu.js";

const CHAT_ACTION = 1 << 0;
const CHAT_SYSTEM = 1 << 1;
const DEFAULT_ROOM = "lobby";

// Your own identity (set via /name and /desc); kept module-side so setting
// one never wipes the other.
const identity = { name: "", description: "" };

// Slash-command help, shown by /help. Both `/` and `\` prefixes are accepted.
const SLASH_HELP = [
  "/me <action> — pose an action (also \\me)",
  "/away [reason] · /back · /afk — announce your status",
  "/topic <text> — set the room topic",
  "/roomflags <min-class 0-3> <on|off> — set join gate + interview mode",
  "/clear — clear this transcript",
  "/help — this list",
];

export function buildChat() {
  const body = document.createElement("div");
  body.style.flex = "1";
  body.style.display = "flex";
  body.style.flexDirection = "column";
  body.style.minHeight = "0";
  body.innerHTML = `
    <div class="topicbar" id="chat-topic"><span id="chat-topic-text">topic: —</span><span class="chat-room-tag" id="chat-room-tag"></span></div>
    <div class="chat-invite-banner hidden" id="chat-invite-banner"></div>
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
  const topicTextEl = body.querySelector("#chat-topic-text");
  const roomTagEl = body.querySelector("#chat-room-tag");
  const inviteBanner = body.querySelector("#chat-invite-banner");
  const entry = body.querySelector("#chat-entry");

  function renderRoomTag() {
    const room = getState().room;
    if (room === DEFAULT_ROOM) {
      roomTagEl.innerHTML = "";
      return;
    }
    roomTagEl.innerHTML = ` · private chat <button class="mini" id="chat-back-to-lobby">Back to Lobby</button>`;
    roomTagEl.querySelector("#chat-back-to-lobby").onclick = () => switchRoom(DEFAULT_ROOM);
  }

  async function switchRoom(room) {
    const previous = getState().room;
    if (previous === room) return;
    try {
      await invoke("join_room", { room });
    } catch (err) {
      line("err", "! " + (err.message || err));
      return; // the join itself failed — we're still in the old room
    }
    // The join succeeded, so we ARE in the new room now from the user's
    // point of view — reflect that immediately. Leaving the old room is
    // best-effort cleanup after the fact; if it fails, that's a stale
    // server-side membership to warn about, not a reason to tell the user
    // they never actually switched.
    update({ room, users: [], topic: "" });
    topicTextEl.textContent = "topic: —";
    renderRoomTag();
    scroll.innerHTML = "";
    line("sys", `*** now in ${room === DEFAULT_ROOM ? "the lobby" : "a private chat"}`);
    if (previous) {
      try {
        await invoke("leave_room", { room: previous });
      } catch (err) {
        line("warn", "! couldn't leave the previous room: " + (err.message || err));
      }
    }
  }

  /** A ChatInvited event — show an accept/ignore banner. */
  function onInvited(ev) {
    inviteBanner.innerHTML =
      `<b>${esc(ev.from)}</b> invited you to a private chat — ` +
      `<button class="mini" id="chat-invite-join">Join</button>` +
      `<button class="mini" id="chat-invite-ignore">Ignore</button>`;
    inviteBanner.classList.remove("hidden");
    inviteBanner.querySelector("#chat-invite-join").onclick = async () => {
      inviteBanner.classList.add("hidden");
      await switchRoom(ev.room);
    };
    inviteBanner.querySelector("#chat-invite-ignore").onclick = () => {
      inviteBanner.classList.add("hidden");
    };
  }

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
    const raw = entry.value;
    if (!raw.trim()) return;
    entry.value = "";
    try {
      await handleInput(raw);
    } catch (err) {
      line("err", "! " + (err.message || err));
    }
  });

  // Parse and dispatch a line of input. A leading `/` or `\` marks a command;
  // everything else is an ordinary chat message.
  async function handleInput(raw) {
    const room = getState().room;
    if (!/^[/\\]/.test(raw)) {
      await invoke("send_chat", { room, flags: 0, text: raw });
      return;
    }
    const space = raw.indexOf(" ");
    const cmd = (space === -1 ? raw.slice(1) : raw.slice(1, space)).toLowerCase();
    const rest = space === -1 ? "" : raw.slice(space + 1);
    switch (cmd) {
      case "me":
        if (rest.trim()) await invoke("send_chat", { room, flags: CHAT_ACTION, text: rest });
        break;
      case "away":
        await invoke("send_chat", { room, flags: CHAT_ACTION, text: rest.trim() ? `is away (${rest.trim()})` : "is away" });
        break;
      case "back":
        await invoke("send_chat", { room, flags: CHAT_ACTION, text: "is back" });
        break;
      case "afk":
        await invoke("send_chat", { room, flags: CHAT_ACTION, text: rest.trim() ? `is afk (${rest.trim()})` : "is afk" });
        break;
      case "topic":
        await invoke("set_topic", { room, topic: rest });
        break;
      case "roomflags": {
        // Two positional args: `<minclass 0-3> <on|off>`. Both required, so
        // the caller thinks about both at once rather than clobbering one
        // accidentally.
        const parts = rest.trim().split(/\s+/);
        if (parts.length < 2) {
          line("err", "! usage: /roomflags <min-class 0-3> <on|off>");
          break;
        }
        const minClassJoin = parseInt(parts[0], 10);
        if (!Number.isInteger(minClassJoin) || minClassJoin < 0 || minClassJoin > 3) {
          line("err", "! min-class must be 0..3");
          break;
        }
        const modeArg = parts[1].toLowerCase();
        if (modeArg !== "on" && modeArg !== "off") {
          line("err", "! interview mode must be 'on' or 'off'");
          break;
        }
        try {
          await invoke("set_room_flags", {
            room,
            minClassJoin,
            interviewMode: modeArg === "on",
          });
        } catch (err) {
          line("err", "! " + (err.message || err));
        }
        break;
      }
      case "clear":
        scroll.innerHTML = "";
        break;
      case "help":
        for (const h of SLASH_HELP) line("sys", `*** ${esc(h)}`);
        break;
      case "name":
      case "n":
        identity.name = rest.trim();
        await invoke("set_identity", { name: identity.name, description: identity.description });
        line("sys", `*** display name set to ${esc(identity.name || "(none)")}`);
        break;
      case "desc":
      case "d":
        identity.description = rest.trim();
        await invoke("set_identity", { name: identity.name, description: identity.description });
        line("sys", `*** description set to ${esc(identity.description || "(none)")}`);
        break;
      default:
        line("err", `! unknown command: /${esc(cmd)} — try /help`);
    }
  }

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
      const me = getState().session && getState().session.username;
      for (const u of users) {
        const d = document.createElement("div");
        d.className = "u";
        d.textContent = u;
        // Right-click (or second click) a member for the verb menu — the
        // primary action surface, mirroring the global User List.
        d.addEventListener("contextmenu", (e) => {
          e.preventDefault();
          const items = [];
          if (u !== me) {
            items.push({
              label: "Send Message",
              fn: () => {
                open("messages");
                emitUi("messages", "open-with", { user: u });
              },
            });
          }
          items.push({
            label: "Get Info",
            fn: () => {
              open("userinfo");
              emitUi("userinfo", "show", { user: u });
            },
          });
          if (u !== me) {
            items.push({ label: "Invite to Chat…", fn: () => invoke("invite_to_chat", { to: u }).catch(() => {}) });
          }
          if (items.length) showMenu(e.clientX, e.clientY, items);
        });
        usersEl.appendChild(d);
      }
    },
    onTopic(topic) {
      topicTextEl.textContent = "topic: " + (topic || "—");
    },
    onInvited: onInvited,
    // Called on window open so the room tag / "Back to Lobby" affordance is
    // correct even if the window is opened after already being switched into
    // a non-lobby room (e.g. accepted an invite before ever opening Chat).
    refreshRoomTag: renderRoomTag,
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
