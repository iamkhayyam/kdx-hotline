import { invoke, deliver, currentGeneration } from "../bridge.js";
import { getState, update } from "../store.js";
import { showMenu } from "../menu.js";
import { esc, errorText } from "../html.js";
import { inCurrentRoom, shouldAdoptRoom, createJoinTracker, INVITE_ADOPT_MS } from "../rooms.js";

const CHAT_ACTION = 1 << 0;
const CHAT_SYSTEM = 1 << 1;
const DEFAULT_ROOM = "lobby";
const MAX_LINES = 500;
// The room on screen, per connection generation, so a Chat window reopened
// mid-session comes back to the room the connection is actually in.
const ROOM_KEY = "kdx.chat.room";

function saveRoom(room) {
  try {
    if (room === DEFAULT_ROOM) localStorage.removeItem(ROOM_KEY);
    else localStorage.setItem(ROOM_KEY, JSON.stringify({ gen: currentGeneration(), room }));
  } catch (_) {}
}
function savedRoom(gen) {
  try {
    const s = JSON.parse(localStorage.getItem(ROOM_KEY) || "null");
    return s && s.gen === gen && typeof s.room === "string" ? s.room : null;
  } catch (_) {
    return null;
  }
}

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

/** opts.onUserCount(n): the room on screen now has `n` members. */
export function buildChat(opts = {}) {
  const body = document.createElement("div");
  body.className = "col-fill";
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

  // Set while an invite we sent is waiting for the server to tell us the id
  // of the private room it put us in: { to, until }.
  let pendingInvite = null;
  // A join waiting for the server's answer, and what arrived for its room.
  const joins = createJoinTracker();

  function renderRoomTag() {
    const room = getState().room;
    if (room === DEFAULT_ROOM) {
      roomTagEl.textContent = "";
      return;
    }
    roomTagEl.innerHTML = ` · private chat <button class="mini" id="chat-back-to-lobby">Back to Lobby</button>`;
    roomTagEl.querySelector("#chat-back-to-lobby").onclick = () => switchRoom(DEFAULT_ROOM);
  }

  /** Show `room` from now on (we're already a member server-side). */
  function showRoom(room, banner) {
    update({ room, users: [], topic: "" });
    saveRoom(room);
    topicTextEl.textContent = "topic: —";
    applyUsers([]);
    renderRoomTag();
    scroll.textContent = "";
    lineText("sys", banner);
  }

  async function leaveBestEffort(room) {
    if (!room) return;
    try {
      await invoke("leave_room", { room });
    } catch (err) {
      lineText("warn", "! couldn't leave the previous room: " + errorText(err));
    }
  }

  async function switchRoom(room) {
    const previous = getState().room;
    if (previous === room) return;
    joins.begin(room);
    try {
      // Resolves only once the server has let us in (a refusal — e.g. a
      // private room whose other member already left — rejects).
      await invoke("join_room", { room });
    } catch (err) {
      joins.abort(room);
      const here = previous === DEFAULT_ROOM ? "the lobby" : "this chat";
      lineText("err", `! couldn't join: ${errorText(err)} — still in ${here}`);
      return; // the join itself failed — we're still in the old room
    }
    // The server confirmed the join, so we ARE in the new room now —
    // reflect that, with whatever arrived for it meanwhile. Leaving the old
    // room is best-effort cleanup after the fact; if it fails, that's a
    // stale server-side membership to warn about, not a reason to tell the
    // user they never actually switched.
    const early = joins.finish(room);
    showRoom(room, `*** now in ${room === DEFAULT_ROOM ? "the lobby" : "a private chat"}`);
    if (early) {
      if (early.users) applyUsers(early.users);
      if (early.topic != null) topicTextEl.textContent = "topic: " + (early.topic || "—");
      for (const ev of early.lines) api.onChat(ev);
    }
    await leaveBestEffort(previous);
  }

  /** The server put us in `room` because we invited someone: switch the
   * view there (so their messages don't land in the lobby, and our replies
   * don't go to it), and leave the lobby as an invitee would. */
  async function adoptPrivateRoom(room, users) {
    const previous = getState().room;
    if (previous === room) return;
    const to = pendingInvite ? pendingInvite.to : "";
    pendingInvite = null;
    showRoom(room, `*** private chat${to ? " with " + to : ""} — waiting for them to join`);
    if (users) applyUsers(users);
    await leaveBestEffort(previous);
  }

  /** Invite `user` to a new private chat (from the roster or User List). */
  async function invite(user) {
    if (!user) return;
    pendingInvite = { to: user, until: Date.now() + INVITE_ADOPT_MS };
    try {
      const room = await invoke("invite_to_chat", { to: user });
      // If the backend reports the new room's id, use it directly;
      // otherwise the room's first user_list triggers the switch.
      if (typeof room === "string" && room && pendingInvite) await adoptPrivateRoom(room, null);
    } catch (err) {
      pendingInvite = null;
      lineText("err", "! " + errorText(err));
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

  /** Append a transcript line built from [className|null, text] parts —
   * DOM text nodes only, so nothing a server sends is ever parsed as HTML. */
  function addLine(cls, parts) {
    const div = document.createElement("div");
    div.className = "chat-line" + (cls ? " " + cls : "");
    for (const [partCls, text] of parts) {
      if (partCls) {
        const span = document.createElement("span");
        span.className = partCls;
        span.textContent = text;
        div.appendChild(span);
      } else {
        div.appendChild(document.createTextNode(text));
      }
    }
    scroll.appendChild(div);
    scroll.scrollTop = scroll.scrollHeight;
    while (scroll.children.length > MAX_LINES) scroll.removeChild(scroll.firstChild);
  }

  function lineText(cls, text) {
    addLine(cls, [[null, text]]);
  }

  const hhmm = (ts) => {
    const d = new Date(ts * 1000);
    return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
  };

  entry.addEventListener("keydown", async (e) => {
    if (e.key !== "Enter") return;
    const raw = entry.value;
    if (!raw.trim()) return;
    entry.value = "";
    try {
      await handleInput(raw);
    } catch (err) {
      lineText("err", "! " + errorText(err));
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
          lineText("err", "! usage: /roomflags <min-class 0-3> <on|off>");
          break;
        }
        const minClassJoin = parseInt(parts[0], 10);
        if (!Number.isInteger(minClassJoin) || minClassJoin < 0 || minClassJoin > 3) {
          lineText("err", "! min-class must be 0..3");
          break;
        }
        const modeArg = parts[1].toLowerCase();
        if (modeArg !== "on" && modeArg !== "off") {
          lineText("err", "! interview mode must be 'on' or 'off'");
          break;
        }
        try {
          await invoke("set_room_flags", {
            room,
            minClassJoin,
            interviewMode: modeArg === "on",
          });
        } catch (err) {
          lineText("err", "! " + errorText(err));
        }
        break;
      }
      case "clear":
        scroll.textContent = "";
        break;
      case "help":
        for (const h of SLASH_HELP) lineText("sys", `*** ${h}`);
        break;
      case "name":
      case "n":
        identity.name = rest.trim();
        await invoke("set_identity", { name: identity.name, description: identity.description });
        lineText("sys", `*** display name set to ${identity.name || "(none)"}`);
        break;
      case "desc":
      case "d":
        identity.description = rest.trim();
        await invoke("set_identity", { name: identity.name, description: identity.description });
        lineText("sys", `*** description set to ${identity.description || "(none)"}`);
        break;
      default:
        lineText("err", `! unknown command: /${cmd} — try /help`);
    }
  }

  function applyUsers(users) {
    update({ users });
    if (opts.onUserCount) opts.onUserCount(users.length);
    usersEl.textContent = "";
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
          items.push({ label: "Send Message", fn: () => deliver("messages", "open-with", { user: u }) });
        }
        items.push({ label: "Get Info", fn: () => deliver("userinfo", "show", { user: u }) });
        if (u !== me) {
          items.push({ label: "Invite to Chat…", fn: () => invite(u) });
        }
        if (items.length) showMenu(e.clientX, e.clientY, items);
      });
      usersEl.appendChild(d);
    }
  }

  const api = {
    body,
    onChat(ev) {
      if (!inCurrentRoom(ev, getState().room)) {
        joins.offer(ev);
        return;
      }
      const ts = hhmm(ev.timestamp);
      if (ev.flags & CHAT_SYSTEM) {
        addLine("sys", [["ts", ts], [null, `*** ${ev.text}`]]);
      } else if (ev.flags & CHAT_ACTION) {
        addLine("action", [["ts", ts], [null, `*** ${ev.sender} ${ev.text}`]]);
      } else {
        addLine("", [["ts", ts], ["nick", `<${ev.sender}>`], [null, ` ${ev.text}`]]);
      }
    },
    /** A room's member list. Returns true if it was applied to the view. */
    onUserList(ev) {
      const current = getState().room;
      if (ev.room !== current) {
        // The room we're joining: applied once the join is confirmed.
        if (joins.offer(ev)) return false;
        if (shouldAdoptRoom(ev.room, current, pendingInvite)) {
          adoptPrivateRoom(ev.room, ev.users);
          return true;
        }
        return false;
      }
      applyUsers(ev.users);
      return true;
    },
    onTopic(ev) {
      if (!inCurrentRoom(ev, getState().room)) {
        joins.offer(ev);
        return;
      }
      topicTextEl.textContent = "topic: " + (ev.topic || "—");
    },
    onInvited: onInvited,
    invite,
    /** The connection ended: membership is gone, so the next login starts
     * in the lobby again. */
    onDisconnected() {
      pendingInvite = null;
      if (joins.room) joins.abort(joins.room);
      update({ room: DEFAULT_ROOM, users: [], topic: "" });
      saveRoom(DEFAULT_ROOM);
      usersEl.textContent = "";
      topicTextEl.textContent = "topic: —";
      inviteBanner.classList.add("hidden");
      renderRoomTag();
    },
    /** After hydration: a Chat window reopened while this connection is in
     * a private room shows that room again (its events would otherwise be
     * filtered out as "another room"). */
    afterHydrate(session) {
      const room = session && savedRoom(session.gen);
      if (room && room !== getState().room) {
        update({ room });
        renderRoomTag();
        lineText("sys", "*** in a private chat");
      }
    },
    refreshRoomTag: renderRoomTag,
    onWarning(text) {
      lineText("warn", "! " + text);
    },
    onError(text) {
      lineText("err", "! " + text);
    },
    focusEntry() {
      entry.focus();
    },
  };
  return api;
}
