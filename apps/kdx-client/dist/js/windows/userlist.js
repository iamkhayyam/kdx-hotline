// User List — the server-wide roster (distinct from a chat room's member
// list). Class color bars per row, type-to-filter, right-click "Get Info"
// plus the verbs the session's privileges allow (privileges.js).

import { invoke, deliver } from "../bridge.js";
import { showMenu } from "../menu.js";
import { getState } from "../store.js";
import { esc, num, errorText } from "../html.js";
import { peerActions } from "../privileges.js";

const CLASS_NAME = ["guest", "user", "power user", "admin"];

export function buildUserList() {
  const body = document.createElement("div");
  body.className = "userlist-win";
  body.innerHTML = `
    <div class="ab-toolbar">
      <input class="ab-filter" id="ul-filter" placeholder="filter…" spellcheck="false" />
      <button class="mini" id="ul-refresh">Refresh</button>
    </div>
    <div class="win-body" id="ul-list"></div>
  `;

  const $ = (s) => body.querySelector(s);
  const listEl = $("#ul-list");
  const filter = $("#ul-filter");
  let users = [];

  async function refresh() {
    listEl.innerHTML = '<div class="empty">loading…</div>';
    try {
      users = await invoke("list_users");
      render();
    } catch (err) {
      listEl.innerHTML = `<div class="empty">${esc(errorText(err))}</div>`;
    }
  }

  function render() {
    const needle = filter.value.trim().toLowerCase();
    const shown = users.filter((u) => !needle || u.username.toLowerCase().includes(needle));
    if (!shown.length) {
      listEl.innerHTML = '<div class="empty">no one online</div>';
      return;
    }
    listEl.innerHTML = "";
    for (const u of shown) {
      const row = document.createElement("div");
      row.className = "ul-row";
      row.innerHTML =
        `<span class="classbar" data-class="${num(u.class)}"></span>` +
        `<span class="ul-name">${esc(u.name && u.name.trim() ? u.name + " (" + u.username + ")" : u.username)}</span>` +
        `<span class="ul-meta">${esc(CLASS_NAME[u.class] || "?")} · idle ${esc(fmtIdle(u.idle_secs))}${u.description && u.description.trim() ? " · " + esc(u.description) : ""}</span>`;
      row.addEventListener("click", () => deliver("userinfo", "show", { user: u.username }));
      row.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        // Only the verbs this session holds the privilege for.
        const may = peerActions(getState().session);
        const items = [];
        if (may.message) {
          items.push({ label: "Send Message", fn: () => deliver("messages", "open-with", { user: u.username }) });
        }
        items.push({ label: "Get Info", fn: () => deliver("userinfo", "show", { user: u.username }) });
        // The Chat window sends the invite, so it can follow the inviter
        // into the private room the server creates.
        if (may.invite) {
          items.push({ label: "Invite to Chat…", fn: () => deliver("chat", "invite", { user: u.username }) });
        }
        if (may.disconnect) {
          items.push({ label: "Disconnect…", fn: () => deliver("admin", "open-disconnect", { user: u.username }) });
        }
        showMenu(e.clientX, e.clientY, items);
      });
      listEl.appendChild(row);
    }
  }

  /** Apply a live presence change without a full re-fetch. */
  function onPresence(user, online) {
    users = users.filter((u) => u.username !== user.username);
    if (online) users.push(user);
    render();
  }

  filter.addEventListener("input", render);
  $("#ul-refresh").addEventListener("click", refresh);

  return { body, refresh, onPresence, get count() { return users.length; } };
}

function fmtIdle(secs) {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  return `${Math.floor(secs / 3600)}h`;
}
