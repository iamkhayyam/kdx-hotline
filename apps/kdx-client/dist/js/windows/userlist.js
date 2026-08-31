// User List — the server-wide roster (distinct from a chat room's member
// list). Class color bars per row, type-to-filter, right-click "Get Info".

import { invoke, emitUi } from "../bridge.js";
import { open } from "../wm.js";
import { showMenu } from "../menu.js";

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
      listEl.innerHTML = `<div class="empty">${err.message || err}</div>`;
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
        `<span class="classbar" data-class="${u.class}"></span>` +
        `<span class="ul-name">${esc(u.name && u.name.trim() ? u.name + " (" + u.username + ")" : u.username)}</span>` +
        `<span class="ul-meta">${CLASS_NAME[u.class] || "?"} · idle ${fmtIdle(u.idle_secs)}${u.description && u.description.trim() ? " · " + esc(u.description) : ""}</span>`;
      row.addEventListener("click", () => {
        open("userinfo");
        emitUi("userinfo", "show", { user: u.username });
      });
      row.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        const items = [
          {
            label: "Send Message",
            fn: () => {
              open("messages");
              emitUi("messages", "open-with", { user: u.username });
            },
          },
          {
            label: "Get Info",
            fn: () => {
              open("userinfo");
              emitUi("userinfo", "show", { user: u.username });
            },
          },
        ];
        items.push({ label: "Invite to Chat…", fn: () => invoke("invite_to_chat", { to: u.username }).catch(() => {}) });
        items.push({
          label: "Disconnect…",
          fn: () => {
            open("admin");
            emitUi("admin", "open-disconnect", { user: u.username });
          },
        });
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
function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}
