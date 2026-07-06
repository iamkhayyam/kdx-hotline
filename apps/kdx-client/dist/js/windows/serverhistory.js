// Server History — a read-only audit log of admin-worthy events (logins,
// kicks/bans, account/role/newsgroup changes, server settings edits,
// broadcasts, shutdowns). Requires SERVER_ADMIN; the server enforces it and
// errors otherwise. Newest first.

import { invoke } from "../bridge.js";

const HISTORY_LIMIT = 500;

const ACTION_LABEL = {
  login: "Login",
  login_failed: "Login failed",
  login_banned: "Login refused (banned)",
  kicked: "Kicked",
  banned: "Banned",
  account_created: "Account created",
  account_updated: "Account updated",
  role_created: "Role created",
  role_updated: "Role updated",
  role_deleted: "Role deleted",
  role_assigned: "Role assigned",
  role_unassigned: "Role unassigned",
  newsgroup_created: "Newsgroup created",
  server_settings_updated: "Server settings updated",
  broadcast: "Broadcast",
  shutdown: "Shutdown",
};

export function buildServerHistory() {
  const body = document.createElement("div");
  body.className = "roles-win";
  body.innerHTML = `
    <div class="ab-toolbar">
      <input class="ab-filter" id="sh-filter" placeholder="filter…" spellcheck="false" />
      <button class="mini" id="sh-refresh">Refresh</button>
    </div>
    <div class="win-body" id="sh-list"></div>
  `;

  const $ = (s) => body.querySelector(s);
  const listEl = $("#sh-list");
  const filter = $("#sh-filter");
  let entries = [];

  async function refresh() {
    listEl.innerHTML = '<div class="empty">loading…</div>';
    try {
      entries = await invoke("list_history", { limit: HISTORY_LIMIT });
      render();
    } catch (err) {
      listEl.innerHTML = `<div class="empty">${esc(err.message || String(err))}</div>`;
    }
  }

  function render() {
    const needle = filter.value.trim().toLowerCase();
    const shown = entries.filter(
      (e) =>
        !needle ||
        e.actor.toLowerCase().includes(needle) ||
        actionLabel(e.action).toLowerCase().includes(needle) ||
        e.detail.toLowerCase().includes(needle)
    );
    if (!shown.length) {
      listEl.innerHTML = '<div class="empty">no history yet</div>';
      return;
    }
    const table = document.createElement("table");
    table.className = "files";
    table.innerHTML =
      "<thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const e of shown) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td class="fsize">${esc(fmtTime(e.timestamp))}</td>` +
        `<td class="fname">${esc(e.actor || "—")}</td>` +
        `<td class="fsize">${esc(actionLabel(e.action))}</td>` +
        `<td class="fmeta">${esc(e.detail || "")}</td>`;
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.innerHTML = "";
    listEl.appendChild(table);
  }

  $("#sh-refresh").addEventListener("click", refresh);
  filter.addEventListener("input", render);

  return { body, refresh };
}

function actionLabel(action) {
  return ACTION_LABEL[action] || action;
}
function fmtTime(unixSecs) {
  return new Date(unixSecs * 1000).toLocaleString();
}
function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}
