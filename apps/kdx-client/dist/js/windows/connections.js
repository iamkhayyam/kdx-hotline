// Connection Monitor — live view of every current session. Same shape as
// the User List, but the server enforces USER_KICK so plain users cannot
// enumerate everyone's address / idle time. Auto-refreshes every 5s while
// the window is visible; the timer stops when it's hidden or closed.

import { invoke } from "../bridge.js";

const CLASS_NAME = ["guest", "user", "power user", "admin"];
const REFRESH_MS = 5000;

export function buildConnections() {
  const body = document.createElement("div");
  body.className = "roles-win";
  body.innerHTML = `
    <div class="ab-toolbar">
      <input class="ab-filter" id="cn-filter" placeholder="filter…" spellcheck="false" />
      <button class="mini" id="cn-refresh">Refresh</button>
    </div>
    <div class="win-body" id="cn-list"></div>
  `;
  const $ = (s) => body.querySelector(s);
  const listEl = $("#cn-list");
  const filter = $("#cn-filter");
  let rows = [];
  let timer = null;

  async function refresh() {
    try {
      rows = await invoke("list_connections");
      render();
    } catch (err) {
      listEl.innerHTML = `<div class="empty">${esc(err.message || String(err))}</div>`;
      // Stop the auto-refresh if the server rejects us — no point spamming
      // a permissions error. A manual Refresh click can re-try.
      stop();
    }
  }

  function render() {
    const needle = filter.value.trim().toLowerCase();
    const shown = rows.filter(
      (r) =>
        !needle ||
        r.username.toLowerCase().includes(needle) ||
        r.address.toLowerCase().includes(needle)
    );
    if (!shown.length) {
      listEl.innerHTML = '<div class="empty">no live sessions</div>';
      return;
    }
    const table = document.createElement("table");
    table.className = "files";
    table.innerHTML =
      "<thead><tr><th></th><th>User</th><th>Class</th>" +
      "<th>Address</th><th>Login</th><th>Idle</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const r of shown) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td><span class="classbar" data-class="${r.class}"></span></td>` +
        `<td class="fname">${esc(r.username)}</td>` +
        `<td class="fsize">${esc(CLASS_NAME[r.class] || "?")}</td>` +
        `<td class="fmeta">${esc(r.address)}</td>` +
        `<td class="fsize">${esc(fmtLoginAt(r.login_at))}</td>` +
        `<td class="fsize">${esc(fmtIdle(r.idle_secs))}</td>`;
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.innerHTML = "";
    listEl.appendChild(table);
  }

  function start() {
    if (timer) return;
    refresh();
    timer = setInterval(refresh, REFRESH_MS);
  }
  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  $("#cn-refresh").addEventListener("click", refresh);
  filter.addEventListener("input", render);

  return { body, refresh, start, stop };
}

function fmtLoginAt(unixSecs) {
  return new Date(unixSecs * 1000).toLocaleTimeString();
}
function fmtIdle(secs) {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  return `${Math.floor(secs / 3600)}h`;
}
function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}
