// Trackers — the server directory. Lists the live servers the connected
// server's tracker knows about (name, population, address, description), with a
// type-to-filter box. "Connect" pre-fills the Connect window with a server's
// address so the user can authenticate to it.

import { invoke } from "../bridge.js";

export function buildTrackers(onConnect) {
  const body = document.createElement("div");
  body.className = "trk-win";
  body.innerHTML = `
    <div class="ab-toolbar">
      <input class="ab-filter" id="trk-filter" placeholder="filter servers…" spellcheck="false" />
      <button class="mini" id="trk-refresh">Refresh</button>
    </div>
    <div class="win-body" id="trk-list"></div>`;

  const $ = (s) => body.querySelector(s);
  const listEl = $("#trk-list");
  const filter = $("#trk-filter");
  let servers = [];

  async function refresh() {
    listEl.innerHTML = '<div class="empty">querying tracker…</div>';
    try {
      servers = await invoke("list_servers", { filter: "" });
      render();
    } catch (err) {
      listEl.innerHTML = `<div class="empty">${esc(err.message || String(err))}</div>`;
    }
  }

  function render() {
    const needle = filter.value.trim().toLowerCase();
    const shown = servers.filter(
      (s) => !needle || s.name.toLowerCase().includes(needle) || s.description.toLowerCase().includes(needle)
    );
    if (!shown.length) {
      listEl.innerHTML = `<div class="empty">${servers.length ? "no matches" : "no servers registered"}</div>`;
      return;
    }
    listEl.innerHTML = "";
    for (const s of shown) {
      const full = s.max_users > 0 && s.users >= s.max_users;
      const row = document.createElement("div");
      row.className = "trk-row";
      row.innerHTML =
        `<div class="trk-main">` +
        `<span class="trk-name">${esc(s.name)}</span>` +
        `<span class="trk-pop${full ? " full" : ""}">${s.users}/${s.max_users}</span>` +
        `</div>` +
        `<div class="trk-sub">${esc(s.description || "—")}</div>` +
        `<div class="trk-addr">${esc(s.host)}:${s.port}` +
        `<button class="mini" data-host="${esc(s.host)}" data-port="${s.port}">Connect</button></div>`;
      row.querySelector("button").addEventListener("click", () => onConnect(s.host, s.port));
      listEl.appendChild(row);
    }
  }

  filter.addEventListener("input", render);
  $("#trk-refresh").addEventListener("click", refresh);

  return { body, refresh };
}

function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}
