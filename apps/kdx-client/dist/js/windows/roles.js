// Administration — SysOp-defined custom roles (Discord-style): named,
// colorable privilege bundles a SysOp can create and assign to accounts on
// top of their base class. Viewing the list is open to any connected user;
// mutations are server-enforced on USER_ADMIN and simply error otherwise.

import { invoke } from "../bridge.js";
import { open } from "../wm.js";

const PRIVILEGES = [
  { bit: 1 << 0, name: "CHAT_SEND", label: "Chat: send" },
  { bit: 1 << 1, name: "CHAT_PRIVATE", label: "Chat: private message" },
  { bit: 1 << 2, name: "CHAT_CREATE_ROOM", label: "Chat: create room" },
  { bit: 1 << 3, name: "CHAT_SET_TOPIC", label: "Chat: set topic" },
  { bit: 1 << 4, name: "FILE_LIST", label: "Files: list" },
  { bit: 1 << 5, name: "FILE_DOWNLOAD", label: "Files: download" },
  { bit: 1 << 6, name: "FILE_UPLOAD", label: "Files: upload" },
  { bit: 1 << 7, name: "FILE_DELETE", label: "Files: delete" },
  { bit: 1 << 8, name: "FILE_MANAGE_TREE", label: "Files: manage tree" },
  { bit: 1 << 16, name: "USER_KICK", label: "Users: kick" },
  { bit: 1 << 17, name: "USER_BAN", label: "Users: ban" },
  { bit: 1 << 18, name: "USER_ADMIN", label: "Users: manage accounts/roles" },
  { bit: 1 << 19, name: "SERVER_ADMIN", label: "Server: config/shutdown" },
];

export function buildRoles() {
  const body = document.createElement("div");
  body.className = "roles-win";
  body.innerHTML = `
    <div class="ab-toolbar">
      <input class="ab-filter" id="rl-filter" placeholder="filter…" spellcheck="false" />
      <button class="mini" id="rl-accounts">Accounts…</button>
      <button class="mini" id="rl-server">Server…</button>
      <button class="mini" id="rl-history">History…</button>
      <button class="mini" id="rl-iprules">IP Rules…</button>
      <button class="mini" id="rl-connections">Connections…</button>
      <button class="mini" id="rl-new">New Role</button>
      <button class="mini" id="rl-refresh">Refresh</button>
    </div>
    <div class="win-body" id="rl-list"></div>
    <form class="ab-editor hidden" id="rl-editor">
      <div class="ab-grid">
        <label>Name<input id="rl-name" spellcheck="false" /></label>
        <label>Color<input id="rl-color" placeholder="#e11b1b" spellcheck="false" /></label>
        <label>Rank<input id="rl-rank" value="0" /></label>
      </div>
      <div class="rl-privs" id="rl-privs"></div>
      <div class="ab-actions">
        <button type="submit" class="btn">Save</button>
        <button type="button" class="btn" id="rl-delete">Delete</button>
        <button type="button" class="btn" id="rl-cancel">Cancel</button>
      </div>
    </form>
    <div class="rl-assign">
      <div class="rl-assign-head">Roles</div>
      <div class="rl-assign-row">
        <input id="rl-username" placeholder="username" spellcheck="false" />
        <select id="rl-role-select"></select>
        <button class="mini" id="rl-assign-btn">Assign</button>
        <button class="mini" id="rl-unassign-btn">Unassign</button>
        <button class="mini" id="rl-lookup-btn">Look Up</button>
      </div>
      <div class="rl-assign-result" id="rl-assign-result"></div>
    </div>
    <div class="rl-kick">
      <div class="rl-assign-head">Disconnect User</div>
      <div class="rl-assign-row">
        <input id="rl-kick-user" placeholder="username" spellcheck="false" />
        <input id="rl-kick-reason" class="rl-kick-reason" placeholder="reason (optional)" spellcheck="false" />
      </div>
      <div class="rl-assign-row">
        <label class="rl-kick-ban">Ban
          <select id="rl-kick-ban">
            <option value="0">no ban (kick only)</option>
            <option value="300">5 minutes</option>
            <option value="3600">1 hour</option>
            <option value="86400">1 day</option>
            <option value="604800">1 week</option>
            <option value="31536000">1 year</option>
          </select>
        </label>
        <button class="mini danger" id="rl-kick-btn">Disconnect</button>
      </div>
      <div class="rl-assign-result" id="rl-kick-result"></div>
    </div>
  `;

  const $ = (s) => body.querySelector(s);
  const listEl = $("#rl-list");
  const filter = $("#rl-filter");
  const editor = $("#rl-editor");
  const privsEl = $("#rl-privs");
  const roleSelect = $("#rl-role-select");
  const assignResult = $("#rl-assign-result");
  let roles = [];
  let editingId = null;

  privsEl.innerHTML = PRIVILEGES.map(
    (p) => `<label class="rl-priv"><input type="checkbox" data-bit="${p.bit}" />${p.label}</label>`
  ).join("");

  async function refresh() {
    listEl.innerHTML = '<div class="empty">loading…</div>';
    try {
      roles = await invoke("list_roles");
      roles.sort((a, b) => b.rank - a.rank);
      render();
    } catch (err) {
      listEl.innerHTML = `<div class="empty">${err.message || err}</div>`;
    }
  }

  function render() {
    const needle = filter.value.trim().toLowerCase();
    const shown = roles.filter((r) => !needle || r.name.toLowerCase().includes(needle));
    roleSelect.innerHTML = roles.map((r) => `<option value="${r.id}">${esc(r.name)}</option>`).join("");
    if (!shown.length) {
      listEl.innerHTML = '<div class="empty">no roles — New Role to define one</div>';
      return;
    }
    const table = document.createElement("table");
    table.className = "files";
    table.innerHTML =
      "<thead><tr><th></th><th>Name</th><th>Rank</th><th>Privileges</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const r of shown) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td><span class="rl-swatch" style="background:${esc(r.color || "#6b5555")}"></span></td>` +
        `<td class="fname">${esc(r.name)}</td>` +
        `<td class="fsize">${r.rank}</td>` +
        `<td class="fmeta">${countBits(r.privileges)} granted</td>`;
      tr.addEventListener("click", () => openEditor(r));
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.appendChild(table);
  }

  function openEditor(role) {
    editingId = role ? role.id : null;
    $("#rl-name").value = role ? role.name : "";
    $("#rl-color").value = role ? role.color : "";
    $("#rl-rank").value = role ? role.rank : 0;
    for (const cb of privsEl.querySelectorAll("input[type=checkbox]")) {
      const bit = Number(cb.dataset.bit);
      cb.checked = role ? (role.privileges & bit) !== 0 : false;
    }
    $("#rl-delete").classList.toggle("hidden", !role);
    editor.classList.remove("hidden");
    listEl.classList.add("hidden");
  }

  function closeEditor() {
    editor.classList.add("hidden");
    listEl.classList.remove("hidden");
    editingId = null;
  }

  function collectPrivileges() {
    let bits = 0;
    for (const cb of privsEl.querySelectorAll("input[type=checkbox]")) {
      if (cb.checked) bits |= Number(cb.dataset.bit);
    }
    return bits >>> 0;
  }

  $("#rl-new").addEventListener("click", () => openEditor(null));
  $("#rl-cancel").addEventListener("click", closeEditor);
  $("#rl-refresh").addEventListener("click", refresh);
  $("#rl-accounts").addEventListener("click", () => open("accounts"));
  $("#rl-server").addEventListener("click", () => open("server"));
  $("#rl-history").addEventListener("click", () => open("history"));
  $("#rl-iprules").addEventListener("click", () => open("iprules"));
  $("#rl-connections").addEventListener("click", () => open("connections"));
  filter.addEventListener("input", render);

  editor.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = $("#rl-name").value.trim();
    if (!name) return;
    const color = $("#rl-color").value.trim();
    const rank = parseInt($("#rl-rank").value, 10) || 0;
    const privileges = collectPrivileges();
    try {
      roles = editingId
        ? await invoke("update_role", { id: editingId, name, privileges, rank, color })
        : await invoke("create_role", { name, privileges, rank, color });
      roles.sort((a, b) => b.rank - a.rank);
      closeEditor();
      render();
    } catch (err) {
      assignResult.textContent = err.message || String(err);
    }
  });

  $("#rl-delete").addEventListener("click", async () => {
    if (!editingId) return;
    try {
      roles = await invoke("delete_role", { id: editingId });
      closeEditor();
      render();
    } catch (err) {
      assignResult.textContent = err.message || String(err);
    }
  });

  $("#rl-assign-btn").addEventListener("click", () => assignOrUnassign("assign_role"));
  $("#rl-unassign-btn").addEventListener("click", () => assignOrUnassign("unassign_role"));

  async function assignOrUnassign(cmd) {
    const username = $("#rl-username").value.trim();
    const roleId = roleSelect.value;
    if (!username || !roleId) return;
    try {
      await invoke(cmd, { username, roleId });
      assignResult.textContent = `ok: ${cmd === "assign_role" ? "assigned" : "unassigned"} for ${username}`;
    } catch (err) {
      assignResult.textContent = err.message || String(err);
    }
  }

  $("#rl-lookup-btn").addEventListener("click", async () => {
    const username = $("#rl-username").value.trim();
    if (!username) return;
    try {
      const ids = await invoke("account_roles", { username });
      const names = ids.map((id) => roles.find((r) => r.id === id)?.name || id);
      assignResult.textContent = names.length ? `${username}: ${names.join(", ")}` : `${username}: no roles`;
    } catch (err) {
      assignResult.textContent = err.message || String(err);
    }
  });

  const kickResult = $("#rl-kick-result");
  $("#rl-kick-btn").addEventListener("click", async () => {
    const username = $("#rl-kick-user").value.trim();
    if (!username) return;
    const reason = $("#rl-kick-reason").value.trim();
    const banSecs = parseInt($("#rl-kick-ban").value, 10) || 0;
    // The server acks over the event channel (server_info / server_error);
    // this just reflects that the request was sent.
    try {
      await invoke("disconnect_user", { username, reason, banSecs });
      kickResult.textContent = banSecs
        ? `requested disconnect + ban of ${username}`
        : `requested disconnect of ${username}`;
    } catch (err) {
      kickResult.textContent = err.message || String(err);
    }
  });

  /** Pre-fill the Disconnect panel from a User List context-menu verb. */
  function openDisconnect(username) {
    $("#rl-kick-user").value = username;
    $("#rl-kick-reason").value = "";
    kickResult.textContent = "";
    $("#rl-kick-user").scrollIntoView({ block: "nearest" });
  }

  return { body, refresh, openDisconnect };
}

function countBits(n) {
  let count = 0;
  let v = n >>> 0;
  while (v) {
    count += v & 1;
    v >>>= 1;
  }
  return count;
}
function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}
