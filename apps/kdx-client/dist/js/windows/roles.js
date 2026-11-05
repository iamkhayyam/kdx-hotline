// Administration — the moderation hub. SysOp-defined custom roles
// (Discord-style): named, colorable privilege bundles a SysOp can create and
// assign to accounts on top of their base class; the Disconnect User panel;
// and buttons to the other admin windows. Each tool is shown only to a
// session holding the privilege the server checks for it (privileges.js):
// roles (listing and changes) USER_ADMIN, disconnect USER_KICK, a ban with
// it USER_BAN too, and each window its own. The server enforces all of it.

import { invoke } from "../bridge.js";
import { open } from "../wm.js";
import { getState, subscribe } from "../store.js";
import { esc, num, safeColor, errorText } from "../html.js";
import { PRIVILEGES, adminTools, privilegesOf } from "../privileges.js";

const DEFAULT_SWATCH = "#6b5555";

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
      <button class="mini" id="rl-bans">Bans…</button>
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
    <div class="rl-assign" id="rl-roles-panel">
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
    <div class="rl-kick" id="rl-kick-panel">
      <div class="rl-assign-head">Disconnect User</div>
      <div class="rl-assign-row">
        <input id="rl-kick-user" placeholder="username" spellcheck="false" />
        <input id="rl-kick-reason" class="rl-kick-reason" placeholder="reason (optional)" spellcheck="false" />
      </div>
      <div class="rl-assign-row">
        <label class="rl-kick-ban" id="rl-kick-ban-field">Ban
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
    (p) => `<label class="rl-priv"><input type="checkbox" data-bit="${num(p.bit)}" />${esc(p.label)}</label>`
  ).join("");

  /** Show `text` in the role list's place. */
  function listNote(text) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = text;
    listEl.replaceChildren(empty);
  }

  async function refresh() {
    // Listing roles needs USER_ADMIN too: without it, don't ask.
    const session = getState().session;
    if (!session) {
      roles = [];
      listNote("not connected");
      return;
    }
    if (!adminTools(session).roles) {
      roles = [];
      listNote("managing roles needs the USER_ADMIN privilege");
      return;
    }
    listEl.innerHTML = '<div class="empty">loading…</div>';
    try {
      roles = await invoke("list_roles");
      roles.sort((a, b) => b.rank - a.rank);
      render();
    } catch (err) {
      // Server error text: shown as text, never parsed as markup.
      listNote(errorText(err));
    }
  }

  function render() {
    const needle = filter.value.trim().toLowerCase();
    const shown = roles.filter((r) => !needle || r.name.toLowerCase().includes(needle));
    roleSelect.innerHTML = roles.map((r) => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join("");
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
        `<td><span class="rl-swatch"></span></td>` +
        `<td class="fname">${esc(r.name)}</td>` +
        `<td class="fsize">${num(r.rank)}</td>` +
        `<td class="fmeta">${num(countBits(r.privileges))} granted</td>`;
      // The color is server data: only a plain hex color, applied via CSSOM
      // (an inline style= would be blocked by the CSP anyway).
      tr.querySelector(".rl-swatch").style.background = safeColor(r.color, DEFAULT_SWATCH);
      tr.addEventListener("click", () => openEditor(r));
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.replaceChildren(table);
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
  $("#rl-bans").addEventListener("click", () => open("bans"));
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
      assignResult.textContent = errorText(err);
    }
  });

  $("#rl-delete").addEventListener("click", async () => {
    if (!editingId) return;
    try {
      roles = await invoke("delete_role", { id: editingId });
      closeEditor();
      render();
    } catch (err) {
      assignResult.textContent = errorText(err);
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
      assignResult.textContent = errorText(err);
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
      assignResult.textContent = errorText(err);
    }
  });

  const kickResult = $("#rl-kick-result");
  $("#rl-kick-btn").addEventListener("click", async () => {
    const username = $("#rl-kick-user").value.trim();
    if (!username) return;
    const reason = $("#rl-kick-reason").value.trim();
    const banSecs = adminTools(getState().session).ban ? parseInt($("#rl-kick-ban").value, 10) || 0 : 0;
    // The server acks over the event channel (server_info / server_error);
    // this just reflects that the request was sent.
    try {
      await invoke("disconnect_user", { username, reason, banSecs });
      kickResult.textContent = banSecs
        ? `requested disconnect + ban of ${username}`
        : `requested disconnect of ${username}`;
    } catch (err) {
      kickResult.textContent = errorText(err);
    }
  });

  /** Pre-fill the Disconnect panel from a User List context-menu verb. */
  function openDisconnect(username) {
    $("#rl-kick-user").value = username;
    $("#rl-kick-reason").value = "";
    kickResult.textContent = "";
    $("#rl-kick-user").scrollIntoView({ block: "nearest" });
  }

  // Show each tool only to a session holding its privilege; re-laid out
  // (and the role list re-fetched) when the session arrives or changes.
  let gatedFor; // the privilege bits (or null: no session) last laid out for
  function applyGates() {
    const session = getState().session;
    const key = session ? privilegesOf(session) : null;
    if (key === gatedFor) return;
    const first = gatedFor === undefined;
    gatedFor = key;
    const tools = adminTools(session);
    const shown = [
      ["#rl-accounts", tools.accounts],
      ["#rl-server", tools.server],
      ["#rl-history", tools.history],
      ["#rl-iprules", tools.iprules],
      ["#rl-connections", tools.connections],
      ["#rl-bans", tools.bans],
      ["#rl-filter", tools.roles],
      ["#rl-new", tools.roles],
      ["#rl-refresh", tools.roles],
      ["#rl-roles-panel", tools.roles],
      ["#rl-kick-panel", tools.kick],
      ["#rl-kick-ban-field", tools.ban],
    ];
    for (const [sel, on] of shown) $(sel).classList.toggle("hidden", !on);
    if (!tools.ban) $("#rl-kick-ban").value = "0";
    if (!tools.roles && !editor.classList.contains("hidden")) closeEditor();
    // The window's mount does the first fetch.
    if (!first) refresh();
  }
  applyGates();
  subscribe(applyGates);

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
