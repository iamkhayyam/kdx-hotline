// IP Rules — Allow-Deny list checked at connection accept, before TLS.
// SysOp maintains an ordered list of allow/deny CIDR rules; first match
// wins, unmatched peers are allowed (fail-open). Requires SERVER_ADMIN;
// the server enforces it and errors otherwise.

import { invoke } from "../bridge.js";

export function buildIpRules() {
  const body = document.createElement("div");
  body.className = "roles-win";
  body.innerHTML = `
    <div class="ab-toolbar">
      <input class="ab-filter" id="ipr-filter" placeholder="filter…" spellcheck="false" />
      <button class="mini" id="ipr-new">New Rule</button>
      <button class="mini" id="ipr-refresh">Refresh</button>
    </div>
    <div class="win-body" id="ipr-list"></div>
    <form class="ab-editor hidden" id="ipr-editor">
      <div class="ab-grid">
        <label>Action
          <select id="ipr-action">
            <option value="deny">deny</option>
            <option value="allow">allow</option>
          </select>
        </label>
        <label>Position<input id="ipr-position" value="10" inputmode="numeric" /></label>
      </div>
      <label class="srv-full">CIDR<input id="ipr-cidr" placeholder="1.2.3.0/24 or 2001:db8::/32" spellcheck="false" autocomplete="off" /></label>
      <label class="srv-full">Note<input id="ipr-note" placeholder="why this rule exists (optional)" spellcheck="false" autocomplete="off" /></label>
      <div class="ab-actions">
        <button type="submit" class="btn">Save</button>
        <button type="button" class="btn" id="ipr-cancel">Cancel</button>
      </div>
      <div class="rl-assign-result" id="ipr-result"></div>
    </form>
  `;

  const $ = (s) => body.querySelector(s);
  const listEl = $("#ipr-list");
  const filter = $("#ipr-filter");
  const editor = $("#ipr-editor");
  const result = $("#ipr-result");
  let rules = [];

  async function refresh() {
    listEl.innerHTML = '<div class="empty">loading…</div>';
    try {
      rules = await invoke("list_ip_rules");
      render();
    } catch (err) {
      listEl.innerHTML = `<div class="empty">${esc(err.message || String(err))}</div>`;
    }
  }

  function render() {
    const needle = filter.value.trim().toLowerCase();
    const shown = rules.filter(
      (r) =>
        !needle ||
        r.cidr.toLowerCase().includes(needle) ||
        r.note.toLowerCase().includes(needle) ||
        r.action.toLowerCase().includes(needle)
    );
    if (!shown.length) {
      listEl.innerHTML = '<div class="empty">no rules — every peer is allowed (fail-open)</div>';
      return;
    }
    const table = document.createElement("table");
    table.className = "files";
    table.innerHTML =
      "<thead><tr><th>Pos</th><th>Action</th><th>CIDR</th><th>Note</th><th></th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const r of shown) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td class="fsize">${r.position}</td>` +
        `<td class="fsize">${esc(r.action)}</td>` +
        `<td class="fname">${esc(r.cidr)}</td>` +
        `<td class="fmeta">${esc(r.note || "")}</td>` +
        `<td class="fsize"><button class="mini danger" data-id="${esc(r.id)}">delete</button></td>`;
      const btn = tr.querySelector("button");
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        if (!confirm(`Delete this rule?\n${r.action} ${r.cidr}`)) return;
        try {
          rules = await invoke("delete_ip_rule", { id: r.id });
          render();
        } catch (err) {
          alert(err.message || String(err));
        }
      });
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.innerHTML = "";
    listEl.appendChild(table);
  }

  function openEditor() {
    $("#ipr-action").value = "deny";
    $("#ipr-position").value = "10";
    $("#ipr-cidr").value = "";
    $("#ipr-note").value = "";
    result.textContent = "";
    editor.classList.remove("hidden");
    listEl.classList.add("hidden");
  }
  function closeEditor() {
    editor.classList.add("hidden");
    listEl.classList.remove("hidden");
  }

  $("#ipr-new").addEventListener("click", openEditor);
  $("#ipr-cancel").addEventListener("click", closeEditor);
  $("#ipr-refresh").addEventListener("click", refresh);
  filter.addEventListener("input", render);

  editor.addEventListener("submit", async (e) => {
    e.preventDefault();
    const positionRaw = $("#ipr-position").value.trim();
    const position = parseInt(positionRaw, 10);
    if (!Number.isInteger(position)) {
      result.textContent = "position must be a whole number";
      return;
    }
    const action = $("#ipr-action").value;
    const cidr = $("#ipr-cidr").value.trim();
    if (!cidr) {
      result.textContent = "a CIDR is required (e.g. 1.2.3.0/24 or 2001:db8::/32)";
      return;
    }
    const note = $("#ipr-note").value;
    try {
      rules = await invoke("create_ip_rule", { position, action, cidr, note });
      closeEditor();
      render();
    } catch (err) {
      result.textContent = esc(err.message || String(err));
    }
  });

  return { body, refresh };
}

function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}
