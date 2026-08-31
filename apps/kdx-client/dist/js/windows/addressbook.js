// Address Book — saved server bookmarks. Persists to localStorage; a click
// fills the Connect window and connects. Mirrors KDX: name, address, login,
// password, comments, plus Connects count and Last Connect.

import { emitUi } from "../bridge.js";
import { open } from "../wm.js";

const KEY = "kdx.addressbook";

function load() {
  try {
    return JSON.parse(localStorage.getItem(KEY) || "[]");
  } catch (_) {
    return [];
  }
}
function save(list) {
  try {
    localStorage.setItem(KEY, JSON.stringify(list));
  } catch (_) {}
}

/** Cross-window: fill + submit live in the Connect window via kdx-ui. */
export function buildAddressBook() {
  const body = document.createElement("div");
  body.className = "addressbook";
  body.innerHTML = `
    <div class="ab-toolbar">
      <input class="ab-filter" id="ab-filter" placeholder="filter…" spellcheck="false" />
      <button class="mini" id="ab-add">Add</button>
    </div>
    <div class="ab-list" id="ab-list"></div>
    <form class="ab-editor hidden" id="ab-editor">
      <div class="ab-grid">
        <label>Name<input id="ab-name" spellcheck="false" /></label>
        <label>Address<input id="ab-host" value="127.0.0.1" spellcheck="false" /></label>
        <label>Port<input id="ab-port" value="10700" /></label>
        <label>Login<input id="ab-login" spellcheck="false" /></label>
        <label>Password<input id="ab-pass" type="password" /></label>
        <label class="wide">Comments<input id="ab-comments" spellcheck="false" /></label>
      </div>
      <div class="ab-actions">
        <button type="submit" class="btn">Save</button>
        <button type="button" class="btn" id="ab-cancel">Cancel</button>
      </div>
    </form>
  `;

  const $ = (s) => body.querySelector(s);
  const listEl = $("#ab-list");
  const editor = $("#ab-editor");
  const filter = $("#ab-filter");
  let editIndex = -1;

  function render() {
    const list = load();
    const needle = filter.value.trim().toLowerCase();
    listEl.innerHTML = "";
    const shown = list.filter(
      (b) => !needle || (b.name + b.host + (b.comments || "")).toLowerCase().includes(needle)
    );
    if (!shown.length) {
      listEl.innerHTML = '<div class="empty">no bookmarks — Add one</div>';
      return;
    }
    const table = document.createElement("table");
    table.className = "files";
    table.innerHTML =
      "<thead><tr><th>Name</th><th>Address</th><th style='text-align:right'>Connects</th><th>Last</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const b of shown) {
      const idx = list.indexOf(b);
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td class="fname">${esc(b.name || b.host)}</td>` +
        `<td>${esc(b.host)}:${b.port}</td>` +
        `<td class="fsize">${b.connects || 0}</td>` +
        `<td class="fmeta">${b.lastConnect ? new Date(b.lastConnect).toLocaleDateString() : "—"}</td>`;
      tr.addEventListener("click", () => connect(idx));
      tr.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        rowMenu(e.clientX, e.clientY, idx);
      });
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.appendChild(table);
  }

  async function connect(idx) {
    const list = load();
    const b = list[idx];
    if (!b) return;
    b.connects = (b.connects || 0) + 1;
    b.lastConnect = Date.now();
    save(list);
    render();
    open("connect");
    emitUi("connect", "fill", { host: b.host, port: b.port, login: b.login, password: b.password });
    emitUi("connect", "submit");
  }

  function openEditor(idx) {
    editIndex = idx;
    const b = idx >= 0 ? load()[idx] : {};
    $("#ab-name").value = b.name || "";
    $("#ab-host").value = b.host || "127.0.0.1";
    $("#ab-port").value = b.port || 10700;
    $("#ab-login").value = b.login || "";
    $("#ab-pass").value = b.password || "";
    $("#ab-comments").value = b.comments || "";
    editor.classList.remove("hidden");
    listEl.classList.add("hidden");
  }
  function closeEditor() {
    editor.classList.add("hidden");
    listEl.classList.remove("hidden");
  }

  function rowMenu(x, y, idx) {
    import("../menu.js").then(({ showMenu }) => {
      showMenu(x, y, [
        { label: "Connect", fn: () => connect(idx) },
        { label: "Edit", fn: () => openEditor(idx) },
        { separator: true },
        { label: "Remove", fn: () => { const l = load(); l.splice(idx, 1); save(l); render(); } },
      ]);
    });
  }

  $("#ab-add").addEventListener("click", () => openEditor(-1));
  $("#ab-cancel").addEventListener("click", closeEditor);
  filter.addEventListener("input", render);
  editor.addEventListener("submit", (e) => {
    e.preventDefault();
    const list = load();
    const entry = {
      name: $("#ab-name").value.trim(),
      host: $("#ab-host").value.trim(),
      port: parseInt($("#ab-port").value, 10) || 10700,
      login: $("#ab-login").value.trim(),
      password: $("#ab-pass").value,
      comments: $("#ab-comments").value.trim(),
    };
    if (editIndex >= 0) {
      entry.connects = list[editIndex].connects;
      entry.lastConnect = list[editIndex].lastConnect;
      list[editIndex] = entry;
    } else {
      list.push(entry);
    }
    save(list);
    closeEditor();
    render();
  });

  render();
  return { body, render };
}

function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}
