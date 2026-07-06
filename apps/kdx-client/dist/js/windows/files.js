import { invoke, pickFile, pickSave } from "../bridge.js";
import { showMenu } from "../menu.js";

const KINDS = { 0: "[DIR]", 1: "[FILE]", 2: "[DROP]", 3: "[UP]" };
const KIND_DIR = 0, KIND_FILE = 1, KIND_DROPBOX = 2;

export function buildFiles() {
  const body = document.createElement("div");
  body.style.flex = "1";
  body.style.display = "flex";
  body.style.flexDirection = "column";
  body.style.minHeight = "0";
  body.innerHTML = `
    <div class="pathbar">
      <span class="path" id="f-path">/</span>
      <input class="ab-filter" id="f-filter" placeholder="filter…" spellcheck="false" />
      <button class="mini" id="f-up">Up</button>
      <button class="mini" id="f-refresh">Refresh</button>
      <button class="mini" id="f-upload">Upload</button>
    </div>
    <div class="win-body" style="flex:1" id="f-list"></div>`;

  const pathEl = body.querySelector("#f-path");
  const listEl = body.querySelector("#f-list");
  const filter = body.querySelector("#f-filter");
  let cwd = "/";
  let entries = [];

  async function refresh() {
    pathEl.textContent = cwd;
    listEl.innerHTML = '<div class="empty">loading…</div>';
    try {
      const res = await invoke("list_files", { path: cwd });
      entries = res.entries;
      render();
    } catch (err) {
      listEl.innerHTML = `<div class="empty">${escapeHtml(err.message || String(err))}</div>`;
    }
  }

  function render() {
    const needle = filter.value.trim().toLowerCase();
    const shown = entries.filter((e) => !needle || e.name.toLowerCase().includes(needle));
    if (!shown.length) {
      listEl.innerHTML = `<div class="empty">${entries.length ? "no matches" : "empty"}</div>`;
      return;
    }
    const table = document.createElement("table");
    table.className = "files";
    table.innerHTML =
      "<thead><tr><th>Name</th><th style='text-align:right'>Size</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const e of shown) {
      const tr = document.createElement("tr");
      if (e.kind === KIND_DROPBOX) tr.className = "dropbox";
      tr.innerHTML =
        `<td class="fname"><span class="kind">${KINDS[e.kind] || "[?]"}</span>${escapeHtml(e.name)}</td>` +
        `<td class="fsize">${e.kind === KIND_FILE ? fmtSize(e.size) : "—"}</td>`;
      tr.addEventListener("click", () => onEntry(e));
      tr.addEventListener("contextmenu", (ev) => {
        ev.preventDefault();
        const items = [];
        if (e.kind === KIND_FILE) items.push({ label: "Download…", fn: () => downloadEntry(e) });
        else items.push({ label: "Open", fn: () => onEntry(e) });
        items.push({ label: "Copy Name", fn: () => copyText(e.name) });
        items.push({ label: "Refresh", fn: refresh });
        showMenu(ev.clientX, ev.clientY, items);
      });
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.innerHTML = "";
    listEl.appendChild(table);
  }

  async function onEntry(e) {
    if (e.kind === KIND_DIR || e.kind === KIND_DROPBOX || e.kind === 3) {
      cwd = joinPath(cwd, e.name);
      filter.value = "";
      refresh();
    } else if (e.kind === KIND_FILE) {
      downloadEntry(e);
    }
  }

  async function downloadEntry(e) {
    const dest = await pickSave(e.name);
    if (!dest) return;
    invoke("download", { remotePath: joinPath(cwd, e.name), local: dest }).catch(() => {});
  }

  filter.addEventListener("input", render);
  body.querySelector("#f-up").onclick = () => {
    if (cwd === "/") return;
    cwd = cwd.replace(/\/[^/]+$/, "") || "/";
    filter.value = "";
    refresh();
  };
  body.querySelector("#f-refresh").onclick = refresh;
  body.querySelector("#f-upload").onclick = async () => {
    const path = await pickFile();
    if (!path) return;
    invoke("upload", { local: path, remoteDir: cwd }).catch(() => {});
  };

  return { body, refresh };
}

function copyText(text) {
  if (navigator.clipboard) navigator.clipboard.writeText(text).catch(() => {});
}

function joinPath(base, name) {
  return (base === "/" ? "" : base) + "/" + name;
}
function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}
function escapeHtml(s) {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}
