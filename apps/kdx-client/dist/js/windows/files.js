import { invoke, pickFile, pickSave } from "../bridge.js";

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
      <span class="spacer"></span>
      <button class="mini" id="f-up">Up</button>
      <button class="mini" id="f-refresh">Refresh</button>
      <button class="mini" id="f-upload">Upload</button>
    </div>
    <div class="win-body" style="flex:1" id="f-list"></div>`;

  const pathEl = body.querySelector("#f-path");
  const listEl = body.querySelector("#f-list");
  let cwd = "/";

  async function refresh() {
    pathEl.textContent = cwd;
    listEl.innerHTML = '<div class="empty">loading…</div>';
    try {
      const res = await invoke("list_files", { path: cwd });
      render(res.entries);
    } catch (err) {
      listEl.innerHTML = `<div class="empty">${err.message || err}</div>`;
    }
  }

  function render(entries) {
    if (!entries.length) {
      listEl.innerHTML = '<div class="empty">empty</div>';
      return;
    }
    const table = document.createElement("table");
    table.className = "files";
    table.innerHTML =
      "<thead><tr><th>Name</th><th style='text-align:right'>Size</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const e of entries) {
      const tr = document.createElement("tr");
      if (e.kind === KIND_DROPBOX) tr.className = "dropbox";
      tr.innerHTML =
        `<td class="fname"><span class="kind">${KINDS[e.kind] || "[?]"}</span>${escapeHtml(e.name)}</td>` +
        `<td class="fsize">${e.kind === KIND_FILE ? fmtSize(e.size) : "—"}</td>`;
      tr.addEventListener("click", () => onEntry(e));
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.innerHTML = "";
    listEl.appendChild(table);
  }

  async function onEntry(e) {
    if (e.kind === KIND_DIR || e.kind === KIND_DROPBOX || e.kind === 3) {
      cwd = joinPath(cwd, e.name);
      refresh();
    } else if (e.kind === KIND_FILE) {
      const dest = await pickSave(e.name);
      if (!dest) return;
      invoke("download", { remotePath: joinPath(cwd, e.name), local: dest }).catch(() => {});
    }
  }

  body.querySelector("#f-up").onclick = () => {
    if (cwd === "/") return;
    cwd = cwd.replace(/\/[^/]+$/, "") || "/";
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
