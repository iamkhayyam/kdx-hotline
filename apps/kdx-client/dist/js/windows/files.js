import { invoke, pickFile, pickSave } from "../bridge.js";
import { showMenu } from "../menu.js";

const KINDS = { 0: "[DIR]", 1: "[FILE]", 2: "[DROP]", 3: "[UP]" };
const KIND_NAME = { 0: "folder", 1: "file", 2: "drop box", 3: "upload folder" };
const KIND_DIR = 0, KIND_FILE = 1, KIND_DROPBOX = 2;
const CLASS_NAME = ["guest", "user", "power user", "admin"];

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
      <button class="mini" id="f-newfolder">New Folder</button>
      <button class="mini" id="f-search-toggle">Search</button>
      <button class="mini" id="f-refresh">Refresh</button>
      <button class="mini" id="f-upload">Upload</button>
    </div>
    <form class="f-searchbar hidden" id="f-searchbar">
      <input id="f-search-query" placeholder="search the catalog…" spellcheck="false" autocomplete="off" />
      <button type="submit" class="mini">Search</button>
      <button type="button" class="mini" id="f-gen-catalog">Generate Catalog</button>
      <button type="button" class="mini" id="f-search-close">×</button>
    </form>
    <div class="f-search-status" id="f-search-status"></div>
    <form class="f-mkform hidden" id="f-mkform">
      <div class="f-mkrow">
        <input id="f-mk-name" placeholder="folder name" spellcheck="false" autocomplete="off" />
        <select id="f-mk-kind">
          <option value="0">Folder</option>
          <option value="3">Upload folder</option>
          <option value="2">Drop Box</option>
        </select>
      </div>
      <div class="f-mkrow">
        <label class="f-mklbl">Read<select id="f-mk-read">${classOptions(0)}</select></label>
        <label class="f-mklbl">Write<select id="f-mk-write">${classOptions(1)}</select></label>
        <button type="submit" class="mini">Create</button>
        <button type="button" class="mini" id="f-mk-cancel">Cancel</button>
      </div>
      <div class="f-mk-result" id="f-mk-result"></div>
    </form>
    <div class="f-info hidden" id="f-info"></div>
    <div class="win-body" style="flex:1" id="f-list"></div>`;

  const pathEl = body.querySelector("#f-path");
  const listEl = body.querySelector("#f-list");
  const filter = body.querySelector("#f-filter");
  const mkform = body.querySelector("#f-mkform");
  const infoEl = body.querySelector("#f-info");
  const searchbar = body.querySelector("#f-searchbar");
  const searchStatus = body.querySelector("#f-search-status");
  let cwd = "/";
  let entries = [];
  let searchHits = null; // non-null while showing search results instead of a folder listing

  async function refresh() {
    // Navigating/refreshing a folder always leaves search-results mode.
    searchHits = null;
    searchbar.classList.add("hidden");
    searchStatus.textContent = "";
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
    if (searchHits) renderSearchResults();
    else renderBrowse();
  }

  function renderBrowse() {
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
        items.push({ label: "Get Info", fn: () => showInfo(e) });
        items.push({ label: "Copy Name", fn: () => copyText(e.name) });
        items.push({ label: "Delete", fn: () => deleteEntry(e) });
        items.push({ label: "Refresh", fn: refresh });
        showMenu(ev.clientX, ev.clientY, items);
      });
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.innerHTML = "";
    listEl.appendChild(table);
  }

  // Catalog search results carry a full path (they can span any folder), so
  // clicking one jumps the browser there instead of joining onto `cwd`.
  function renderSearchResults() {
    if (!searchHits.length) {
      listEl.innerHTML = '<div class="empty">no matches in the catalog</div>';
      return;
    }
    const table = document.createElement("table");
    table.className = "files";
    table.innerHTML =
      "<thead><tr><th>Name</th><th>Path</th><th style='text-align:right'>Size</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const e of searchHits) {
      const tr = document.createElement("tr");
      if (e.kind === KIND_DROPBOX) tr.className = "dropbox";
      tr.innerHTML =
        `<td class="fname"><span class="kind">${KINDS[e.kind] || "[?]"}</span>${escapeHtml(e.name)}</td>` +
        `<td class="fmeta">${escapeHtml(e.path)}</td>` +
        `<td class="fsize">${e.kind === KIND_FILE ? fmtSize(e.size) : "—"}</td>`;
      tr.addEventListener("click", () => onSearchHit(e));
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.innerHTML = "";
    listEl.appendChild(table);
  }

  function onSearchHit(e) {
    if (e.kind === KIND_FILE) {
      downloadEntryAt(e.path, e.name);
      return;
    }
    exitSearch();
    cwd = e.path;
    refresh();
  }

  function exitSearch() {
    searchHits = null;
    searchStatus.textContent = "";
    searchbar.classList.add("hidden");
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
    await downloadEntryAt(joinPath(cwd, e.name), e.name);
  }

  async function downloadEntryAt(remotePath, name) {
    const dest = await pickSave(name);
    if (!dest) return;
    invoke("download", { remotePath, local: dest }).catch(() => {});
  }

  function showInfo(e) {
    infoEl.innerHTML =
      `<span class="kind">${KINDS[e.kind] || "[?]"}</span> ` +
      `<b>${escapeHtml(e.name)}</b> — ${KIND_NAME[e.kind] || "?"}` +
      (e.kind === KIND_FILE ? ` · ${fmtSize(e.size)}` : "") +
      ` · <span class="f-info-path">${escapeHtml(joinPath(cwd, e.name))}</span>` +
      ` <button class="mini" id="f-info-close">×</button>`;
    infoEl.classList.remove("hidden");
    infoEl.querySelector("#f-info-close").onclick = () => infoEl.classList.add("hidden");
  }

  async function deleteEntry(e) {
    const kind = KIND_NAME[e.kind] || "item";
    if (!confirm(`Delete ${kind} “${e.name}”${e.kind !== KIND_FILE ? " and everything in it" : ""}?`)) {
      return;
    }
    try {
      const res = await invoke("delete_path", { path: joinPath(cwd, e.name) });
      entries = res.entries;
      infoEl.classList.add("hidden");
      render();
    } catch (err) {
      infoEl.innerHTML = `<span class="err">${escapeHtml(err.message || String(err))}</span>`;
      infoEl.classList.remove("hidden");
    }
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

  // Search — a catalog-wide lookup, distinct from the type-to-filter box
  // (which only narrows the current folder's listing).
  body.querySelector("#f-search-toggle").onclick = () => {
    mkform.classList.add("hidden");
    searchbar.classList.remove("hidden");
    const q = body.querySelector("#f-search-query");
    q.value = "";
    searchStatus.textContent = "";
    q.focus();
  };
  body.querySelector("#f-search-close").onclick = () => {
    exitSearch();
    render();
  };
  body.querySelector("#f-gen-catalog").onclick = async () => {
    searchStatus.textContent = "generating catalog…";
    try {
      const count = await invoke("generate_catalog");
      searchStatus.textContent = `catalog ready — ${count} entries indexed`;
    } catch (err) {
      searchStatus.textContent = escapeHtml(err.message || String(err));
    }
  };
  searchbar.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const query = body.querySelector("#f-search-query").value.trim();
    searchStatus.textContent = "searching…";
    try {
      searchHits = await invoke("search_files", { query });
      searchStatus.textContent = `${searchHits.length} match${searchHits.length === 1 ? "" : "es"}`;
      render();
    } catch (err) {
      searchHits = [];
      searchStatus.textContent = escapeHtml(err.message || String(err));
      render();
    }
  });

  // New Folder dialog.
  body.querySelector("#f-newfolder").onclick = () => {
    searchbar.classList.add("hidden");
    mkform.classList.remove("hidden");
    body.querySelector("#f-mk-name").value = "";
    body.querySelector("#f-mk-result").textContent = "";
    body.querySelector("#f-mk-name").focus();
  };
  body.querySelector("#f-mk-cancel").onclick = () => mkform.classList.add("hidden");
  mkform.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const name = body.querySelector("#f-mk-name").value.trim();
    if (!name) return;
    try {
      const res = await invoke("create_folder", {
        path: cwd,
        name,
        kind: parseInt(body.querySelector("#f-mk-kind").value, 10) || 0,
        minReadClass: parseInt(body.querySelector("#f-mk-read").value, 10) || 0,
        minWriteClass: parseInt(body.querySelector("#f-mk-write").value, 10) || 0,
      });
      entries = res.entries;
      mkform.classList.add("hidden");
      render();
    } catch (err) {
      body.querySelector("#f-mk-result").textContent = escapeHtml(err.message || String(err));
    }
  });

  return { body, refresh };
}

function classOptions(selected) {
  return CLASS_NAME.map(
    (name, i) => `<option value="${i}"${i === selected ? " selected" : ""}>${name}</option>`
  ).join("");
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
