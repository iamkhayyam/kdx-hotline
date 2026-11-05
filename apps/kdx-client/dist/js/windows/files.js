import { invoke } from "../bridge.js";
import { showMenu } from "../menu.js";
import { esc, num, plainText, errorText } from "../html.js";
import { askConfirm, confirmThen } from "../confirm.js";

const KINDS = { 0: "[DIR]", 1: "[FILE]", 2: "[DROP]", 3: "[UP]", 4: "[→]" };
const KIND_NAME = { 0: "folder", 1: "file", 2: "drop box", 3: "upload folder", 4: "alias" };
const KIND_DIR = 0, KIND_FILE = 1, KIND_DROPBOX = 2, KIND_ALIAS = 4;
const CLASS_NAME = ["guest", "user", "power user", "admin"];

export function buildFiles() {
  const body = document.createElement("div");
  body.className = "col-fill";
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
        <label class="f-mklbl">Read<select id="f-mk-read">${classOptionsHtml(0)}</select></label>
        <label class="f-mklbl">Write<select id="f-mk-write">${classOptionsHtml(1)}</select></label>
      </div>
      <div class="f-mkrow">
        <label class="f-mklbl wide">Owner (optional, for drop boxes)<input id="f-mk-owner" placeholder="login" spellcheck="false" autocomplete="off" /></label>
        <button type="submit" class="mini">Create</button>
        <button type="button" class="mini" id="f-mk-cancel">Cancel</button>
      </div>
      <div class="f-mk-result" id="f-mk-result"></div>
    </form>
    <div class="f-info hidden" id="f-info"></div>
    <div class="f-xfer hidden" id="f-xfer"><span id="f-xfer-text"></span><button class="mini" id="f-xfer-cancel">Cancel</button></div>
    <div class="f-move-banner hidden" id="f-move-banner"></div>
    <div class="win-body grow" id="f-list"></div>`;

  const pathEl = body.querySelector("#f-path");
  const listEl = body.querySelector("#f-list");
  const filter = body.querySelector("#f-filter");
  const mkform = body.querySelector("#f-mkform");
  const infoEl = body.querySelector("#f-info");
  const searchbar = body.querySelector("#f-searchbar");
  const searchStatus = body.querySelector("#f-search-status");
  const moveBanner = body.querySelector("#f-move-banner");
  const xferEl = body.querySelector("#f-xfer");
  const xferText = body.querySelector("#f-xfer-text");
  const xferCancel = body.querySelector("#f-xfer-cancel");
  let cwd = "/";
  let entries = [];
  let searchHits = null; // non-null while showing search results instead of a folder listing
  // Pending Select-for-Move or Select-for-Alias operation. Both work the same
  // way — select something, navigate elsewhere, "Do Here" — so they share one
  // banner. `op` is "move" or "alias"; `path`/`name` describe the selection.
  let pending = null; // { op: "move" | "alias", path, name } or null

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
      listEl.innerHTML = `<div class="empty">${esc(errorText(err))}</div>`;
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
    table.innerHTML = '<thead><tr><th>Name</th><th class="num">Size</th></tr></thead>';
    const tb = document.createElement("tbody");
    for (const e of shown) {
      const tr = document.createElement("tr");
      if (e.kind === KIND_DROPBOX) tr.className = "dropbox";
      if (e.kind === KIND_ALIAS) tr.className = "alias";
      // For files (and aliases to files) show size; folders (and aliases to
      // folders) show em-dash.
      const showSize = e.kind === KIND_FILE || (e.kind === KIND_ALIAS && e.size > 0);
      tr.innerHTML =
        `<td class="fname"><span class="kind">${esc(KINDS[e.kind] || "[?]")}</span>${esc(plainText(e.name))}</td>` +
        `<td class="fsize">${showSize ? esc(fmtSize(e.size)) : "—"}</td>`;
      tr.addEventListener("click", () => onEntry(e));
      tr.addEventListener("contextmenu", (ev) => {
        ev.preventDefault();
        const items = [];
        if (e.kind === KIND_FILE) items.push({ label: "Download…", fn: () => downloadEntry(e) });
        else items.push({ label: "Open", fn: () => onEntry(e) });
        items.push({ label: "Get Info", fn: () => showInfo(e) });
        items.push({ label: "Copy Name", fn: () => copyText(e.name) });
        items.push({ label: "Select for Move", fn: () => selectForOp(e, "move") });
        // Alias-into is available for any non-alias entry (chains are
        // refused server-side too).
        if (e.kind !== KIND_ALIAS) {
          items.push({ label: "Select for Alias", fn: () => selectForOp(e, "alias") });
        }
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
    table.innerHTML = '<thead><tr><th>Name</th><th>Path</th><th class="num">Size</th></tr></thead>';
    const tb = document.createElement("tbody");
    for (const e of searchHits) {
      const tr = document.createElement("tr");
      if (e.kind === KIND_DROPBOX) tr.className = "dropbox";
      tr.innerHTML =
        `<td class="fname"><span class="kind">${esc(KINDS[e.kind] || "[?]")}</span>${esc(plainText(e.name))}</td>` +
        `<td class="fmeta">${esc(plainText(e.path))}</td>` +
        `<td class="fsize">${e.kind === KIND_FILE ? esc(fmtSize(e.size)) : "—"}</td>`;
      tr.addEventListener("click", () => onSearchHit(e));
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.innerHTML = "";
    listEl.appendChild(table);
  }

  function onSearchHit(e) {
    if (e.kind === KIND_FILE) {
      downloadEntryAt(e.path);
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
    } else if (e.kind === KIND_ALIAS) {
      // Try to list through the alias — if the target is a folder this
      // navigates into it; if the target is a file the server returns a
      // NotAFolder error and we fall through to a download attempt.
      try {
        await invoke("list_files", { path: joinPath(cwd, e.name) });
        cwd = joinPath(cwd, e.name);
        filter.value = "";
        refresh();
      } catch {
        downloadEntry(e);
      }
    }
  }

  async function downloadEntry(e) {
    await downloadEntryAt(joinPath(cwd, e.name));
  }

  // The Save dialog runs on the Rust side: it opens in Downloads with the
  // server's name reduced to a safe basename, and the webview never names a
  // local path. Progress shows in File Transfers.
  async function downloadEntryAt(remotePath) {
    await runTransfer(`↓ ${plainText(remotePath.split("/").pop())}`, () => invoke("download", { remotePath }));
  }

  // One transfer at a time per connection: while one runs (after the
  // native file dialog), the strip offers to cancel it.
  let xferRunning = 0;
  async function runTransfer(label, start) {
    xferRunning++;
    xferText.textContent = `${label} — progress in File Transfers`;
    xferCancel.disabled = false;
    xferEl.classList.remove("hidden");
    try {
      await start();
    } catch (err) {
      showError(err);
    } finally {
      if (--xferRunning === 0) xferEl.classList.add("hidden");
    }
  }
  xferCancel.onclick = async () => {
    xferCancel.disabled = true;
    try {
      await invoke("cancel_transfer");
    } catch (err) {
      showError(err);
      xferCancel.disabled = false;
    }
  };

  /** Show an error in the info strip (as text, never markup). */
  function showError(err) {
    const div = document.createElement("div");
    div.className = "err";
    div.textContent = errorText(err);
    infoEl.replaceChildren(div);
    infoEl.classList.remove("hidden");
  }

  async function showInfo(e) {
    infoEl.innerHTML =
      `<span class="kind">${esc(KINDS[e.kind] || "[?]")}</span> ` +
      `<b>${esc(plainText(e.name))}</b> — ${esc(KIND_NAME[e.kind] || "?")}` +
      (e.kind === KIND_FILE ? ` · ${esc(fmtSize(e.size))}` : "") +
      ` · <span class="f-info-path">${esc(plainText(joinPath(cwd, e.name)))}</span>` +
      ` <button class="mini" id="f-info-close">×</button>`;
    infoEl.classList.remove("hidden");
    infoEl.querySelector("#f-info-close").onclick = () => infoEl.classList.add("hidden");
    // Server-side detail (Get Info): sha256, ACL classes, owner, access item.
    try {
      const info = await invoke("get_file_info", { path: joinPath(cwd, e.name) });
      const cls = ["guest", "user", "power", "admin"];
      const itemTag = { 1: "[UL]", 2: "[DB]" }[info.kind] || (info.name.match(/\[([a-z]+)\]\s*$/i) || [])[1] || "";
      infoEl.innerHTML =
        `<span class="kind">${esc(KINDS[info.kind] || "[?]")}</span> ` +
        `<b>${esc(plainText(info.name))}</b> — ${esc(KIND_NAME[info.kind] || "?")}` +
        (info.kind === 1 ? ` · ${esc(fmtSize(info.size))}` : "") +
        ` <button class="mini" id="f-info-close">×</button>` +
        `<div class="f-info-grid">` +
        `<span>Read</span><span>${esc(cls[info.min_read_class] || info.min_read_class)}</span>` +
        `<span>Write</span><span>${esc(cls[info.min_write_class] || info.min_write_class)}</span>` +
        (itemTag ? `<span>Access</span><span>${esc(itemTag)}</span>` : "") +
        (info.owner ? `<span>Owner</span><span>${esc(info.owner)}</span>` : "") +
        (info.sha256 ? `<span>SHA-256</span><span class="f-info-hash">${esc(info.sha256)}</span>` : "") +
        `</div>`;
      infoEl.querySelector("#f-info-close").onclick = () => infoEl.classList.add("hidden");
    } catch (err) {
      const div = document.createElement("div");
      div.className = "err";
      div.textContent = errorText(err);
      infoEl.appendChild(div);
    }
  }

  async function deleteEntry(e) {
    const kind = KIND_NAME[e.kind] || "item";
    const path = joinPath(cwd, e.name);
    const question =
      `Delete ${kind} “${plainText(e.name)}”${e.kind !== KIND_FILE ? " and everything in it" : ""}?`;
    await confirmThen(
      () => askConfirm(question, { confirmLabel: "Delete", danger: true }),
      async () => {
        try {
          const res = await invoke("delete_path", { path });
          entries = res.entries;
          searchHits = null; // defensive: this response is a folder listing, not search results
          infoEl.classList.add("hidden");
          render();
        } catch (err) {
          showError(err);
        }
      }
    );
  }

  // Select-for-Move / Select-for-Alias → navigate elsewhere → "Do Here" (a
  // two-step operation, since the destination is "wherever the browser is
  // currently looking"). Both verbs share this banner; `pending.op`
  // decides which invoke fires.
  function selectForOp(e, op) {
    pending = { op, path: joinPath(cwd, e.name), name: e.name };
    renderPendingBanner();
  }

  function renderPendingBanner() {
    if (!pending) {
      moveBanner.classList.add("hidden");
      return;
    }
    const verb = pending.op === "alias" ? "Aliasing" : "Moving";
    const doLabel = pending.op === "alias" ? "Alias Here" : "Move Here";
    moveBanner.innerHTML =
      `${esc(verb)} <b>${esc(plainText(pending.name))}</b> — ` +
      `<button class="mini" id="f-op-do">${esc(doLabel)}</button>` +
      `<button class="mini" id="f-op-cancel">Cancel</button>`;
    moveBanner.classList.remove("hidden");
    moveBanner.querySelector("#f-op-do").onclick = async () => {
      try {
        const res =
          pending.op === "alias"
            ? await invoke("alias_path", { sourcePath: pending.path, destPath: cwd })
            : await invoke("move_path", { path: pending.path, destPath: cwd });
        entries = res.entries;
        searchHits = null; // defensive: this response is a folder listing, not search results
        pending = null;
        renderPendingBanner();
        render();
      } catch (err) {
        moveBanner.innerHTML = `<span class="err">${esc(errorText(err))}</span> ` +
          `<button class="mini" id="f-op-cancel">Cancel</button>`;
        moveBanner.querySelector("#f-op-cancel").onclick = () => {
          pending = null;
          renderPendingBanner();
        };
      }
    };
    moveBanner.querySelector("#f-op-cancel").onclick = () => {
      pending = null;
      renderPendingBanner();
    };
  }

  filter.addEventListener("input", render);
  body.querySelector("#f-up").onclick = () => {
    if (cwd === "/") return;
    cwd = cwd.replace(/\/[^/]+$/, "") || "/";
    filter.value = "";
    refresh();
  };
  body.querySelector("#f-refresh").onclick = refresh;
  // The Open dialog runs on the Rust side too.
  body.querySelector("#f-upload").onclick = async () => {
    const remoteDir = cwd;
    await runTransfer(`↑ into ${plainText(remoteDir)}`, () => invoke("upload", { remoteDir }));
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
      searchStatus.textContent = errorText(err);
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
      searchStatus.textContent = errorText(err);
      render();
    }
  });

  // New Folder dialog.
  body.querySelector("#f-newfolder").onclick = () => {
    searchbar.classList.add("hidden");
    mkform.classList.remove("hidden");
    body.querySelector("#f-mk-name").value = "";
    body.querySelector("#f-mk-owner").value = "";
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
        owner: body.querySelector("#f-mk-owner").value.trim() || null,
      });
      entries = res.entries;
      mkform.classList.add("hidden");
      render();
    } catch (err) {
      body.querySelector("#f-mk-result").textContent = errorText(err);
    }
  });

  return { body, refresh };
}

function classOptionsHtml(selected) {
  return CLASS_NAME.map(
    (name, i) => `<option value="${num(i)}"${i === selected ? " selected" : ""}>${esc(name)}</option>`
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
