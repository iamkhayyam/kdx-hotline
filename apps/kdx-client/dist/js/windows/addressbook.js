// Address Book — saved server bookmarks. Non-secret fields persist to
// localStorage; a bookmark's password goes to the OS keychain via the Rust
// side (save_secret) and never comes back to the webview: connecting from a
// bookmark hands the Connect window only the bookmark's id, and Rust reads
// the password itself at login. Mirrors KDX: name, address, login, password,
// comments, plus Connects count and Last Connect.

import { deliver, invoke } from "../bridge.js";
import { esc, num } from "../html.js";

const KEY = "kdx.addressbook";

function load() {
  try {
    const list = JSON.parse(localStorage.getItem(KEY) || "[]");
    return Array.isArray(list) ? list.filter((b) => b && typeof b === "object") : [];
  } catch (_) {
    return [];
  }
}
function save(list) {
  try {
    localStorage.setItem(KEY, JSON.stringify(list));
  } catch (_) {}
}

function newId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** Store a bookmark's password in the keychain; resolves true if saved. */
async function storeSecret(b, password) {
  try {
    return !!(await invoke("save_secret", {
      bookmarkId: b.id,
      host: b.host,
      port: b.port,
      login: b.login || "",
      password,
    }));
  } catch (_) {
    return false;
  }
}

async function forgetSecret(b) {
  if (!b.id) return;
  try {
    await invoke("delete_secret", { bookmarkId: b.id });
  } catch (_) {}
}

/**
 * One-time migration for bookmarks saved by older builds, which kept the
 * password in plaintext localStorage: strip it from storage right away, then
 * (with `toKeychain`, from a window allowed to call save_secret) move it into
 * the OS keychain; without a keychain it is dropped and asked for at
 * connect. Also gives id-less bookmarks an id. Idempotent.
 */
export async function migrateAddressBook({ toKeychain = false } = {}) {
  const list = load();
  const legacy = list.filter((b) => typeof b.password === "string");
  if (!legacy.length && list.every((b) => b.id)) return;
  const secrets = new Map();
  for (const b of list) {
    if (!b.id) b.id = newId();
    if (typeof b.password === "string") {
      if (b.password) secrets.set(b.id, b.password);
      delete b.password;
      b.hasSecret = false;
    }
  }
  save(list); // plaintext gone from storage before any async work
  if (!toKeychain) return;
  let changed = false;
  for (const b of list) {
    const pw = secrets.get(b.id);
    if (pw && (await storeSecret(b, pw))) {
      b.hasSecret = true;
      changed = true;
    }
  }
  if (changed) {
    // Re-read so a concurrent edit isn't clobbered; only flip the flags.
    const fresh = load();
    for (const f of fresh) if (list.some((b) => b.id === f.id && b.hasSecret)) f.hasSecret = true;
    save(fresh);
  }
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
        <label>Password<input id="ab-pass" type="password" autocomplete="new-password" /></label>
        <label class="wide">Comments<input id="ab-comments" spellcheck="false" /></label>
      </div>
      <div class="ab-note" id="ab-note"></div>
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
  const note = $("#ab-note");
  let editIndex = -1;

  function render() {
    const list = load();
    const needle = filter.value.trim().toLowerCase();
    listEl.textContent = "";
    const shown = list.filter(
      (b) => !needle || (String(b.name || "") + String(b.host || "") + String(b.comments || "")).toLowerCase().includes(needle)
    );
    if (!shown.length) {
      listEl.innerHTML = '<div class="empty">no bookmarks — Add one</div>';
      return;
    }
    const table = document.createElement("table");
    table.className = "files";
    table.innerHTML =
      '<thead><tr><th>Name</th><th>Address</th><th class="num">Connects</th><th>Last</th></tr></thead>';
    const tb = document.createElement("tbody");
    for (const b of shown) {
      const idx = list.indexOf(b);
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td class="fname">${esc(b.name || b.host)}</td>` +
        `<td>${esc(b.host)}:${num(b.port)}</td>` +
        `<td class="fsize">${num(b.connects || 0)}</td>` +
        `<td class="fmeta">${esc(b.lastConnect ? new Date(b.lastConnect).toLocaleDateString() : "—")}</td>`;
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

  function connect(idx) {
    const list = load();
    const b = list[idx];
    if (!b) return;
    b.connects = (b.connects || 0) + 1;
    b.lastConnect = Date.now();
    save(list);
    render();
    // Only the id travels: Rust reads the password from the keychain.
    deliver("connect", "fill", {
      host: b.host,
      port: b.port,
      login: b.login,
      bookmarkId: b.id,
      hasSecret: !!b.hasSecret,
    });
    deliver("connect", "submit");
  }

  function openEditor(idx) {
    editIndex = idx;
    const b = idx >= 0 ? load()[idx] || {} : {};
    $("#ab-name").value = b.name || "";
    $("#ab-host").value = b.host || "127.0.0.1";
    $("#ab-port").value = b.port || 10700;
    $("#ab-login").value = b.login || "";
    $("#ab-pass").value = "";
    $("#ab-pass").placeholder = b.hasSecret ? "saved in keychain — type to change" : "";
    $("#ab-comments").value = b.comments || "";
    note.textContent = "";
    editor.classList.remove("hidden");
    listEl.classList.add("hidden");
  }
  function closeEditor() {
    editor.classList.add("hidden");
    listEl.classList.remove("hidden");
  }

  function rowMenu(x, y, idx) {
    const b = load()[idx];
    if (!b) return;
    import("../menu.js").then(({ showMenu }) => {
      const items = [
        { label: "Connect", fn: () => connect(idx) },
        { label: "Edit", fn: () => openEditor(idx) },
      ];
      if (b.hasSecret) {
        items.push({
          label: "Forget Password",
          fn: async () => {
            await forgetSecret(b);
            const l = load();
            const e = l.find((x) => x.id === b.id);
            if (e) e.hasSecret = false;
            save(l);
            render();
          },
        });
      }
      items.push({ separator: true });
      items.push({
        label: "Remove",
        fn: async () => {
          const l = load().filter((x) => x.id !== b.id);
          save(l);
          render();
          await forgetSecret(b);
        },
      });
      showMenu(x, y, items);
    });
  }

  $("#ab-add").addEventListener("click", () => openEditor(-1));
  $("#ab-cancel").addEventListener("click", closeEditor);
  filter.addEventListener("input", render);
  editor.addEventListener("submit", async (e) => {
    e.preventDefault();
    const list = load();
    const prev = editIndex >= 0 ? list[editIndex] : null;
    const entry = {
      id: (prev && prev.id) || newId(),
      name: $("#ab-name").value.trim(),
      host: $("#ab-host").value.trim(),
      port: parseInt($("#ab-port").value, 10) || 10700,
      login: $("#ab-login").value.trim(),
      comments: $("#ab-comments").value.trim(),
      hasSecret: !!(prev && prev.hasSecret),
    };
    if (prev) {
      entry.connects = prev.connects;
      entry.lastConnect = prev.lastConnect;
    }
    const password = $("#ab-pass").value;
    $("#ab-pass").value = "";
    // A saved password is bound to its server + login; re-save it (or drop
    // it) when either changes.
    const rebound = prev && (prev.host !== entry.host || prev.port !== entry.port || (prev.login || "") !== entry.login);
    if (password) {
      entry.hasSecret = await storeSecret(entry, password);
    } else if (rebound && entry.hasSecret) {
      await forgetSecret(entry);
      entry.hasSecret = false;
    }
    if (editIndex >= 0 && list[editIndex]) list[editIndex] = entry;
    else list.push(entry);
    save(list);
    render();
    if (password && !entry.hasSecret) {
      // Stay open so the user sees why: no keychain, nothing stored.
      note.textContent = "No system keychain available — the password was not saved; you'll be asked for it when connecting.";
      editIndex = list.indexOf(entry);
      return;
    }
    if (rebound && !password && prev.hasSecret) {
      note.textContent = "Server or login changed — the saved password was forgotten.";
      editIndex = list.indexOf(entry);
      return;
    }
    closeEditor();
  });

  // Older builds' plaintext passwords: move them into the keychain.
  migrateAddressBook({ toKeychain: true }).then(render, render);
  render();
  return { body, render };
}
