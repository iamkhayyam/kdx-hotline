// Accounts — SysOp account management (Administration). List accounts, create
// new ones, edit an account's class + per-privilege overrides, and reset
// another account's password. Viewing and mutating both require USER_ADMIN;
// the server enforces it (and who may manage whom) and errors otherwise.
// Overrides are tri-state per privilege: Inherit (follow the class), Grant
// (force on), or Revoke (force off) — mapped onto the granted/revoked
// bitmasks the account row carries. Passwords typed here never reach the
// server: client-core derives the stored credential from them locally.

import { invoke } from "../bridge.js";
import { esc, num, errorText } from "../html.js";
import { askConfirm, confirmThen } from "../confirm.js";
import { newPasswordProblem } from "../passwords.js";

const CLASS_NAME = ["guest", "user", "power user", "admin"];

const PRIVILEGES = [
  { bit: 1 << 0, label: "Chat: send" },
  { bit: 1 << 1, label: "Chat: private message" },
  { bit: 1 << 2, label: "Chat: create room" },
  { bit: 1 << 3, label: "Chat: set topic" },
  { bit: 1 << 4, label: "Files: list" },
  { bit: 1 << 5, label: "Files: download" },
  { bit: 1 << 6, label: "Files: upload" },
  { bit: 1 << 7, label: "Files: delete" },
  { bit: 1 << 8, label: "Files: manage tree" },
  { bit: 1 << 16, label: "Users: kick" },
  { bit: 1 << 17, label: "Users: ban" },
  { bit: 1 << 18, label: "Users: manage accounts/roles" },
  { bit: 1 << 19, label: "Server: config/shutdown" },
];

export function buildAccounts() {
  const body = document.createElement("div");
  body.className = "roles-win";
  body.innerHTML = `
    <div class="ab-toolbar">
      <input class="ab-filter" id="ac-filter" placeholder="filter…" spellcheck="false" />
      <button class="mini" id="ac-new">New Account</button>
      <button class="mini" id="ac-refresh">Refresh</button>
    </div>
    <div class="win-body" id="ac-list"></div>
    <form class="ab-editor hidden" id="ac-editor">
      <div class="ab-grid">
        <label>Login<input id="ac-username" spellcheck="false" autocomplete="off" /></label>
        <label id="ac-pass-field">Password<input id="ac-password" type="password" autocomplete="new-password" /></label>
        <label id="ac-pass2-field">Confirm password<input id="ac-password2" type="password" autocomplete="new-password" /></label>
        <label>Class
          <select id="ac-class">
            <option value="0">guest</option>
            <option value="1" selected>user</option>
            <option value="2">power user</option>
            <option value="3">admin</option>
          </select>
        </label>
      </div>
      <div class="ac-overrides" id="ac-overrides"></div>
      <div class="ab-actions">
        <button type="submit" class="btn">Save</button>
        <button type="button" class="btn" id="ac-cancel">Cancel</button>
        <button type="button" class="btn" id="ac-setpw-open">Set Password…</button>
      </div>
      <div class="ac-setpw hidden" id="ac-setpw">
        <div class="ab-grid">
          <label>New password<input id="ac-newpw" type="password" autocomplete="new-password" /></label>
          <label>Confirm new password<input id="ac-newpw2" type="password" autocomplete="new-password" /></label>
        </div>
        <div class="ab-actions">
          <button type="button" class="btn danger" id="ac-setpw-go">Set Password</button>
          <button type="button" class="btn" id="ac-setpw-cancel">Cancel</button>
        </div>
      </div>
      <div class="rl-assign-result" id="ac-result"></div>
    </form>
  `;

  const $ = (s) => body.querySelector(s);
  const listEl = $("#ac-list");
  const filter = $("#ac-filter");
  const editor = $("#ac-editor");
  const overridesEl = $("#ac-overrides");
  const result = $("#ac-result");
  let accounts = [];
  let editingUser = null; // null = creating

  overridesEl.innerHTML = PRIVILEGES.map(
    (p) =>
      `<label class="ac-override"><span>${esc(p.label)}</span>` +
      `<select data-bit="${num(p.bit)}">` +
      `<option value="inherit">Inherit</option>` +
      `<option value="grant">Grant</option>` +
      `<option value="revoke">Revoke</option>` +
      `</select></label>`
  ).join("");

  async function refresh() {
    listEl.innerHTML = '<div class="empty">loading…</div>';
    try {
      accounts = await invoke("list_accounts");
      render();
    } catch (err) {
      listEl.innerHTML = `<div class="empty">${esc(errorText(err))}</div>`;
    }
  }

  function render() {
    const needle = filter.value.trim().toLowerCase();
    const shown = accounts.filter((a) => !needle || a.username.toLowerCase().includes(needle));
    if (!shown.length) {
      listEl.innerHTML = '<div class="empty">no accounts — New Account to add one</div>';
      return;
    }
    const table = document.createElement("table");
    table.className = "files";
    table.innerHTML =
      "<thead><tr><th></th><th>Login</th><th>Class</th><th>Overrides</th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const a of shown) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td><span class="classbar" data-class="${num(a.base_class)}"></span></td>` +
        `<td class="fname">${esc(a.username)}</td>` +
        `<td class="fsize">${esc(CLASS_NAME[a.base_class] || "?")}</td>` +
        `<td class="fmeta">${esc(overrideSummary(a))}</td>`;
      tr.addEventListener("click", () => openEditor(a));
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.innerHTML = "";
    listEl.appendChild(table);
  }

  function overrideSummary(a) {
    const g = countBits(a.granted);
    const r = countBits(a.revoked);
    if (!g && !r) return "—";
    const parts = [];
    if (g) parts.push(`+${g}`);
    if (r) parts.push(`−${r}`);
    return parts.join(" ");
  }

  function openEditor(account) {
    editingUser = account ? account.username : null;
    $("#ac-username").value = account ? account.username : "";
    $("#ac-username").disabled = !!account;
    $("#ac-password").value = "";
    $("#ac-password2").value = "";
    // The initial password applies only when creating; an existing
    // account's password is reset separately (Set Password…).
    $("#ac-pass-field").classList.toggle("hidden", !!account);
    $("#ac-pass2-field").classList.toggle("hidden", !!account);
    $("#ac-setpw-open").classList.toggle("hidden", !account);
    closeSetPassword();
    $("#ac-class").value = String(account ? account.base_class : 1);
    for (const sel of overridesEl.querySelectorAll("select")) {
      const bit = Number(sel.dataset.bit);
      if (account && (account.granted & bit) !== 0) sel.value = "grant";
      else if (account && (account.revoked & bit) !== 0) sel.value = "revoke";
      else sel.value = "inherit";
    }
    result.textContent = "";
    editor.classList.remove("hidden");
    listEl.classList.add("hidden");
  }

  function closeEditor() {
    closeSetPassword();
    $("#ac-password").value = "";
    $("#ac-password2").value = "";
    editor.classList.add("hidden");
    listEl.classList.remove("hidden");
    editingUser = null;
  }

  // ---- Set Password… (an administrator's reset of another account) ----
  function closeSetPassword() {
    $("#ac-newpw").value = "";
    $("#ac-newpw2").value = "";
    $("#ac-setpw").classList.add("hidden");
  }

  async function setPassword() {
    const username = editingUser;
    if (!username) return;
    const password = $("#ac-newpw").value;
    const problem = newPasswordProblem(password, $("#ac-newpw2").value);
    if (problem) {
      result.textContent = problem;
      return;
    }
    result.textContent = "";
    try {
      const done = await confirmThen(
        () =>
          askConfirm(
            `Set a new password for ${username}?\nTheir current password stops working, and every session they have open is signed out.`,
            { confirmLabel: "Set Password", danger: true }
          ),
        async () => {
          accounts = await invoke("set_account_password", { username, newPassword: password });
        }
      );
      if (done) {
        closeSetPassword();
        render();
        result.textContent = `password set for ${username} — tell them the new one out-of-band`;
      }
    } catch (err) {
      result.textContent = errorText(err);
    }
  }

  $("#ac-setpw-open").addEventListener("click", () => {
    result.textContent = "";
    $("#ac-setpw").classList.remove("hidden");
    $("#ac-newpw").focus();
  });
  $("#ac-setpw-cancel").addEventListener("click", closeSetPassword);
  $("#ac-setpw-go").addEventListener("click", setPassword);
  // Enter in these fields sets the password; it must not submit (Save) the
  // class/override editor around them.
  for (const id of ["#ac-newpw", "#ac-newpw2"]) {
    $(id).addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        setPassword();
      }
    });
  }

  function collectOverrides() {
    let granted = 0;
    let revoked = 0;
    for (const sel of overridesEl.querySelectorAll("select")) {
      const bit = Number(sel.dataset.bit);
      if (sel.value === "grant") granted |= bit;
      else if (sel.value === "revoke") revoked |= bit;
    }
    return { granted: granted >>> 0, revoked: revoked >>> 0 };
  }

  $("#ac-new").addEventListener("click", () => openEditor(null));
  $("#ac-cancel").addEventListener("click", closeEditor);
  $("#ac-refresh").addEventListener("click", refresh);
  filter.addEventListener("input", render);

  editor.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = $("#ac-username").value.trim();
    if (!username) return;
    const baseClass = parseInt($("#ac-class").value, 10) || 0;
    const { granted, revoked } = collectOverrides();
    try {
      if (editingUser) {
        accounts = await invoke("update_account", { username, baseClass, granted, revoked });
      } else {
        const password = $("#ac-password").value;
        const problem = newPasswordProblem(password, $("#ac-password2").value);
        if (problem) {
          result.textContent = problem;
          return;
        }
        accounts = await invoke("create_account", { username, password, baseClass, granted, revoked });
      }
      closeEditor();
      render();
    } catch (err) {
      result.textContent = errorText(err);
    }
  });

  return { body, refresh };
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
