// Bans — the account bans in force (set from the Disconnect User panel),
// longest-lasting first, with Unban. Listing and lifting need USER_BAN; a
// ban set by a higher class can only be lifted by that class or above (or
// by whoever set it, or an Admin). The server enforces all of it — the
// Unban buttons are just dimmed where it would refuse.

import { invoke } from "../bridge.js";
import { getState } from "../store.js";
import { esc, errorText } from "../html.js";
import { askConfirm, confirmThen } from "../confirm.js";
import { canLiftBan, banRemaining, filterBans, truncationNote } from "../moderation.js";

const CLASS_NAME = ["guest", "user", "power user", "admin"];

export function buildBans() {
  const body = document.createElement("div");
  body.className = "roles-win";
  body.innerHTML = `
    <div class="ab-toolbar">
      <input class="ab-filter" id="ban-filter" placeholder="filter…" spellcheck="false" />
      <button class="mini" id="ban-refresh">Refresh</button>
    </div>
    <div class="rl-assign-result ipr-status" id="ban-status"></div>
    <div class="win-body" id="ban-list"></div>
    <div class="rl-assign-result ban-note" id="ban-note"></div>
    <form class="rl-assign" id="ban-byname">
      <div class="rl-assign-head">Unban by name</div>
      <div class="rl-assign-row">
        <input id="ban-user" placeholder="username" spellcheck="false" autocomplete="off" />
        <button type="submit" class="mini danger">Unban</button>
      </div>
    </form>
  `;

  const $ = (s) => body.querySelector(s);
  const listEl = $("#ban-list");
  const filter = $("#ban-filter");
  const status = $("#ban-status");
  const note = $("#ban-note");
  let list = { total: 0, bans: [] };
  let loaded = false; // a listing has arrived (an error must stay on screen)

  async function refresh() {
    status.textContent = "";
    listEl.innerHTML = '<div class="empty">loading…</div>';
    try {
      list = await invoke("list_bans");
      loaded = true;
      render();
    } catch (err) {
      loaded = false;
      // Server error text: shown as text, never parsed as markup.
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = errorText(err);
      listEl.replaceChildren(empty);
      note.textContent = "";
    }
  }

  function render() {
    note.textContent = truncationNote(list);
    const shown = filterBans(list.bans, filter.value);
    if (!shown.length) {
      listEl.innerHTML = list.bans.length
        ? '<div class="empty">no bans match the filter</div>'
        : '<div class="empty">no bans in force</div>';
      return;
    }
    const session = getState().session;
    const now = Date.now() / 1000;
    const table = document.createElement("table");
    table.className = "files";
    table.innerHTML =
      "<thead><tr><th>User</th><th>Expires</th><th>Reason</th><th>Banned by</th><th></th></tr></thead>";
    const tb = document.createElement("tbody");
    for (const b of shown) {
      const tr = document.createElement("tr");
      const until = new Date(b.until * 1000).toLocaleString();
      const by = `${b.banned_by} (${CLASS_NAME[b.banned_by_class] || "?"})`;
      tr.innerHTML =
        `<td class="fname">${esc(b.username)}</td>` +
        `<td class="fsize" title="${esc(until)}">in ${esc(banRemaining(b.until, now))}</td>` +
        `<td class="fmeta">${esc(b.reason || "")}</td>` +
        `<td class="fmeta">${esc(by)}</td>` +
        `<td class="fsize"><button class="mini danger">unban</button></td>`;
      const btn = tr.querySelector("button");
      if (!canLiftBan(session, b)) {
        btn.disabled = true;
        btn.title = "set by a higher rank — only they, a higher class or an admin can lift it";
      }
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        unban(b.username, `set by ${b.banned_by}${b.reason ? `: ${b.reason}` : ""}`);
      });
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    listEl.replaceChildren(table);
  }

  /** Ask, then lift the ban; resolves to whether it was lifted. */
  async function unban(username, detail) {
    status.textContent = "";
    let lifted = false;
    await confirmThen(
      () =>
        askConfirm(`Lift the ban on ${username}?${detail ? `\n${detail}` : ""}`, {
          confirmLabel: "Unban",
          danger: true,
        }),
      async () => {
        try {
          list = await invoke("remove_ban", { username });
          lifted = true;
          render();
          status.textContent = `unbanned ${username}`;
        } catch (err) {
          // Inline, like every other window (no native alert boxes).
          status.textContent = errorText(err);
        }
      }
    );
    return lifted;
  }

  $("#ban-refresh").addEventListener("click", refresh);
  filter.addEventListener("input", () => {
    if (loaded) render();
  });
  $("#ban-byname").addEventListener("submit", (e) => {
    e.preventDefault();
    const username = $("#ban-user").value.trim();
    if (!username) return;
    unban(username, "").then((lifted) => {
      if (lifted) $("#ban-user").value = "";
    });
  });

  // Hydration brings the session (who "me" is), which decides which
  // Unban buttons are live; re-render a listing that arrived before it.
  const afterHydrate = () => {
    if (loaded) render();
  };
  return { body, refresh, afterHydrate };
}
