// Server — remote server management. Settings (name/description/greeting/
// max users, with port and throttle shown read-only since they're fixed at
// process start), Broadcast to every connected session, and Shutdown
// (gracefully stops the server — never touches the host machine).

import { invoke } from "../bridge.js";

export function buildServerAdmin(openHistory) {
  const body = document.createElement("div");
  body.className = "srv-win";
  body.innerHTML = `
    <div class="srv-section">
      <div class="srv-head">Server Settings</div>
      <form id="srv-settings-form">
        <div class="ab-grid">
          <label>Name<input id="srv-name" spellcheck="false" autocomplete="off" /></label>
          <label>Max Users<input id="srv-max-users" inputmode="numeric" /></label>
        </div>
        <label class="srv-full">Description<input id="srv-desc" spellcheck="false" autocomplete="off" /></label>
        <label class="srv-full">Login Greeting<input id="srv-greeting" spellcheck="false" autocomplete="off" /></label>
        <div class="srv-readonly" id="srv-readonly"></div>
        <div class="ab-actions">
          <button type="submit" class="btn">Save</button>
          <button type="button" class="mini" id="srv-refresh">Refresh</button>
          <button type="button" class="mini" id="srv-history">History…</button>
        </div>
        <div class="rl-assign-result" id="srv-settings-result"></div>
      </form>
    </div>
    <div class="srv-section">
      <div class="srv-head">Broadcast</div>
      <form id="srv-broadcast-form" class="srv-inline">
        <input id="srv-broadcast-text" placeholder="message to every connected user…" spellcheck="false" autocomplete="off" />
        <button type="submit" class="mini">Send</button>
      </form>
      <div class="rl-assign-result" id="srv-broadcast-result"></div>
    </div>
    <div class="srv-section srv-danger">
      <div class="srv-head">Shutdown</div>
      <div class="srv-inline">
        <input id="srv-shutdown-message" placeholder="shutdown notice (optional)" spellcheck="false" autocomplete="off" />
        <button class="mini danger" id="srv-shutdown-btn">Shutdown Server</button>
      </div>
      <div class="rl-assign-result" id="srv-shutdown-result"></div>
    </div>`;

  const $ = (s) => body.querySelector(s);
  const settingsForm = $("#srv-settings-form");
  const settingsResult = $("#srv-settings-result");

  async function refresh() {
    settingsResult.textContent = "";
    try {
      const s = await invoke("get_server_settings");
      $("#srv-name").value = s.name;
      $("#srv-desc").value = s.description;
      $("#srv-greeting").value = s.greeting;
      $("#srv-max-users").value = s.max_users;
      $("#srv-readonly").innerHTML =
        `port <b>${s.port}</b> · ` +
        `upload ${s.max_upload_bytes_per_sec ? fmtRate(s.max_upload_bytes_per_sec) : "unlimited"} · ` +
        `download ${s.max_download_bytes_per_sec ? fmtRate(s.max_download_bytes_per_sec) : "unlimited"} ` +
        `<span class="srv-note">(fixed at server start)</span>`;
    } catch (err) {
      settingsResult.textContent = esc(err.message || String(err));
    }
  }

  settingsForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = $("#srv-name").value.trim();
    if (!name) {
      settingsResult.textContent = "a server name is required";
      return;
    }
    // parseInt("") and parseInt("abc") both yield NaN — validate explicitly
    // rather than falling back to 0, which would silently wipe out a
    // configured cap as "unlimited" on a blank/bad input.
    const maxUsersRaw = $("#srv-max-users").value.trim();
    const maxUsers = parseInt(maxUsersRaw, 10);
    if (!Number.isInteger(maxUsers) || maxUsers < 0) {
      settingsResult.textContent = "max users must be a non-negative whole number";
      return;
    }
    try {
      const s = await invoke("update_server_settings", {
        name,
        description: $("#srv-desc").value,
        greeting: $("#srv-greeting").value,
        maxUsers,
      });
      $("#srv-max-users").value = s.max_users;
      settingsResult.textContent = "saved";
    } catch (err) {
      settingsResult.textContent = esc(err.message || String(err));
    }
  });
  $("#srv-refresh").addEventListener("click", refresh);
  if (openHistory) $("#srv-history").addEventListener("click", openHistory);

  $("#srv-broadcast-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = $("#srv-broadcast-text").value.trim();
    if (!text) return;
    const result = $("#srv-broadcast-result");
    try {
      await invoke("broadcast", { text });
      result.textContent = "sent — awaiting server ack…";
      $("#srv-broadcast-text").value = "";
    } catch (err) {
      result.textContent = esc(err.message || String(err));
    }
  });

  $("#srv-shutdown-btn").addEventListener("click", async () => {
    const message = $("#srv-shutdown-message").value.trim();
    if (!confirm("Shut down the server? Every connected user, including you, will be disconnected.")) {
      return;
    }
    const result = $("#srv-shutdown-result");
    try {
      await invoke("shutdown_server", { message });
      result.textContent = "shutdown requested…";
    } catch (err) {
      result.textContent = esc(err.message || String(err));
    }
  });

  return { body, refresh };
}

function fmtRate(bytesPerSec) {
  if (bytesPerSec >= 1024 * 1024) return (bytesPerSec / 1024 / 1024).toFixed(1) + " MB/s";
  if (bytesPerSec >= 1024) return (bytesPerSec / 1024).toFixed(1) + " KB/s";
  return bytesPerSec + " B/s";
}
function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}
