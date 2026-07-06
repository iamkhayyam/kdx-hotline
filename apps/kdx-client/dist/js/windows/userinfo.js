// User Info — one user's detail. A single window that re-targets on request
// (mirrors the reference: "Refresh button", account/class/login/idle/address).

import { invoke } from "../bridge.js";

const CLASS_NAME = ["guest", "user", "power user", "admin"];

export function buildUserInfo() {
  const body = document.createElement("div");
  body.className = "userinfo";
  body.innerHTML = `
    <div class="ui-empty" id="ui-empty">select a user from the User List</div>
    <div class="ui-detail hidden" id="ui-detail">
      <div class="ui-name" id="ui-name"></div>
      <div class="ui-row"><span>Class</span><span id="ui-class"></span></div>
      <div class="ui-row"><span>Logged in</span><span id="ui-login"></span></div>
      <div class="ui-row"><span>Idle</span><span id="ui-idle"></span></div>
      <div class="ui-row"><span>Address</span><span id="ui-addr"></span></div>
      <button class="btn" id="ui-refresh">Refresh</button>
    </div>
  `;
  const $ = (s) => body.querySelector(s);
  let current = null;

  async function show(username) {
    current = username;
    $("#ui-empty").textContent = "loading…";
    $("#ui-empty").classList.remove("hidden");
    $("#ui-detail").classList.add("hidden");
    try {
      const info = await invoke("get_user_info", { username });
      $("#ui-empty").classList.add("hidden");
      $("#ui-detail").classList.remove("hidden");
      $("#ui-name").textContent = info.username;
      $("#ui-class").textContent = CLASS_NAME[info.class] || "?";
      $("#ui-login").textContent = new Date(info.login_at * 1000).toLocaleString();
      $("#ui-idle").textContent = fmtDur(info.idle_secs);
      $("#ui-addr").textContent = info.address;
    } catch (err) {
      $("#ui-empty").textContent = `${username}: ${err.message || err}`;
      $("#ui-empty").classList.remove("hidden");
      $("#ui-detail").classList.add("hidden");
    }
  }

  $("#ui-refresh").addEventListener("click", () => current && show(current));

  return { body, show };
}

function fmtDur(secs) {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  return `${String(d).padStart(2, "0")}:${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")} ago`;
}
