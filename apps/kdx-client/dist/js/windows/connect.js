import { invoke } from "../bridge.js";
import { update, getState } from "../store.js";

const CLASSES = ["guest", "user", "power user", "admin"];

export function buildConnect(onLoggedIn) {
  const body = document.createElement("div");
  body.className = "login";
  body.innerHTML = `
    <div class="row">
      <div class="field"><label for="c-host">Server</label>
        <input id="c-host" value="127.0.0.1" spellcheck="false" /></div>
      <div class="field port"><label for="c-port">Port</label>
        <input id="c-port" value="10700" /></div>
    </div>
    <div class="field"><label for="c-user">Login</label>
      <input id="c-user" value="" spellcheck="false" /></div>
    <div class="field"><label for="c-pass">Password</label>
      <input id="c-pass" type="password" value="" /></div>
    <button class="btn full" id="c-go">Authenticate</button>
    <p class="note">Challenge-response over TLS. <b>Your password never leaves this machine</b> — the server sends a one-time challenge and gets back only a keyed digest.</p>
    <div class="status" id="c-status"></div>
    <div id="c-tofu"></div>
  `;

  const $ = (id) => body.querySelector(id);
  const status = $("#c-status");
  const tofuBox = $("#c-tofu");
  const go = $("#c-go");

  // Restore the last server/login the user connected to.
  try {
    const saved = JSON.parse(localStorage.getItem("kdx.lastServer") || "{}");
    if (saved.host) $("#c-host").value = saved.host;
    if (saved.port) $("#c-port").value = saved.port;
    if (saved.username) $("#c-user").value = saved.username;
  } catch (_) {}

  function setStatus(msg, cls) {
    status.textContent = msg;
    status.className = "status " + (cls || "");
  }

  async function attempt() {
    const host = $("#c-host").value.trim();
    const port = parseInt($("#c-port").value.trim(), 10) || 10700;
    const username = $("#c-user").value.trim();
    const password = $("#c-pass").value;
    tofuBox.innerHTML = "";
    go.disabled = true;
    update({ connection: "connecting", server: { host, port } });
    setStatus("connecting…");

    try {
      await invoke("connect", { host, port });
      await finishLogin(host, port, username, password);
    } catch (err) {
      if (err && err.kind === "untrusted_certificate") {
        update({ connection: "offline" });
        showTofu(err, host, port, username, password);
      } else {
        update({ connection: "offline" });
        setStatus(errMsg(err), "err");
      }
      go.disabled = false;
    }
  }

  async function finishLogin(host, port, username, password) {
    setStatus("authenticating…");
    const klass = await invoke("login", { username, password });
    try {
      localStorage.setItem("kdx.lastServer", JSON.stringify({ host, port, username }));
    } catch (_) {}
    update({ connection: "online", session: { class: klass }, server: { host, port } });
    setStatus(`logged in as ${username} (${CLASSES[klass] || "?"})`, "ok");
    go.disabled = false;
    await invoke("join_room", { room: getState().room });
    onLoggedIn();
  }

  function showTofu(err, host, port, username, password) {
    const changed = !!err.previous;
    tofuBox.innerHTML = `
      <div class="tofu">
        <h3>${changed ? "⚠ server key changed" : "unrecognized server"}</h3>
        <div>${changed
          ? '<span class="warn">The key for this server changed since you last trusted it. This can mean the server was reinstalled — or an impostor.</span>'
          : "First time connecting to this server. Verify the fingerprint out-of-band before trusting it."}</div>
        <div class="fp">${err.fingerprint}</div>
        ${changed ? `<div>previously: <span class="fp">${err.previous}</span></div>` : ""}
        <div class="actions">
          <button class="btn" id="t-trust">Trust &amp; connect</button>
          <button class="btn" id="t-cancel">Cancel</button>
        </div>
      </div>`;
    tofuBox.querySelector("#t-cancel").onclick = () => {
      tofuBox.innerHTML = "";
      setStatus("cancelled", "err");
    };
    tofuBox.querySelector("#t-trust").onclick = async () => {
      try {
        await invoke("trust", { host, port, fingerprint: err.fingerprint });
        tofuBox.innerHTML = "";
        go.disabled = true;
        update({ connection: "connecting" });
        setStatus("connecting…");
        await invoke("connect", { host, port });
        await finishLogin(host, port, username, password);
      } catch (e) {
        update({ connection: "offline" });
        setStatus(errMsg(e), "err");
        go.disabled = false;
      }
    };
  }

  go.addEventListener("click", attempt);
  $("#c-pass").addEventListener("keydown", (e) => {
    if (e.key === "Enter") attempt();
  });

  // Exposed so the Address Book can pre-fill and connect from a bookmark.
  function fill(fields) {
    if (fields.host != null) $("#c-host").value = fields.host;
    if (fields.port != null) $("#c-port").value = fields.port;
    if (fields.login != null) $("#c-user").value = fields.login;
    if (fields.password != null) $("#c-pass").value = fields.password;
  }

  return { body, fill, submit: attempt };
}

function errMsg(err) {
  if (!err) return "unknown error";
  if (typeof err === "string") return err;
  return err.message || JSON.stringify(err);
}
