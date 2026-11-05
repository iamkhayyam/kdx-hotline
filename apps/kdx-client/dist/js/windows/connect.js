import { invoke, emitUi, noteGeneration } from "../bridge.js";
import { update, getState, subscribe } from "../store.js";
import { esc, num, errorText } from "../html.js";
import { canAutoSubmit } from "../bookmarks.js";
import { MIN_PASSWORD_LENGTH, changePasswordProblem } from "../passwords.js";

const CLASSES = ["guest", "user", "power user", "admin"];
// Characters of a CHANGED server key the user must type back before it
// replaces the pinned one (the Rust `trust` command checks the same).
const KEY_CODE_LEN = 8;

/** What the user must type to accept a changed key: the start of the new
 * fingerprint's digest (after "sha256:"). */
function keyChangeCode(fingerprint) {
  const fp = String(fingerprint || "");
  const i = fp.indexOf(":");
  return [...(i === -1 ? fp : fp.slice(i + 1))].slice(0, KEY_CODE_LEN).join("");
}

export function buildConnect() {
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
    <div class="pw-change hidden" id="c-account">
      <button class="btn full" type="button" id="c-pw-open">Change Password…</button>
      <form class="pw-form hidden" id="c-pw-form">
        <div class="field"><label for="c-pw-current">Current password</label>
          <input id="c-pw-current" type="password" autocomplete="current-password" /></div>
        <div class="field"><label for="c-pw-new">New password</label>
          <input id="c-pw-new" type="password" autocomplete="new-password" /></div>
        <div class="field"><label for="c-pw-confirm">Confirm new password</label>
          <input id="c-pw-confirm" type="password" autocomplete="new-password" /></div>
        <div class="pw-actions">
          <button class="btn" type="submit" id="c-pw-save">Change</button>
          <button class="btn" type="button" id="c-pw-cancel">Cancel</button>
        </div>
        <p class="note">At least ${num(MIN_PASSWORD_LENGTH)} characters. <b>Neither password leaves this machine</b> — you prove the current one with a fresh challenge-response, and the server gets only a credential derived from the new one. Your other sessions on this server are signed out.</p>
      </form>
      <div class="status" id="c-pw-status"></div>
    </div>
  `;

  const $ = (id) => body.querySelector(id);
  const status = $("#c-status");
  const tofuBox = $("#c-tofu");
  const go = $("#c-go");
  const passEl = $("#c-pass");

  // Set when the Address Book filled the form from a bookmark whose password
  // lives in the OS keychain: an empty password field then means "use the
  // saved one", which the Rust side reads itself (never via the webview).
  let bookmarkId = null;
  const forgetBookmark = () => {
    bookmarkId = null;
    passEl.placeholder = "";
  };
  for (const id of ["#c-host", "#c-port", "#c-user", "#c-pass"]) $(id).addEventListener("input", forgetBookmark);

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

  function fields() {
    return {
      host: $("#c-host").value.trim(),
      port: parseInt($("#c-port").value.trim(), 10) || 10700,
      username: $("#c-user").value.trim(),
      password: passEl.value,
    };
  }

  async function attempt() {
    const { host, port, username, password } = fields();
    tofuBox.textContent = "";
    go.disabled = true;
    update({ connection: "connecting", server: { host, port } });
    setStatus("connecting…");

    try {
      const gen = await invoke("connect", { host, port });
      noteGeneration(gen);
      await finishLogin(gen, host, port, username, password);
    } catch (err) {
      update({ connection: "offline" });
      if (err && err.kind === "untrusted_certificate") {
        showTofu(err, host, port);
      } else {
        setStatus(errorText(err), "err");
      }
    } finally {
      go.disabled = false;
    }
  }

  async function finishLogin(gen, host, port, username, password) {
    setStatus("authenticating…");
    const useSaved = !password && bookmarkId;
    const klass = await invoke("login", {
      username,
      password,
      bookmarkId: useSaved ? bookmarkId : null,
    });
    try {
      localStorage.setItem("kdx.lastServer", JSON.stringify({ host, port, username }));
    } catch (_) {}
    update({ connection: "online", session: { class: klass, username }, server: { host, port } });
    setStatus(`logged in as ${username} (${CLASSES[klass] || "?"})`, "ok");
    try {
      await invoke("join_room", { room: getState().room });
    } catch (err) {
      // Logged in all the same: say so, and let the other windows know.
      setStatus(`logged in as ${username}, but couldn't join the chat: ${errorText(err)}`, "warn");
    }
    // Tell every other window who we are (they keep their own store), and
    // let the launcher open the chat window + snapshot the roster.
    emitUi("*", "session", { gen, session: { username, class: klass }, server: { host, port } });
    emitUi("main", "login-success");
  }

  function showTofu(err, host, port) {
    if (err.previous) showChangedKey(err, host, port);
    else showFirstContact(err, host, port);
  }

  // First contact (TOFU): one click to trust and connect.
  function showFirstContact(err, host, port) {
    tofuBox.innerHTML = `
      <div class="tofu">
        <h3>unrecognized server</h3>
        <div>First time connecting to this server. Verify the fingerprint out-of-band before trusting it.</div>
        <div class="fp">${esc(err.fingerprint)}</div>
        <div class="actions">
          <button class="btn" id="t-trust">Trust &amp; connect</button>
          <button class="btn" id="t-cancel">Cancel</button>
        </div>
      </div>`;
    tofuBox.querySelector("#t-cancel").onclick = cancelTofu;
    tofuBox.querySelector("#t-trust").onclick = async () => {
      try {
        await invoke("trust", { host, port });
      } catch (e) {
        setStatus(errorText(e), "err");
        return;
      }
      tofuBox.textContent = "";
      attempt();
    };
  }

  // A key that CHANGED since it was pinned is how a man-in-the-middle looks.
  // No one-click path: show both keys, make the user type part of the new
  // one, and never log in automatically afterwards.
  function showChangedKey(err, host, port) {
    const code = keyChangeCode(err.fingerprint);
    tofuBox.innerHTML = `
      <div class="tofu changed">
        <h3>⚠ server key changed</h3>
        <div class="warn">The key presented by ${esc(host)}:${num(port)} is not the one you trusted before.
          This can mean the server was reinstalled — or that someone is intercepting this connection.
          Don't continue unless the server's operator confirmed the new key to you.</div>
        <div class="tofu-label">previously trusted</div>
        <div class="fp old">${esc(err.previous)}</div>
        <div class="tofu-label">presented now</div>
        <div class="fp">${esc(err.fingerprint)}</div>
        <label class="tofu-confirm">To replace the pinned key, type the first ${num(KEY_CODE_LEN)} characters of the new key (after “sha256:”)
          <input id="t-code" spellcheck="false" autocomplete="off" /></label>
        <div class="actions">
          <button class="btn" id="t-replace" disabled>Replace pinned key</button>
          <button class="btn" id="t-cancel">Cancel</button>
        </div>
      </div>`;
    const input = tofuBox.querySelector("#t-code");
    const replace = tofuBox.querySelector("#t-replace");
    input.addEventListener("input", () => {
      replace.disabled = input.value.trim() !== code;
    });
    tofuBox.querySelector("#t-cancel").onclick = cancelTofu;
    replace.onclick = async () => {
      try {
        await invoke("trust", { host, port, confirm: input.value.trim() });
      } catch (e) {
        setStatus(errorText(e), "err");
        return;
      }
      tofuBox.textContent = "";
      setStatus("pinned key replaced — check the details, then Authenticate to connect", "warn");
    };
  }

  function cancelTofu() {
    tofuBox.textContent = "";
    setStatus("cancelled", "err");
  }

  go.addEventListener("click", attempt);
  passEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") attempt();
  });

  // ---- Change Password (the logged-in account's own) ----
  const account = $("#c-account");
  const pwOpen = $("#c-pw-open");
  const pwForm = $("#c-pw-form");
  const pwSave = $("#c-pw-save");
  const pwStatus = $("#c-pw-status");
  const pwCurrent = $("#c-pw-current");
  const pwNew = $("#c-pw-new");
  const pwConfirm = $("#c-pw-confirm");

  function setPwStatus(msg, cls) {
    pwStatus.textContent = msg;
    pwStatus.className = "status " + (cls || "");
  }

  function closePwForm() {
    pwCurrent.value = "";
    pwNew.value = "";
    pwConfirm.value = "";
    pwForm.classList.add("hidden");
    pwOpen.classList.remove("hidden");
  }

  // Offered only while logged in; logging out (or being dropped) closes it.
  function syncAccount(s) {
    const loggedIn = s.connection === "online" && !!s.session;
    account.classList.toggle("hidden", !loggedIn);
    if (!loggedIn && !pwForm.classList.contains("hidden")) {
      closePwForm();
      setPwStatus("");
    }
  }
  subscribe(syncAccount);
  syncAccount(getState());

  pwOpen.addEventListener("click", () => {
    pwOpen.classList.add("hidden");
    pwForm.classList.remove("hidden");
    setPwStatus("");
    pwCurrent.focus();
  });
  $("#c-pw-cancel").addEventListener("click", () => {
    closePwForm();
    setPwStatus("");
  });
  pwForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const current = pwCurrent.value;
    const next = pwNew.value;
    const problem = changePasswordProblem(current, next, pwConfirm.value);
    if (problem) {
      setPwStatus(problem, "err");
      return;
    }
    pwSave.disabled = true;
    setPwStatus("changing password…");
    try {
      const message = await invoke("change_password", { currentPassword: current, newPassword: next });
      closePwForm();
      setPwStatus(`${message}. Update any password saved for this server in the Address Book.`, "ok");
    } catch (err) {
      pwCurrent.value = "";
      setPwStatus(errorText(err), "err");
    } finally {
      pwSave.disabled = false;
    }
  });

  function askForPassword() {
    const login = $("#c-user").value.trim();
    setStatus(login ? `enter the password for ${login}` : "enter the password", "warn");
    passEl.focus();
  }

  // Exposed so the Address Book / Trackers can pre-fill (and connect). A
  // bookmark's password is never sent here — only its id.
  function fill(fields) {
    if (fields.host != null) $("#c-host").value = fields.host;
    if (fields.port != null) $("#c-port").value = fields.port;
    if (fields.login != null) $("#c-user").value = fields.login;
    passEl.value = "";
    forgetBookmark();
    if (fields.bookmarkId && fields.hasSecret) {
      bookmarkId = String(fields.bookmarkId);
      passEl.placeholder = "saved in keychain";
    }
    if (fields.askPassword) askForPassword();
  }

  // An automatic submit (from a bookmark) never sends an empty password
  // that has no saved one behind it: that login can only fail.
  function submit() {
    if (!canAutoSubmit({ password: passEl.value, bookmarkId })) {
      askForPassword();
      return;
    }
    attempt();
  }

  return { body, fill, submit };
}
