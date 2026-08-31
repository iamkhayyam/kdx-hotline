// The Button Bar — KDX's authentic vertical launcher, now its OWN native
// window (the "main" window). Always present; every other window floats free
// on the desktop. Its titlebar is a native drag region; − minimizes to the
// OS Dock, ✕ quits the app. Feature buttons auto-enable as their window gets
// registered, so later milestones light up their entry without touching this
// file.

import { inTauri, getCurrentWindow } from "./bridge.js";
import { isRegistered, isOpen, toggle } from "./wm.js";

// Order mirrors the real KDX client's left strip.
const FEATURES = [
  { id: "news", label: "Public News", win: "news", requires: "connected" },
  { id: "chat", label: "Public Chat", win: "chat", requires: "connected" },
  { id: "files", label: "Files", win: "files", requires: "connected" },
  { id: "userlist", label: "User List", win: "userlist", requires: "connected" },
  { id: "admin", label: "Administration", win: "admin", requires: "connected" },
  { sep: true },
  { id: "disconnect", label: "Disconnect", action: "disconnect", requires: "connected" },
  { id: "connect", label: "Connect…", win: "connect" },
  { id: "addressbook", label: "Address Book", win: "addressbook" },
  { id: "trackers", label: "Trackers", win: "trackers", requires: "connected" },
  { id: "transfers", label: "File Transfers", win: "transfers" },
  { id: "messages", label: "Messages", win: "messages", led: true, requires: "connected" },
  { sep: true },
  { id: "settings", label: "Settings", win: "settings" },
  { id: "about", label: "About", win: "about" },
  { id: "exit", label: "Exit", action: "exit" },
];

/**
 * Build the Button Bar into `mount`. `handlers`: { onAction(name) } for
 * non-window features (disconnect, exit) and server-header clicks.
 * Returns { update(state), setLed(on) }.
 */
export function buildButtonBar(mount, handlers) {
  const bar = document.createElement("nav");
  bar.className = "buttonbar";

  const titlebar = document.createElement("div");
  titlebar.className = "bb-titlebar";
  titlebar.innerHTML =
    '<span class="bb-brand">KDX</span>' +
    '<span class="bb-spacer"></span>' +
    '<button class="tb-btn tb-menu" id="bb-windows" title="Windows (F1)">☰</button>' +
    '<button class="tb-btn tb-close" title="Quit KDX">✕</button>';
  // The whole titlebar is a native drag region except the buttons.
  if (inTauri) {
    titlebar.setAttribute("data-tauri-drag-region", "");
    titlebar.querySelectorAll("*").forEach((n) => {
      if (!n.closest("button")) n.setAttribute("data-tauri-drag-region", "");
    });
    const win = getCurrentWindow();
    const windowsBtn = titlebar.querySelector("#bb-windows");
    windowsBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      const r = windowsBtn.getBoundingClientRect();
      handlers.onAction("windows", { x: r.left, y: r.bottom + 2 });
    });
    titlebar.querySelector(".tb-close").addEventListener("click", () => win.close());
    // Focus glow on the launcher itself.
    win.onFocusChanged(({ payload }) => bar.classList.toggle("focused", !!payload));
    win.isFocused().then((f) => bar.classList.toggle("focused", !!f)).catch(() => {});
  } else {
    titlebar.querySelector("#bb-windows").style.display = "none";
    titlebar.querySelector(".tb-close").style.display = "none";
  }

  bar.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    handlers.onAction("windows", { x: e.clientX, y: e.clientY });
  });

  const header = document.createElement("div");
  header.className = "bb-header";
  header.innerHTML =
    '<div class="bb-banner" id="bb-banner"></div>' +
    '<button class="bb-server" id="bb-server"><span id="bb-server-name">Not connected</span><span class="bb-caret">▾</span></button>';
  header.querySelector("#bb-server").addEventListener("click", () => handlers.onAction("server"));

  const list = document.createElement("div");
  list.className = "bb-list";
  const items = new Map();
  for (const f of FEATURES) {
    if (f.sep) {
      const s = document.createElement("div");
      s.className = "bb-sep";
      list.appendChild(s);
      continue;
    }
    const btn = document.createElement("button");
    btn.className = "bb-item";
    btn.dataset.id = f.id;
    btn.innerHTML =
      '<span class="bb-icon"></span>' +
      `<span class="bb-label">${f.label}</span>` +
      (f.led ? '<span class="wonderlight" id="wl-messages"></span>' : "");
    btn.addEventListener("click", () => {
      if (btn.disabled) return;
      if (f.win) toggle(f.win);
      else if (f.action) handlers.onAction(f.action);
    });
    list.appendChild(btn);
    items.set(f.id, { f, btn });
  }

  const footer = document.createElement("div");
  footer.className = "bb-footer";
  footer.innerHTML =
    '<span class="bb-count" id="bb-c-users" title="users online">[0]</span>' +
    '<span class="bb-count" id="bb-c-rooms" title="rooms">[0]</span>' +
    '<span class="bb-count" id="bb-c-xfer" title="active transfers">[0]</span>';

  bar.appendChild(titlebar);
  bar.appendChild(header);
  bar.appendChild(list);
  bar.appendChild(footer);
  mount.appendChild(bar);

  const serverName = header.querySelector("#bb-server-name");
  const cUsers = footer.querySelector("#bb-c-users");
  const cRooms = footer.querySelector("#bb-c-rooms");
  const cXfer = footer.querySelector("#bb-c-xfer");
  const banner = header.querySelector("#bb-banner");

  function update(state) {
    const connected = state.connection === "online";
    const isAdmin = state.session && state.session.class === 3;

    serverName.textContent = connected && state.server
      ? state.server.host
      : state.connection === "connecting"
      ? "connecting…"
      : "Not connected";
    banner.classList.toggle("on", connected);

    for (const { f, btn } of items.values()) {
      let enabled = true;
      if (f.win && !isRegistered(f.win)) enabled = false; // not built yet
      if (f.requires === "connected" && !connected) enabled = false;
      if (f.requires === "admin" && !(connected && isAdmin)) enabled = false;
      if (f.id === "connect") enabled = true; // always reachable
      if (f.id === "exit") enabled = true;
      btn.disabled = !enabled;
      btn.classList.toggle("active", !!f.win && isOpen(f.win));
    }

    const users = state.presenceCount || 0;
    const xfer = state.transfers
      ? Object.values(state.transfers).filter((t) => t.status === undefined).length
      : 0;
    cUsers.textContent = `[${users}]`;
    cRooms.textContent = `[${connected ? 1 : 0}]`;
    cXfer.textContent = `[${xfer}]`;
  }

  function setLed(on) {
    const led = document.getElementById("wl-messages");
    if (led) led.classList.toggle("blink", on);
  }

  return { update, setLed };
}
