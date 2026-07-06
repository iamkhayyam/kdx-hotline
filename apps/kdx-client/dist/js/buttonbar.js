// The Button Bar — KDX's authentic vertical launcher. The only always-present
// element: a server header, a list of feature buttons (each opens/focuses a
// window), a WonderLight LED on Messages, and footer counters. Feature buttons
// auto-enable as their window gets registered with the window manager, so
// later milestones light up their entry without touching this file.

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
  // A floating window on the desktop — positioned, not a fixed rail.
  const pos = loadPos();
  bar.style.left = pos.x + "px";
  bar.style.top = pos.y + "px";

  const titlebar = document.createElement("div");
  titlebar.className = "bb-titlebar";
  titlebar.innerHTML = '<span class="bb-brand">KDX</span>';
  makeDraggable(bar, titlebar, mount);

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

function loadPos() {
  try {
    const p = JSON.parse(localStorage.getItem("kdx.win.buttonbar") || "null");
    if (p && typeof p.x === "number") return p;
  } catch (_) {}
  return { x: 12, y: 12 };
}

function makeDraggable(el, handle, desk) {
  handle.addEventListener("pointerdown", (e) => {
    if (e.target.closest("button")) return;
    e.preventDefault();
    const rect = el.getBoundingClientRect();
    const deskRect = desk.getBoundingClientRect();
    const offX = e.clientX - rect.left;
    const offY = e.clientY - rect.top;
    const move = (ev) => {
      const x = Math.min(Math.max(0, ev.clientX - deskRect.left - offX), deskRect.width - 60);
      const y = Math.min(Math.max(0, ev.clientY - deskRect.top - offY), deskRect.height - 24);
      el.style.left = x + "px";
      el.style.top = y + "px";
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      try {
        localStorage.setItem(
          "kdx.win.buttonbar",
          JSON.stringify({ x: parseInt(el.style.left, 10) || 0, y: parseInt(el.style.top, 10) || 0 })
        );
      } catch (_) {}
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  });
}
