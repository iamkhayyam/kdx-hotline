// KDX entry point. Every window loads index.html and runs this file; the
// ?win= query param decides what mounts:
//   ?win=<id>  ->  a floating feature window (see windows/registry.js)
//   (none)     ->  the launcher: a small floating KDX control strip that
//                  opens every other window. Closing it quits the app.
//
// Server events ("kdx") are broadcast to every window by the Rust forwarder;
// window-to-window UI commands ride the "kdx-ui" channel. Each window keeps
// its own copy of store.js — shared facts (session, server, presence) arrive
// via the session broadcast / kdx events.

import {
  invoke,
  inTauri,
  windowLabel,
  getCurrentWindow,
  onKdxEvent,
  onUi,
  logicalPosition,
  logicalSize,
} from "./bridge.js";
import { initDesktop, open, toggle, hide, show, onChange } from "./wm.js";
import { getState, subscribe, update, updateTransfer } from "./store.js";
import { buildButtonBar } from "./buttonbar.js";
import { mountFeature, registerAll, FEATURES } from "./windows/registry.js";
import { showMenu } from "./menu.js";
import { applySettings, loadSettings } from "./windows/settings.js";

const desktop = document.getElementById("desktop");

// ---- dispatch ----
if (windowLabel() === "main") {
  mountLauncher();
} else {
  initDesktop(desktop);
  registerAll();
  mountFeature(windowLabel());
}

// ---- the launcher window ----

function mountLauncher() {
  initDesktop(desktop);
  registerAll();
  applySettings(loadSettings());

  const buttonBar = buildButtonBar(desktop, {
    onAction: (name, at) => {
      if (name === "disconnect") {
        invoke("disconnect").catch(() => {});
        update({ connection: "offline", session: null, presenceCount: 0 });
      } else if (name === "server") {
        toggle("connect");
      } else if (name === "windows") {
        openWindowsMenu(at && at.x != null ? at : null);
      } else if (name === "exit") {
        const win = getCurrentWindow();
        if (win) win.close();
      }
    },
  });

  // Windows hide/show menu. KDX has no Dock-minimize: hiding makes a window
  // disappear until it's restored here (or via F1 / Cmd+H).
  const hidden = new Set(); // labels currently hidden (but alive)
  function openWindowsMenu(at) {
    const items = FEATURES.map((f) => {
      const exists = isOpen(f.id);
      const visible = exists && !hidden.has(f.id);
      return {
        label: (visible ? "✓ " : "   ") + f.title,
        fn: () => {
          if (visible) hide(f.id);
          else if (exists) show(f.id);
          else open(f.id);
        },
      };
    });
    if (at && at.x != null) showMenu(at.x, at.y, items);
    else showMenu(24, 120, items);
  }

  // Reflect store + window state in the Button Bar.
  subscribe((s) => buttonBar.update(s));
  onChange(() => buttonBar.update(getState()));
  buttonBar.update(getState());

  // Restore the launcher's own saved geometry, then keep it in sync.
  if (inTauri) {
    const win = getCurrentWindow();
    win
      .outerPosition()
      .then((p) => {
        const saved = loadLauncherPos();
        if (saved) {
          win.setPosition(logicalPosition(saved.x, saved.y));
          if (saved.w) win.setSize(logicalSize(saved.w, saved.h));
        }
      })
      .catch(() => {});
    const savePos = () => {
      Promise.all([win.outerPosition(), win.outerSize(), win.scaleFactor()]).then(([p, s, sf]) => {
        try {
          localStorage.setItem(
            "kdx.win.main",
            JSON.stringify({ x: p.x, y: p.y, w: Math.round(s.width / sf), h: Math.round(s.height / sf) })
          );
        } catch (_) {}
      });
    };
    win.onMoved(savePos);
    win.onResized(savePos);
  }

  // Server events the launcher cares about: unread/LED, auto-open windows,
  // presence count, transfer count, disconnect handling.
  const online = new Set();
  let unread = 0;

  onKdxEvent((ev) => {
    switch (ev.type) {
      case "private_message":
        unread += 1;
        buttonBar.setLed(true);
        open("messages");
        break;
      case "chat_invited":
        open("chat");
        break;
      case "presence":
        if (ev.online) online.add(ev.user.username);
        else online.delete(ev.user.username);
        update({ presenceCount: online.size });
        break;
      case "transfer_progress":
        updateTransfer(ev.id, { direction: ev.direction, done: ev.done, total: ev.total });
        break;
      case "transfer_complete":
        updateTransfer(ev.id, { status: ev.status });
        break;
      case "disconnected":
        unread = 0;
        online.clear();
        update({ connection: "offline", session: null, presenceCount: 0 });
        open("connect");
        break;
    }
  });

  // UI commands addressed to the launcher.
  onUi((msg) => {
    if (msg.to !== "main" && msg.to !== "*") return;
    switch (msg.action) {
      case "session":
        update({ connection: "online", session: msg.session, server: msg.server });
        break;
      case "login-success":
        unread = 0;
        buttonBar.setLed(false);
        open("chat");
        invoke("list_users")
          .then((users) => {
            online.clear();
            for (const u of users) online.add(u.username);
            update({ presenceCount: online.size });
          })
          .catch(() => {});
        break;
      case "set-led":
        buttonBar.setLed(msg.unread > 0);
        break;
      case "window-hidden":
        hidden.add(msg.label);
        break;
      case "window-shown":
        hidden.delete(msg.label);
        break;
      case "window-opened":
        hidden.delete(msg.label);
        break;
      case "window-closed":
        hidden.delete(msg.label);
        break;
      case "windows-menu":
        openWindowsMenu(null);
        break;
    }
  });

  // F1 opens the Windows menu from the launcher itself.
  window.addEventListener("keydown", (e) => {
    if (e.key === "F1") {
      e.preventDefault();
      openWindowsMenu(null);
    }
  });

  // Open the Connect window on start.
  open("connect");
}

function loadLauncherPos() {
  try {
    return JSON.parse(localStorage.getItem("kdx.win.main") || "null");
  } catch (_) {
    return null;
  }
}
