// KDX entry point. Every window loads index.html and runs this file; the
// ?win= query param decides what mounts:
//   ?win=<id>  ->  a floating feature window (see windows/registry.js)
//   (none)     ->  the launcher: a small floating KDX control strip that
//                  opens every other window. Closing it quits the app.
//
// Server events ("kdx") come from the Rust forwarder; window-to-window UI
// commands ride the "kdx-ui" channel. Each window keeps its own copy of
// store.js — shared facts (session, server, presence) arrive via the session
// broadcast / get_session / kdx events. The launcher also brokers commands
// for windows that are still opening (see delivery.js).

import {
  invoke,
  inTauri,
  windowLabel,
  getCurrentWindow,
  onKdxEvent,
  onUi,
  emitUi,
  logicalPosition,
  logicalSize,
} from "./bridge.js";
import { initDesktop, open, toggle, hide, show, onChange, isOpen } from "./wm.js";
import { getState, subscribe, update, updateTransfer } from "./store.js";
import { buildButtonBar } from "./buttonbar.js";
import { mountFeature, registerAll, FEATURES } from "./windows/registry.js";
import { showMenu } from "./menu.js";
import { applySettings, loadSettings } from "./windows/settings.js";
import { createDeliveryQueue } from "./delivery.js";
import { applySession, hydrateSession } from "./session.js";
import { migrateAddressBook } from "./windows/addressbook.js";

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
  // Old builds kept Address Book passwords in plaintext localStorage: move
  // them into the OS keychain (or drop them) before anything else runs.
  migrateAddressBook({ toKeychain: true });
  // Connection generations restart with the app; drop the previous run's
  // remembered chat room (see chat.js).
  try {
    localStorage.removeItem("kdx.chat.room");
  } catch (_) {}

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
      .then(() => {
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

  // ---- command delivery to windows that may still be opening ----
  const queue = createDeliveryQueue();

  /** Open `target` and hand it a UI command once it's listening. */
  function deliverTo(target, cmd, args, { focus = true } = {}) {
    if (typeof target !== "string" || !FEATURES.some((f) => f.id === target)) return;
    if (queue.isReady(target)) {
      emitUi(target, cmd, args);
      if (focus) open(target);
    } else {
      queue.enqueue(target, cmd, args);
      open(target, { focus });
    }
  }

  // Server events the launcher cares about: unread/LED, auto-open windows,
  // presence count, transfer count, disconnect handling.
  const online = new Set();

  onKdxEvent((ev) => {
    switch (ev.type) {
      case "private_message": {
        const me = getState().session && getState().session.username;
        if (ev.from === me) break; // our own echo; Messages is already open
        // A PM for a Messages window that isn't listening yet is queued for
        // it (it used to be lost). Never steal focus: the LED blinks, and an
        // already-open Messages window handles the event itself.
        if (!queue.isReady("messages")) {
          buttonBar.setLed(true);
          deliverTo("messages", "kdx-replay", { ev }, { focus: false });
        }
        break;
      }
      case "chat_invited":
        if (!queue.isReady("chat")) deliverTo("chat", "kdx-replay", { ev }, { focus: false });
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
        online.clear();
        buttonBar.setLed(false);
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
        applySession(msg);
        break;
      case "login-success":
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
      case "deliver":
        deliverTo(msg.target, msg.cmd, msg.args);
        break;
      case "ready":
        for (const item of queue.markReady(msg.label)) emitUi(msg.label, item.cmd, item.args);
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
        queue.markClosed(msg.label);
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

  hydrateSession();

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
