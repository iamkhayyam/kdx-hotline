// Classic KDX window chrome for a REAL native window (decorations: off).
// Renders the black/blood-red titlebar ([✕] [hatched menu] title · tag [+][−]),
// wires the buttons to native window APIs, makes the bar a drag region, and
// persists geometry. Each floating KDX window mounts exactly one of these.

import { getCurrentWindow, inTauri, windowLabel, emitUi, logicalSize } from "./bridge.js";
import { showMenu } from "./menu.js";

/**
 * Mount the classic chrome around `body` into `root`.
 * opts: { title, initialTag?, body, windowMenu?:()=>[items] }
 * Returns { setTag(t), el }.
 */
export function mountChrome(root, opts) {
  const label = windowLabel();
  const win = getCurrentWindow(); // undefined in preview mode

  const el = document.createElement("section");
  el.className = "win" + (inTauri ? " native" : " preview");
  el.innerHTML =
    '<div class="titlebar">' +
    '<button class="tb-btn tb-close" title="Close">✕</button>' +
    '<button class="tb-btn tb-menu" title="Window Menu"></button>' +
    `<h2>${opts.title}</h2>` +
    '<span class="tag"></span>' +
    '<button class="tb-btn tb-max" title="Maximize">+</button>' +
    "</div>" +
    '<div class="win-body"></div>' +
    '<div class="resize-grip" title="Drag to resize"></div>';

  const bar = el.querySelector(".titlebar");
  const tagEl = bar.querySelector(".tag");
  if (opts.initialTag) tagEl.textContent = opts.initialTag;
  el.querySelector(".win-body").appendChild(opts.body);
  root.appendChild(el);

  // Every non-interactive titlebar element is a native drag region.
  if (inTauri) {
    bar.querySelectorAll("*").forEach((n) => {
      if (!n.closest("button")) n.setAttribute("data-tauri-drag-region", "");
    });
  }

  const closeBtn = bar.querySelector(".tb-close");
  const maxBtn = bar.querySelector(".tb-max");
  const menuBtn = bar.querySelector(".tb-menu");

  if (inTauri) {
    closeBtn.addEventListener("click", () => win.close());
    maxBtn.addEventListener("click", () => win.toggleMaximize());
    // Focused windows glow: bright titlebar gradient, red border, hot grip.
    win.onFocusChanged(({ payload }) => el.classList.toggle("focused", !!payload));
    win.isFocused().then((f) => el.classList.toggle("focused", !!f)).catch(() => {});
  } else {
    // Preview mode: close removes the section; max is a no-op.
    closeBtn.addEventListener("click", () => el.remove());
    maxBtn.addEventListener("click", () => {});
  }

  // ---- Window shade: double-click the titlebar to roll the window down to
  // just its head, double-click again to restore. Classic window-shade. ----
  let shaded = false;
  let shadeRestore = null; // { w, h } logical size to restore

  async function toggleShade() {
    if (!inTauri || !win) return;
    if (shaded) {
      await unshade();
    } else {
      try {
        const [size, sf] = await Promise.all([win.outerSize(), win.scaleFactor()]);
        const w = Math.round(size.width / sf);
        const h = Math.round(size.height / sf);
        const barH = Math.ceil(bar.getBoundingClientRect().height);
        shadeRestore = { w, h };
        shaded = true; // guard persistGeometry BEFORE the resize event fires
        await win.setSize(logicalSize(w, barH));
        await win.setResizable(false);
        el.classList.add("shaded");
      } catch (_) {}
    }
  }

  async function unshade() {
    if (!shadeRestore) return;
    try {
      await win.setSize(logicalSize(shadeRestore.w, shadeRestore.h));
      await win.setResizable(true);
      el.classList.remove("shaded");
      shaded = false;
      shadeRestore = null;
    } catch (_) {}
  }



  // Hide (not close): the window disappears and returns via the launcher's
  // Windows menu (or F1 / Cmd+H). No Dock minimize in KDX.
  function hideSelf() {
    if (!inTauri || !win) return;
    win.hide().then(() => emitUi("main", "window-hidden", { label })).catch(() => {});
  }
  window.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "h") {
      e.preventDefault();
      hideSelf();
    } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "w") {
      e.preventDefault();
      if (win) win.close();
    } else if (e.key === "F1") {
      e.preventDefault();
      emitUi("main", "windows-menu");
    }
  });



  bar.addEventListener("dblclick", (e) => {
    if (e.target.closest("button")) return;
    toggleShade();
  });

  // The window menu is state-aware: Keep on Top toggles with a checkmark,
  // Maximize becomes Restore while maximized. Right-clicking the titlebar
  // opens the same menu at the cursor.
  async function openWindowMenu(px, py) {
    const extra = opts.windowMenu ? opts.windowMenu() : [];
    let top = false;
    let maxed = false;
    if (inTauri && win) {
      try {
        [top, maxed] = await Promise.all([win.isAlwaysOnTop(), win.isMaximized()]);
      } catch (_) {}
    }
    const items = [
      ...extra,
      ...(extra.length ? [{ separator: true }] : []),
      {
        label: top ? "✓ Keep on Top" : "Keep on Top",
        fn: () => win && win.setAlwaysOnTop(!top),
      },
      { label: maxed ? "Restore" : "Maximize", fn: () => win && win.toggleMaximize() },
      { label: shaded ? "Unshade" : "Shade", fn: () => toggleShade() },
      { label: "Save Window Location/Size", fn: () => persistGeometry() },
      { separator: true },
      { label: "Hide", fn: () => hideSelf() },
      { label: "Close", fn: () => win && win.close() },
    ];
    showMenu(px, py, items);
  }
  menuBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    const r = menuBtn.getBoundingClientRect();
    openWindowMenu(r.left, r.bottom + 2);
  });
  bar.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    openWindowMenu(e.clientX, e.clientY);
  });

  // Geometry persistence (localStorage is shared across the app's windows).
  // Everything is stored in LOGICAL pixels: `outerPosition` reports logical
  // coordinates but `outerSize` reports physical, so the size is divided by
  // the scale factor (otherwise a window doubles on every Retina restart).
  // A maximized or transiently-fullscreen window never clobbers the saved
  // normal size.
  function persistGeometry() {
    if (!inTauri || shaded) return; // never persist the shaded head size
    win
      .isMaximized()
      .then((maxed) => {
        if (maxed) return;
        return Promise.all([win.outerPosition(), win.outerSize(), win.scaleFactor()]).then(([p, s, sf]) => {
          const w = Math.min(Math.max(160, Math.round(s.width / sf)), 2500);
          const h = Math.min(Math.max(120, Math.round(s.height / sf)), 2500);
          const x = Math.min(Math.max(-2000, Math.round(p.x)), 8000);
          const y = Math.min(Math.max(-2000, Math.round(p.y)), 8000);
          try {
            localStorage.setItem("kdx.win." + label, JSON.stringify({ x, y, w, h }));
          } catch (_) {}
        });
      })
      .catch(() => {});
  }
  if (inTauri) {
    win.onMoved(persistGeometry);
    win.onResized(persistGeometry);
    // Tell the launcher we're gone so its buttons un-light.
    win.onCloseRequested(() => {
      emitUi("main", "window-closed", { label });
    });
  }

  return {
    el,
    setTag: (t) => (tagEl.textContent = t || ""),
  };
}
