// KDX window manager v2 — authentic window anatomy.
//
// Title bar: [X close] [hatched Window Menu] title ......... [+ max] [- min]
// Resize grip in the bottom-right. Windows are registered lazily and toggled
// open. Minimized windows collect in the Dock window. "Keep on Top" pins a
// window into a higher z-band. Geometry (position + size) persists per window.

import { showMenu } from "./menu.js";

const Z_BASE = 10;
const Z_PINNED = 10000;
let zNormal = Z_BASE;
let zPinned = Z_PINNED;

const registry = new Map(); // id -> { opts, win|null, state, pinned, maxed, savedRect }
const changeListeners = new Set();
let desktopEl = null;
let dock = null;

/** state: "closed" | "open" | "minimized" */

export function initDesktop(el) {
  desktopEl = el;
  dock = createDock();
  window.addEventListener("keydown", onGlobalKey, true);
}

/** Notify Button Bar / Dock when any window's state changes. */
export function onChange(fn) {
  changeListeners.add(fn);
  return () => changeListeners.delete(fn);
}
function emitChange() {
  for (const fn of changeListeners) fn();
}

/**
 * Register a feature window (built lazily on first open).
 * opts: { id, title, tag?, rect:{x,y,w,h}, resizable?, build:()=>({el|body, api?}),
 *         windowMenu?:()=>[items], onOpen?, onClose? }
 */
export function register(opts) {
  registry.set(opts.id, {
    opts,
    win: null,
    state: "closed",
    pinned: false,
    maxed: false,
    savedRect: loadRect(opts.id) || opts.rect,
  });
}

export function isRegistered(id) {
  return registry.has(id);
}
export function isOpen(id) {
  const e = registry.get(id);
  return !!e && e.state === "open";
}
export function getState(id) {
  return registry.get(id)?.state || "closed";
}
export function api(id) {
  return registry.get(id)?.win?.api;
}

/** Open (creating if needed), restore if minimized, and focus. */
export function open(id) {
  const entry = registry.get(id);
  if (!entry) return;
  if (!entry.win) build(entry);
  entry.win.el.classList.remove("hidden");
  entry.state = "open";
  removeDockRow(id);
  focus(id);
  entry.opts.onOpen && entry.opts.onOpen(entry.win.api);
  emitChange();
}

/** Toggle from a launcher button: open if closed/minimized, else focus. */
export function toggle(id) {
  const entry = registry.get(id);
  if (!entry) return;
  if (entry.state !== "open") open(id);
  else focus(id);
}

export function close(id) {
  const entry = registry.get(id);
  if (!entry || !entry.win) return;
  entry.win.el.classList.add("hidden");
  entry.state = "closed";
  removeDockRow(id);
  entry.opts.onClose && entry.opts.onClose();
  emitChange();
}

export function minimize(id) {
  const entry = registry.get(id);
  if (!entry || !entry.win) return;
  saveRect(entry);
  entry.win.el.classList.add("hidden");
  entry.state = "minimized";
  addDockRow(entry);
  emitChange();
}

export function focus(id) {
  const entry = registry.get(id);
  if (!entry || !entry.win) return;
  for (const e of registry.values()) e.win && e.win.el.classList.remove("focused");
  entry.win.el.classList.add("focused");
  entry.win.el.style.zIndex = entry.pinned ? ++zPinned : ++zNormal;
}

function toggleMaximize(id) {
  const entry = registry.get(id);
  if (!entry || !entry.win) return;
  const el = entry.win.el;
  if (entry.maxed) {
    el.classList.remove("maximized");
    applyRect(el, entry.savedRect);
    entry.maxed = false;
  } else {
    saveRect(entry);
    el.classList.add("maximized");
    entry.maxed = true;
  }
  focus(id);
}

function toggleKeepOnTop(id) {
  const entry = registry.get(id);
  if (!entry) return;
  entry.pinned = !entry.pinned;
  entry.win.el.classList.toggle("pinned", entry.pinned);
  focus(id);
}

// ---- construction ----

function build(entry) {
  const { opts } = entry;
  const built = opts.build();
  const bodyEl = built.el || built.body || built;
  const el = document.createElement("section");
  el.className = "win";
  el.dataset.id = opts.id;
  applyRect(el, entry.savedRect);

  const bar = document.createElement("div");
  bar.className = "titlebar";
  bar.innerHTML =
    '<button class="tb-btn tb-close" title="Close">✕</button>' +
    '<button class="tb-btn tb-menu" title="Window Menu"></button>' +
    `<h2>${opts.title}</h2>` +
    '<span class="tag"></span>' +
    '<button class="tb-btn tb-max" title="Maximize">+</button>' +
    '<button class="tb-btn tb-min" title="Minimize">−</button>';
  const tagEl = bar.querySelector(".tag");
  if (opts.tag) tagEl.textContent = opts.tag;

  const bodyWrap = document.createElement("div");
  bodyWrap.className = "win-body";
  bodyWrap.appendChild(bodyEl);

  el.appendChild(bar);
  el.appendChild(bodyWrap);
  if (opts.resizable !== false) {
    const grip = document.createElement("div");
    grip.className = "resize-grip";
    el.appendChild(grip);
    makeResizable(el, grip, entry);
  }
  desktopEl.appendChild(el);

  el.addEventListener("pointerdown", () => focus(opts.id));
  bar.querySelector(".tb-close").addEventListener("click", (e) => { e.stopPropagation(); close(opts.id); });
  bar.querySelector(".tb-min").addEventListener("click", (e) => { e.stopPropagation(); minimize(opts.id); });
  bar.querySelector(".tb-max").addEventListener("click", (e) => { e.stopPropagation(); toggleMaximize(opts.id); });
  const menuBtn = bar.querySelector(".tb-menu");
  menuBtn.addEventListener("click", (e) => { e.stopPropagation(); openWindowMenu(entry, menuBtn); });
  bar.addEventListener("contextmenu", (e) => { e.preventDefault(); openWindowMenu(entry, null, e.clientX, e.clientY); });

  makeDraggable(el, bar, entry);
  entry.win = { el, bar, tagEl, api: built.api || {}, setTag: (t) => (tagEl.textContent = t) };
}

function openWindowMenu(entry, btn, px, py) {
  const id = entry.opts.id;
  const extra = entry.opts.windowMenu ? entry.opts.windowMenu() : [];
  const items = [
    ...extra,
    ...(extra.length ? [{ separator: true }] : []),
    { label: entry.pinned ? "✓ Keep on Top" : "Keep on Top", fn: () => toggleKeepOnTop(id) },
    { label: entry.maxed ? "Restore" : "Maximize", fn: () => toggleMaximize(id) },
    { label: "Save Window Location/Size", fn: () => { saveRect(entry); persistRect(id, entry.savedRect); } },
    { separator: true },
    { label: "Minimize", fn: () => minimize(id) },
    { label: "Close", fn: () => close(id) },
  ];
  if (btn) {
    const r = btn.getBoundingClientRect();
    showMenu(r.left, r.bottom + 2, items);
  } else {
    showMenu(px, py, items);
  }
}

// ---- Dock (collects minimized windows) ----

function createDock() {
  const el = document.createElement("section");
  el.className = "win dock hidden";
  el.dataset.id = "__dock";
  el.style.left = "8px";
  el.style.bottom = "8px";
  el.style.width = "190px";
  el.innerHTML =
    '<div class="titlebar dock-bar"><h2>Dock</h2></div><div class="win-body dock-body"></div>';
  desktopEl.appendChild(el);
  return { el, body: el.querySelector(".dock-body"), rows: new Map() };
}

function addDockRow(entry) {
  if (dock.rows.has(entry.opts.id)) return;
  const row = document.createElement("div");
  row.className = "dock-row";
  row.textContent = entry.opts.title;
  row.addEventListener("click", () => open(entry.opts.id));
  dock.body.appendChild(row);
  dock.rows.set(entry.opts.id, row);
  dock.el.classList.remove("hidden");
}
function removeDockRow(id) {
  const row = dock.rows.get(id);
  if (row) { row.remove(); dock.rows.delete(id); }
  if (dock.rows.size === 0) dock.el.classList.add("hidden");
}

// ---- geometry ----

function applyRect(el, r) {
  el.style.left = r.x + "px";
  el.style.top = r.y + "px";
  el.style.width = r.w + "px";
  if (r.h) el.style.height = r.h + "px";
}
function saveRect(entry) {
  if (!entry.win || entry.maxed) return;
  const el = entry.win.el;
  entry.savedRect = {
    x: parseInt(el.style.left, 10) || 0,
    y: parseInt(el.style.top, 10) || 0,
    w: el.offsetWidth,
    h: el.offsetHeight,
  };
}
function persistRect(id, rect) {
  try { localStorage.setItem("kdx.win." + id, JSON.stringify(rect)); } catch (_) {}
}
function loadRect(id) {
  try { return JSON.parse(localStorage.getItem("kdx.win." + id) || "null"); } catch (_) { return null; }
}

function makeDraggable(el, bar, entry) {
  bar.addEventListener("pointerdown", (e) => {
    if (e.target.closest("button, input")) return;
    if (entry.maxed) return;
    e.preventDefault();
    const rect = el.getBoundingClientRect();
    const desk = desktopEl.getBoundingClientRect();
    const offX = e.clientX - rect.left;
    const offY = e.clientY - rect.top;
    const move = (ev) => {
      el.style.left = Math.min(Math.max(0, ev.clientX - desk.left - offX), desk.width - 60) + "px";
      el.style.top = Math.min(Math.max(0, ev.clientY - desk.top - offY), desk.height - 24) + "px";
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      saveRect(entry);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  });
}

function makeResizable(el, grip, entry) {
  grip.addEventListener("pointerdown", (e) => {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX, startY = e.clientY;
    const startW = el.offsetWidth, startH = el.offsetHeight;
    const move = (ev) => {
      el.style.width = Math.max(220, startW + ev.clientX - startX) + "px";
      el.style.height = Math.max(120, startH + ev.clientY - startY) + "px";
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      saveRect(entry);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  });
}

// ---- keyboard: Ctrl-W close, F1 window switcher ----

function onGlobalKey(e) {
  if (e.key === "F1") {
    e.preventDefault();
    openWindowSwitcher();
  } else if ((e.ctrlKey || e.metaKey) && (e.key === "w" || e.key === "W")) {
    const focused = [...registry.values()].find((en) => en.win && en.win.el.classList.contains("focused"));
    if (focused) { e.preventDefault(); close(focused.opts.id); }
  }
}

function openWindowSwitcher() {
  const items = [...registry.values()]
    .filter((e) => e.state !== "closed")
    .map((e) => ({ label: e.opts.title, fn: () => open(e.opts.id) }));
  if (!items.length) items.push({ label: "(no open windows)", disabled: true });
  showMenu(window.innerWidth / 2 - 90, 80, items);
}
