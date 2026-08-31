// KDX window manager — NATIVE windows.
//
// Every KDX "window" is a real macOS/Tauri window that floats anywhere on the
// desktop and minimizes to the OS Dock. This module is the facade: it knows
// each window's config, creates/hides/focuses the native windows, tracks which
// are open (for the launcher's buttons), and persists geometry in
// localStorage (shared across the app's windows).
//
// Windows announce their own lifecycle over the "kdx-ui" channel so the
// launcher stays in sync even when a window is closed from its own chrome.
// In a plain browser (preview mode) `open()` falls back to stacking the
// content in-page so the UI can still be designed without Tauri.

import { getWindow, newWindow, inTauri, emitUi, onUi } from "./bridge.js";
import { mountChrome } from "./chrome.js";

const registry = new Map(); // id -> { id, title, rect, resizable, build? }
const openWindows = new Set(); // ids currently open (this window's view)
const changeListeners = new Set();
let desktopEl = null;

/** state: "open" | "closed" (native windows are open until closed) */

export function initDesktop(el) {
  desktopEl = el;
  if (!inTauri) return;
  onUi((msg) => {
    if (msg.to !== "main" && msg.to !== "*") return;
    if (msg.action === "window-opened") {
      openWindows.add(msg.label);
    } else if (msg.action === "window-closed") {
      openWindows.delete(msg.label);
      emitChange();
    }
  });
}

/** Register a feature window's config (title, default rect, resizable). */
export function register(opts) {
  registry.set(opts.id, opts);
}

export function isRegistered(id) {
  return registry.has(id);
}
export function isOpen(id) {
  return openWindows.has(id);
}
export function getState(id) {
  return openWindows.has(id) ? "open" : "closed";
}

/** Notify the launcher when any window opens/closes. */
export function onChange(fn) {
  changeListeners.add(fn);
  return () => changeListeners.delete(fn);
}
function emitChange() {
  for (const fn of changeListeners) fn();
}

/** Open (creating if needed), restore if minimized, and focus. */
export async function open(id) {
  const opts = registry.get(id);
  if (!opts) return;
  if (isOpen(id)) return focus(id);
  if (!inTauri) return previewOpen(opts);

  let w = await getWindow(id);
  if (w) {
    try { await w.unminimize(); } catch (_) {}
    try { await w.show(); } catch (_) {}
    try { await w.setFocus(); } catch (_) {}
  } else {
    const saved = loadRect(id);
    const rect = saved || opts.rect;
    const ww = saved ? saved.w : opts.rect.w;
    const hh = saved ? saved.h : opts.rect.h;
    const width = ww || 420;
    const height = hh || 320;
    w = await newWindow(id, {
      url: "index.html?win=" + id,
      title: opts.title,
      width,
      height,
      x: clampX(rect.x, width),
      y: clampY(rect.y, height),
      minWidth: opts.minW || 220,
      minHeight: opts.minH || 120,
      resizable: true,
      decorations: false,
      shadow: true,
    });
    emitUi("main", "window-opened", { label: id });
  }
  openWindows.add(id);
  emitChange();
  opts.onOpen && opts.onOpen();
  return w;
}

/** Toggle from a launcher button: open if closed/minimized, else focus. */
export function toggle(id) {
  return isOpen(id) ? focus(id) : open(id);
}

export async function close(id) {
  const w = await getWindow(id);
  if (!w) return;
  try { await w.close(); } catch (_) {}
}

/** Hide a window (it stays alive; the launcher's Windows menu restores it). */
export async function hide(id) {
  const w = await getWindow(id);
  if (!w) return;
  try {
    await w.hide();
    emitUi("main", "window-hidden", { label: id });
  } catch (_) {}
}

/** Show a previously hidden window and focus it. */
export async function show(id) {
  const w = await getWindow(id);
  if (!w) return;
  try {
    await w.show();
    await w.setFocus();
    emitUi("main", "window-shown", { label: id });
  } catch (_) {}
}

export async function focus(id) {
  const w = await getWindow(id);
  if (!w) return;
  try { await w.unminimize(); } catch (_) {}
  try { await w.setFocus(); } catch (_) {}
}

// ---- preview mode: stack windows in-page (no Tauri) ----

function previewOpen(opts) {
  if (!desktopEl) return;
  const built = opts.build ? opts.build() : {};
  const body = built.body || document.createElement("div");
  mountChrome(desktopEl, { title: opts.title, body });
  openWindows.add(opts.id);
  emitChange();
  opts.onOpen && opts.onOpen();
}

// ---- geometry ----

function clampX(x, w) {
  const avail = (screen.availWidth || 1280) - w;
  return Math.min(Math.max(0, x || 20), Math.max(0, avail));
}
function clampY(y, h) {
  const avail = (screen.availHeight || 800) - h;
  return Math.min(Math.max(0, y || 20), Math.max(0, avail));
}
function loadRect(id) {
  try {
    const r = JSON.parse(localStorage.getItem("kdx.win." + id) || "null");
    // Defensive: reject corrupt / off-scale saved geometry. A saved window
    // must fit on one screen and be a sane size (guards against stale
    // physical-pixel values from older builds doubling on every restart).
    const maxW = Math.max(1600, screen.availWidth || 1280);
    const maxH = Math.max(1200, screen.availHeight || 800);
    if (
      r &&
      typeof r.w === "number" && r.w >= 160 && r.w <= maxW &&
      typeof r.h === "number" && r.h >= 120 && r.h <= maxH &&
      typeof r.x === "number" && Math.abs(r.x) <= 8000 &&
      typeof r.y === "number" && Math.abs(r.y) <= 8000
    ) {
      return r;
    }
  } catch (_) {}
  return null;
}
