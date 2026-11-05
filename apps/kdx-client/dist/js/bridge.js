// Thin wrapper over the Tauri global API. Degrades to a no-op stub when
// loaded in a plain browser (e.g. a design preview), so the UI still renders.
//
// In the native client every KDX "window" is a real Tauri window (see wm.js).
// Windows talk to each other over the "kdx-ui" event channel:
//   emitUi(to, action, payload)  ->  { to: <label|"*">, action, ...payload }
// "kdx" carries server events from the Rust forwarder; "kdx-ui" carries
// window-to-window UI commands.
//
// Local file paths never pass through here: upload/download open the native
// dialogs on the Rust side.

import { createKdxFilter } from "./eventfilter.js";

const tauri = window.__TAURI__;
export const inTauri = !!tauri;

// Listener registrations in flight; a window announces "ready" only once
// they have all landed (see listenersReady).
const pendingListens = [];

export async function invoke(cmd, args) {
  if (!inTauri) {
    console.warn(`[preview] invoke ${cmd}`, args);
    throw { kind: "message", message: "Tauri backend unavailable (preview mode)" };
  }
  return tauri.core.invoke(cmd, args);
}

/** Which window this document is running in ("main" = the launcher). */
export function windowLabel() {
  return new URLSearchParams(location.search).get("win") || "main";
}

/** The current native window handle (undefined in preview mode). */
export function getCurrentWindow() {
  return inTauri ? tauri.window.getCurrentWindow() : undefined;
}

/** Look up an existing native window by label, or undefined if it doesn't
 * exist yet. Note: `getByLabel` returns a lazy handle even for labels that
 * were never created, so existence is checked against `getAll()` first. */
export async function getWindow(label) {
  if (!inTauri) return undefined;
  const all = await tauri.webviewWindow.WebviewWindow.getAll();
  return all.find((w) => w.label === label) || undefined;
}

/** Create a native window; resolves to the new WebviewWindow. */
export async function newWindow(label, opts) {
  return new tauri.webviewWindow.WebviewWindow(label, opts);
}

// ---- server events ("kdx") ----

const kdxFilter = createKdxFilter();
const kdxHandlers = new Set();
let kdxListen = null;
let held = null; // array while events are held (window still hydrating)

function applyKdx(ev) {
  if (!kdxFilter.accept(ev)) return;
  for (const h of [...kdxHandlers]) {
    try {
      h(ev);
    } catch (e) {
      console.error("kdx handler failed", e);
    }
  }
}

function dispatchKdx(ev) {
  if (held) {
    if (held.length < 2000) held.push(ev);
    return;
  }
  applyKdx(ev);
}

/** Subscribe to server events for this window. One Tauri listener per
 * window fans out to every handler, so stale-connection and duplicate
 * filtering (eventfilter.js) happens once per event. The listener targets
 * this window's label, so events the forwarder sends only to particular
 * windows (transfer progress) don't reach the others. Returns a promise of
 * an unlisten function. */
export function onKdxEvent(handler) {
  kdxHandlers.add(handler);
  if (!kdxListen) {
    kdxListen = inTauri
      ? tauri.event.listen("kdx", (e) => dispatchKdx(e.payload), { target: windowLabel() })
      : Promise.resolve(() => {});
    pendingListens.push(kdxListen);
  }
  return kdxListen.then(() => () => kdxHandlers.delete(handler));
}

/** Apply an event the launcher queued for us while we were opening. */
export function replayKdxEvent(ev) {
  dispatchKdx(ev);
}

/** Learn the current connection generation (from connect / get_session /
 * a session broadcast); events from older connections are then dropped. */
export function noteGeneration(gen) {
  kdxFilter.setGeneration(gen);
}
export function currentGeneration() {
  return kdxFilter.generation;
}

/** Buffer incoming server events (until releaseKdxEvents), so a window
 * applies none before it knows the session. */
export function holdKdxEvents() {
  if (!held) held = [];
}
export function releaseKdxEvents() {
  const q = held || [];
  held = null;
  for (const ev of q) applyKdx(ev);
}

// ---- window-to-window UI commands ("kdx-ui") ----

/** Send a UI command to another window ("*" broadcasts to all). */
export async function emitUi(to, action, payload) {
  if (!inTauri) return;
  return tauri.event.emit("kdx-ui", { to, action, ...(payload || {}) });
}

/** Subscribe to UI commands (handlers filter on msg.to). Returns unlisten. */
export async function onUi(handler) {
  if (!inTauri) return () => {};
  const p = tauri.event.listen("kdx-ui", (e) => handler(e.payload));
  pendingListens.push(p);
  return p;
}

/** Open `target` (via the launcher) and hand it a UI command once its
 * listeners are up — commands sent to a window that is still opening would
 * otherwise be lost. */
export function deliver(target, cmd, args) {
  return emitUi("main", "deliver", { target, cmd, args: args || {} });
}

/** Resolves once every listener registered so far is active. */
export function listenersReady() {
  return Promise.allSettled(pendingListens).then(() => {});
}

/** Logical-size / logical-position constructors (the dpi module lives under
 * window.__TAURI__, which isn't in scope inside window modules). */
export function logicalSize(w, h) {
  return new tauri.dpi.LogicalSize(w, h);
}
export function logicalPosition(x, y) {
  return new tauri.dpi.LogicalPosition(x, y);
}
