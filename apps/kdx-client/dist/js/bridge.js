// Thin wrapper over the Tauri global API. Degrades to a no-op stub when
// loaded in a plain browser (e.g. a design preview), so the UI still renders.
//
// In the native client every KDX "window" is a real Tauri window (see wm.js).
// Windows talk to each other over the "kdx-ui" event channel:
//   emitUi(to, action, payload)  ->  { to: <label|"*">, action, ...payload }
// "kdx" carries server events (broadcast by the Rust forwarder to all
// windows); "kdx-ui" carries window-to-window UI commands.

const tauri = window.__TAURI__;
export const inTauri = !!tauri;

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

/** Subscribe to the "kdx" server-event stream. Returns an unlisten function. */
export async function onKdxEvent(handler) {
  if (!inTauri) return () => {};
  return tauri.event.listen("kdx", (e) => handler(e.payload));
}

/** Send a UI command to another window ("*" broadcasts to all). */
export async function emitUi(to, action, payload) {
  if (!inTauri) return;
  return tauri.event.emit("kdx-ui", { to, action, ...(payload || {}) });
}

/** Subscribe to UI commands addressed to this window. Returns unlisten. */
export async function onUi(handler) {
  if (!inTauri) return () => {};
  return tauri.event.listen("kdx-ui", (e) => handler(e.payload));
}

/** Logical-size / logical-position constructors (the dpi module lives under
 * window.__TAURI__, which isn't in scope inside window modules). */
export function logicalSize(w, h) {
  return new tauri.dpi.LogicalSize(w, h);
}
export function logicalPosition(x, y) {
  return new tauri.dpi.LogicalPosition(x, y);
}

/** Native open-file dialog; returns a path or null. */
export async function pickFile() {
  if (!inTauri) return null;
  return tauri.dialog.open({ multiple: false, directory: false });
}

/** Native save-file dialog; returns a path or null. */
export async function pickSave(defaultName) {
  if (!inTauri) return null;
  return tauri.dialog.save({ defaultPath: defaultName });
}
