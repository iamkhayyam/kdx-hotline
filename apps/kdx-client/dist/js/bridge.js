// Thin wrapper over the Tauri global API. Degrades to a no-op stub when
// loaded in a plain browser (e.g. a design preview), so the UI still renders.

const tauri = window.__TAURI__;
export const inTauri = !!tauri;

export async function invoke(cmd, args) {
  if (!inTauri) {
    console.warn(`[preview] invoke ${cmd}`, args);
    throw { kind: "message", message: "Tauri backend unavailable (preview mode)" };
  }
  return tauri.core.invoke(cmd, args);
}

/** Subscribe to the "kdx" event stream. Returns an unlisten function. */
export async function onKdxEvent(handler) {
  if (!inTauri) return () => {};
  return tauri.event.listen("kdx", (e) => handler(e.payload));
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
