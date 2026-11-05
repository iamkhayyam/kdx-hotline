// The one HTML escaper. Every value interpolated into markup goes through
// esc() (text and quoted attribute values) or num() (numbers); helpers that
// return trusted markup are named …Html(). scripts/check-escaping.mjs
// enforces this for every module under dist/js. Error and server text that
// isn't part of a larger template should simply use textContent.

const ENTITIES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** Escape any value for an HTML text node or a quoted attribute value. */
export function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ENTITIES[c]);
}

/** A number for markup: finite numbers print as-is, anything else as "?". */
export function num(value) {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? String(n) : "?";
}

const HEX_COLOR = /^#(?:[0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;

/** A server-supplied CSS color, if it's a plain hex color; else `fallback`.
 * Apply the result via CSSOM (`el.style.background = …`), never markup. */
export function safeColor(value, fallback) {
  return typeof value === "string" && HEX_COLOR.test(value) ? value : fallback;
}

// C0/C1 controls plus bidi overrides/embeddings/isolates and zero-width
// characters: invisible, and able to make "exe.txt" read as "txt.exe".
const INVISIBLE = /[\u0000-\u001f\u007f-\u009f؜​-‏‪-‮⁠-⁩﻿]/g;

/** Server-chosen names (files, paths) with invisible/reordering characters
 * removed, for display. */
export function plainText(value) {
  return String(value ?? "").replace(INVISIBLE, "");
}

/** Human-readable text of a rejected invoke / thrown value. */
export function errorText(err) {
  if (err == null) return "unknown error";
  if (typeof err === "string") return err;
  if (typeof err.message === "string") return err.message;
  try {
    return JSON.stringify(err);
  } catch (_) {
    return String(err);
  }
}
