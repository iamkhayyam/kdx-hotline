// In-page confirmation for destructive actions.
//
// Never use window.confirm / alert / prompt here: tauri-plugin-dialog's init
// script replaces them in every window with async functions, so confirm()
// returns a Promise — always truthy — and `if (!confirm(..)) return;` never
// stops anything (and the dialog permission they need isn't granted to any
// window anyway). scripts/check-escaping.mjs rejects them. Ask in the page
// instead, and show errors inline.

/**
 * Run `action` only once `ask()` has resolved to exactly `true`. A declined,
 * dismissed or failed confirmation runs nothing — nor does a truthy
 * non-boolean (such as the Promise a replaced window.confirm returns).
 * Resolves to whether `action` ran (its own errors propagate).
 */
export async function confirmThen(ask, action) {
  let answer;
  try {
    answer = await ask();
  } catch (_) {
    answer = false;
  }
  if (answer !== true) return false;
  await action();
  return true;
}

/**
 * Ask a yes/no question in a modal over this window's page. Resolves `true`
 * only when the confirm button is clicked; Cancel, Escape or a click
 * outside the box resolve `false`. Cancel has the focus, so Enter declines.
 * The question is set as text, never parsed as markup.
 *
 * opts: { confirmLabel = "OK", cancelLabel = "Cancel", danger = false,
 *         host = document.body }
 */
export function askConfirm(question, opts = {}) {
  const { confirmLabel = "OK", cancelLabel = "Cancel", danger = false } = opts;
  const host = opts.host || document.body;
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "confirm-overlay";
    const box = document.createElement("div");
    box.className = "confirm-box" + (danger ? " danger" : "");
    box.setAttribute("role", "alertdialog");
    box.setAttribute("aria-modal", "true");
    const text = document.createElement("div");
    text.className = "confirm-text";
    text.textContent = String(question ?? "");
    const actions = document.createElement("div");
    actions.className = "confirm-actions";
    const ok = document.createElement("button");
    ok.type = "button";
    ok.className = "btn confirm-ok" + (danger ? " danger" : "");
    ok.textContent = confirmLabel;
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "btn confirm-cancel";
    cancel.textContent = cancelLabel;
    actions.appendChild(ok);
    actions.appendChild(cancel);
    box.appendChild(text);
    box.appendChild(actions);
    overlay.appendChild(box);

    let settled = false;
    function onKey(e) {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        finish(false);
      }
    }
    function finish(answer) {
      if (settled) return;
      settled = true;
      document.removeEventListener("keydown", onKey, true);
      overlay.remove();
      resolve(answer);
    }
    ok.addEventListener("click", () => finish(true));
    cancel.addEventListener("click", () => finish(false));
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) finish(false);
    });
    document.addEventListener("keydown", onKey, true);
    host.appendChild(overlay);
    cancel.focus();
  });
}
