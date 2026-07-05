// Floating popup menus — the primary verb surface in KDX (Window Menu and
// list-row context menus both use this). Single-instance: opening one closes
// any other.

let openMenu = null;

/**
 * Show a popup menu at viewport coords (x, y).
 * `items`: array of { label, fn?, disabled?, checked?, separator? }.
 * Returns nothing; the menu closes on selection, outside click, or Escape.
 */
export function showMenu(x, y, items) {
  closeMenu();
  const menu = document.createElement("div");
  menu.className = "popup-menu";

  for (const item of items) {
    if (item.separator) {
      const sep = document.createElement("div");
      sep.className = "popup-sep";
      menu.appendChild(sep);
      continue;
    }
    const row = document.createElement("div");
    row.className = "popup-item" + (item.disabled ? " disabled" : "");
    if (item.checked) row.classList.add("checked");
    row.textContent = item.label;
    if (!item.disabled) {
      row.addEventListener("click", (e) => {
        e.stopPropagation();
        closeMenu();
        item.fn && item.fn();
      });
    }
    menu.appendChild(row);
  }

  document.body.appendChild(menu);
  // Keep it on-screen.
  const r = menu.getBoundingClientRect();
  const vw = window.innerWidth, vh = window.innerHeight;
  if (x + r.width > vw) x = Math.max(0, vw - r.width - 4);
  if (y + r.height > vh) y = Math.max(0, vh - r.height - 4);
  menu.style.left = x + "px";
  menu.style.top = y + "px";

  openMenu = menu;
  // Defer the outside-click listener so the opening click doesn't close it.
  setTimeout(() => {
    window.addEventListener("pointerdown", onOutside, true);
    window.addEventListener("keydown", onKey, true);
  }, 0);
}

export function closeMenu() {
  if (!openMenu) return;
  window.removeEventListener("pointerdown", onOutside, true);
  window.removeEventListener("keydown", onKey, true);
  openMenu.remove();
  openMenu = null;
}

function onOutside(e) {
  if (openMenu && !openMenu.contains(e.target)) closeMenu();
}
function onKey(e) {
  if (e.key === "Escape") {
    e.stopPropagation();
    closeMenu();
  }
}
