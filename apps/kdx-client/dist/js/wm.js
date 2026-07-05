// Minimal in-webview window manager: draggable, focusable panels inside the
// single OS window, preserving the KDX desktop aesthetic.

let zTop = 10;
const windows = new Map();

/**
 * Create a window. `opts`: { id, title, tag?, x, y, width, height, body }.
 * `body` is an HTMLElement. Returns { el, body, setTag }.
 */
export function createWindow(desktop, opts) {
  const el = document.createElement("section");
  el.className = "win";
  el.style.left = opts.x + "px";
  el.style.top = opts.y + "px";
  el.style.width = opts.width + "px";
  if (opts.height) el.style.height = opts.height + "px";
  el.dataset.id = opts.id;

  const bar = document.createElement("div");
  bar.className = "titlebar";
  bar.innerHTML =
    '<div class="lights"><span></span><span></span></div>' +
    `<h2>${opts.title}</h2>` +
    `<span class="tag"></span>`;
  const tagEl = bar.querySelector(".tag");
  if (opts.tag) tagEl.textContent = opts.tag;

  const bodyWrap = document.createElement("div");
  bodyWrap.className = "win-body";
  bodyWrap.style.display = "flex";
  bodyWrap.style.flexDirection = "column";
  bodyWrap.appendChild(opts.body);

  el.appendChild(bar);
  el.appendChild(bodyWrap);
  desktop.appendChild(el);

  const focus = () => {
    for (const w of windows.values()) w.el.classList.remove("focused");
    el.classList.add("focused");
    el.style.zIndex = ++zTop;
  };
  el.addEventListener("pointerdown", focus);

  makeDraggable(el, bar, desktop);

  const handle = { el, body: opts.body, focus, setTag: (t) => (tagEl.textContent = t) };
  windows.set(opts.id, handle);
  return handle;
}

export function getWindow(id) {
  return windows.get(id);
}

function makeDraggable(el, bar, desktop) {
  bar.addEventListener("pointerdown", (e) => {
    if (e.target.closest("button, input")) return;
    e.preventDefault();
    const rect = el.getBoundingClientRect();
    const deskRect = desktop.getBoundingClientRect();
    const offX = e.clientX - rect.left;
    const offY = e.clientY - rect.top;
    const move = (ev) => {
      const x = Math.min(
        Math.max(0, ev.clientX - deskRect.left - offX),
        deskRect.width - 60
      );
      const y = Math.min(
        Math.max(0, ev.clientY - deskRect.top - offY),
        deskRect.height - 30
      );
      el.style.left = x + "px";
      el.style.top = y + "px";
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  });
}
