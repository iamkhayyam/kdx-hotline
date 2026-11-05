// Transfers window: one card per transfer with a live chunk-bitmap grid.
//
// The server chooses a transfer's chunk count, so the grid is capped: the
// Rust forwarder sends at most MAX_CELLS `buckets` (0 = no chunk done,
// 1 = some, 2 = all), cells are created once per card, and an update only
// touches cells whose state changed.

export const MAX_CELLS = 1024;
const CELL_CLASS = ["", "part", "on"];

/** Cell states for a progress event: its `buckets`, or (older backends)
 * its raw LSB-first `bitmap` downsampled here to at most MAX_CELLS. */
export function cellsFor(ev) {
  if (Array.isArray(ev.buckets)) {
    return ev.buckets.slice(0, MAX_CELLS).map((b) => (b === 1 || b === 2 ? b : 0));
  }
  const total = Math.max(0, Math.min(Number(ev.total) || 0, 0xffffffff));
  const bitmap = Array.isArray(ev.bitmap) ? ev.bitmap : [];
  const cells = Math.min(total, MAX_CELLS);
  const haveBits = bitmap.length * 8;
  const out = new Array(cells);
  for (let c = 0; c < cells; c++) {
    const start = Math.floor((c * total) / cells);
    const end = Math.max(start + 1, Math.floor(((c + 1) * total) / cells));
    let done = 0;
    for (let i = start; i < Math.min(end, haveBits); i++) done += (bitmap[i >> 3] >> (i & 7)) & 1;
    out[c] = done === 0 ? 0 : done === end - start ? 2 : 1;
  }
  return out;
}

export function buildTransfers() {
  const body = document.createElement("div");
  body.className = "win-body grow";
  body.innerHTML = '<div class="empty">no transfers</div>';
  const cards = new Map();

  function ensureCard(id) {
    const empty = body.querySelector(".empty");
    if (empty) empty.remove();
    let card = cards.get(id);
    if (!card) {
      const el = document.createElement("div");
      el.className = "xfer";
      el.innerHTML =
        '<div class="row1"><span class="name"></span><span class="stat"></span></div>' +
        '<div class="bitmap"></div>' +
        '<div class="row2"><span class="lbl"></span><span class="pct"></span></div>';
      body.prepend(el);
      card = {
        el,
        name: el.querySelector(".name"),
        stat: el.querySelector(".stat"),
        bitmap: el.querySelector(".bitmap"),
        lbl: el.querySelector(".lbl"),
        pct: el.querySelector(".pct"),
        states: [],
      };
      cards.set(id, card);
    }
    return card;
  }

  function renderCells(card, cells) {
    const kids = card.bitmap.children;
    if (card.states.length !== cells.length) {
      card.bitmap.textContent = "";
      const cols = Math.min(32, Math.max(8, cells.length));
      // CSSOM, not markup: allowed under the CSP's style-src 'self'.
      card.bitmap.style.gridTemplateColumns = `repeat(${cols}, 1fr)`;
      const frag = document.createDocumentFragment();
      for (let i = 0; i < cells.length; i++) frag.appendChild(document.createElement("i"));
      card.bitmap.appendChild(frag);
      card.states = new Array(cells.length).fill(-1);
    }
    for (let i = 0; i < cells.length; i++) {
      if (card.states[i] !== cells[i]) {
        card.states[i] = cells[i];
        kids[i].className = CELL_CLASS[cells[i]];
      }
    }
  }

  return {
    body,
    onProgress(ev) {
      const card = ensureCard(ev.id);
      const arrow = ev.direction === "download" ? "↓" : "↑";
      card.name.textContent = `${arrow} ${shortId(ev.id)}`;
      card.stat.textContent = ev.total ? Math.floor((ev.done / ev.total) * 100) + "%" : "—";
      card.lbl.textContent = `${ev.done}/${ev.total} chunks`;
      card.pct.textContent = ev.direction;
      renderCells(card, cellsFor(ev));
    },
    onComplete(ev) {
      const card = ensureCard(ev.id);
      card.el.classList.add("done");
      const verified = ev.status === 0;
      card.stat.textContent = verified ? "100%" : "failed";
      card.lbl.textContent = verified ? "verified ✓" : ev.message;
    },
  };
}

function shortId(id) {
  return String(id).slice(0, 8);
}
