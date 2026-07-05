// Transfers window: one card per transfer with a live chunk-bitmap grid.

export function buildTransfers() {
  const body = document.createElement("div");
  body.style.flex = "1";
  body.className = "win-body";
  body.innerHTML = '<div class="empty">no transfers</div>';
  const cards = new Map();

  function ensureCard(id) {
    if (body.querySelector(".empty")) body.innerHTML = "";
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
        cells: 0,
      };
      cards.set(id, card);
    }
    return card;
  }

  function renderBitmap(card, total, bytes) {
    if (card.cells !== total) {
      card.bitmap.innerHTML = "";
      const cols = Math.min(32, Math.max(8, total));
      card.bitmap.style.gridTemplateColumns = `repeat(${cols}, 1fr)`;
      for (let i = 0; i < total; i++) card.bitmap.appendChild(document.createElement("i"));
      card.cells = total;
    }
    const kids = card.bitmap.children;
    for (let i = 0; i < total; i++) {
      const on = (bytes[i >> 3] >> (i & 7)) & 1;
      kids[i].className = on ? "on" : "";
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
      renderBitmap(card, ev.total, ev.bitmap || []);
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
  return id.slice(0, 8);
}
