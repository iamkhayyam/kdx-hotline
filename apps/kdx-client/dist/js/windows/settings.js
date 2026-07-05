// Settings — client preferences, persisted to localStorage and applied live.
// Panels mirror KDX (Identity / General / Appearance), pared to what the
// client actually supports today.

const KEY = "kdx.settings";

const THEMES = {
  "blood-red": { name: "Blood Red (default)", green: "#3df56e", alert: "#e11b1b", chrome: "#7a0a0a" },
  tron: { name: "TRON", green: "#7ff9ff", alert: "#00b4d8", chrome: "#0a4a5a" },
  amber: { name: "Amber CRT", green: "#ffb000", alert: "#ff6a00", chrome: "#5a3a0a" },
  matrix: { name: "Matrix Ice", green: "#5cff9e", alert: "#1e9e57", chrome: "#0a3a1e" },
};

export function defaults() {
  return { theme: "blood-red", timestamps: true, name: "", description: "" };
}
export function loadSettings() {
  try {
    return { ...defaults(), ...JSON.parse(localStorage.getItem(KEY) || "{}") };
  } catch (_) {
    return defaults();
  }
}
function saveSettings(s) {
  try {
    localStorage.setItem(KEY, JSON.stringify(s));
  } catch (_) {}
}

/** Apply a theme by overriding the accent CSS variables. */
export function applyTheme(id) {
  const t = THEMES[id] || THEMES["blood-red"];
  const r = document.documentElement.style;
  r.setProperty("--green", t.green);
  r.setProperty("--alert", t.alert);
  r.setProperty("--chrome", t.chrome);
}

export function applySettings(s) {
  applyTheme(s.theme);
  document.body.classList.toggle("no-timestamps", !s.timestamps);
}

export function buildSettings() {
  const body = document.createElement("div");
  body.className = "settings";
  const s = loadSettings();

  const themeOpts = Object.entries(THEMES)
    .map(([id, t]) => `<option value="${id}"${id === s.theme ? " selected" : ""}>${t.name}</option>`)
    .join("");

  body.innerHTML = `
    <div class="set-panel">
      <h3>Appearance</h3>
      <label class="set-row">Theme <select id="set-theme">${themeOpts}</select></label>
      <label class="set-row"><input type="checkbox" id="set-ts"${s.timestamps ? " checked" : ""}/> Show timestamps in chat</label>
    </div>
    <div class="set-panel">
      <h3>Identity</h3>
      <label class="set-row">Name <input id="set-name" value="${esc(s.name)}" spellcheck="false" placeholder="display name"/></label>
      <label class="set-row">Description <input id="set-desc" value="${esc(s.description)}" spellcheck="false" placeholder="e.g. just visiting"/></label>
    </div>
    <div class="set-actions">
      <button class="btn" id="set-save">Save</button>
      <span class="set-status" id="set-status"></span>
    </div>
  `;

  const $ = (x) => body.querySelector(x);

  // Live theme preview on change.
  $("#set-theme").addEventListener("change", (e) => applyTheme(e.target.value));

  $("#set-save").addEventListener("click", () => {
    const next = {
      theme: $("#set-theme").value,
      timestamps: $("#set-ts").checked,
      name: $("#set-name").value.trim(),
      description: $("#set-desc").value.trim(),
    };
    saveSettings(next);
    applySettings(next);
    $("#set-status").textContent = "saved";
    setTimeout(() => ($("#set-status").textContent = ""), 1500);
  });

  return { body };
}

function esc(s) {
  return String(s || "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
}
