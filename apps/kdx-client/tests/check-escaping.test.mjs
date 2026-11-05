import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { checkSource } from "../scripts/check-escaping.mjs";

const rules = (src) => checkSource(src).map((f) => f.rule);

test("flags the audit's unescaped sinks", () => {
  // roles.js:108 before the fix
  assert.ok(rules("el.innerHTML = `<div class=\"empty\">${err.message || err}</div>`;").includes("unescaped"));
  // chat line() fed raw text
  assert.ok(rules("div.innerHTML = `<span class=\"ts\">${ts}</span>${text}`;").includes("unescaped"));
  // attribute context
  assert.ok(rules('tr.innerHTML = `<button data-host="${s.host}">x</button>`;').includes("unescaped"));
  // concatenation
  assert.ok(rules("el.innerHTML = '<b>' + name + '</b>';").includes("concat"));
  // innerHTML from a variable / +=
  assert.ok(rules("el.innerHTML = html;").includes("innerHTML"));
  assert.ok(rules("el.innerHTML += `<i>${esc(x)}</i>`;").includes("sink"));
  assert.ok(rules("el.insertAdjacentHTML('beforeend', x);").includes("sink"));
  // unescaped value hidden in a nested template / ternary
  assert.ok(rules("el.innerHTML = `<b>${ok ? `x ${name}` : \"\"}</b>`;").includes("unescaped"));
});

test("flags inline style and handlers (CSP)", () => {
  assert.ok(rules('el.innerHTML = `<span style="background:${esc(c)}"></span>`;').includes("inline-style"));
  assert.ok(rules("t.innerHTML = \"<th style='text-align:right'>Size</th>\";").includes("inline-style"));
  assert.ok(rules('el.innerHTML = "<img src=x onerror=alert(1)>";').includes("inline-handler"));
  assert.ok(rules('el.setAttribute("style", "color:red");').includes("inline-style"));
});

test("accepts escaped, numeric and trusted-helper interpolations", () => {
  const ok = [
    "el.innerHTML = `<div>${esc(err.message)}</div>`;",
    "el.innerHTML = `<td>${num(r.rank)}</td>` + `<td>${esc(r.name)}</td>`;",
    "el.innerHTML = `<select>${classOptionsHtml(0)}</select>`;",
    'el.innerHTML = `<h3>${changed ? "key changed" : \'<span class="w">new</span>\'}</h3>`;',
    "el.innerHTML = list.map((p) => `<i>${esc(p)}</i>`).join(\"\");",
    "el.innerHTML = \"\";",
    "const re = /[&<>]/g; const half = a / b; el.textContent = `${raw}`;",
    "el.style.background = color;",
  ];
  for (const src of ok) assert.deepEqual(checkSource(src), [], src);
});

test("the shipped webview passes", () => {
  const script = fileURLToPath(new URL("../scripts/check-escaping.mjs", import.meta.url));
  const out = execFileSync(process.execPath, [script], { encoding: "utf8" });
  assert.match(out, /0 findings/);
});
