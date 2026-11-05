// node --test apps/kdx-client/tests
import { test } from "node:test";
import assert from "node:assert/strict";
import { esc, num, safeColor, plainText, errorText } from "../dist/js/html.js";

test("esc escapes all five HTML-significant characters", () => {
  assert.equal(esc(`"'<>&`), "&quot;&#39;&lt;&gt;&amp;");
  assert.equal(esc("plain"), "plain");
  assert.equal(esc(null), "");
  assert.equal(esc(undefined), "");
  assert.equal(esc(42), "42");
});

test("esc neutralises the audit payloads", () => {
  // UI-1: server error text in the Administration window.
  const meta = 'server error: <meta http-equiv="refresh" content="0;url=https://evil.example/kdx">';
  assert.ok(!esc(meta).includes("<"));
  // UI-5: attribute breakout through a tracker host.
  const host = 'x" style="position:fixed;inset:0;opacity:0';
  assert.equal(`<b title="${esc(host)}">`.split('"').length, 3, "stays inside one attribute");
});

test("num only lets finite numbers through", () => {
  assert.equal(num(10700), "10700");
  assert.equal(num("3"), "3");
  assert.equal(num("3<b>"), "?");
  assert.equal(num(NaN), "?");
  assert.equal(num(Infinity), "?");
  assert.equal(num({}), "?");
});

test("safeColor accepts plain hex colors only", () => {
  for (const ok of ["#fff", "#e11b1b", "#E11B1BAA", "#abcd"]) assert.equal(safeColor(ok, "#000"), ok);
  for (const bad of [
    "red;position:fixed;inset:0;z-index:999",
    'red" id="x',
    "url(data:image/png;base64,AAAA)",
    "#12345",
    "#ggg",
    "",
    null,
    42,
  ]) {
    assert.equal(safeColor(bad, "#6b5555"), "#6b5555", String(bad));
  }
});

test("plainText strips controls and bidi/zero-width characters", () => {
  assert.equal(plainText("invoice‮fdp.exe"), "invoicefdp.exe");
  assert.equal(plainText("a\u0000b\nc​d⁦e⁩"), "abcde");
  assert.equal(plainText("日本語 архив.zip"), "日本語 архив.zip");
});

test("errorText handles every rejection shape", () => {
  assert.equal(errorText({ kind: "message", message: "boom" }), "boom");
  assert.equal(errorText("plain"), "plain");
  assert.equal(errorText(null), "unknown error");
  assert.equal(errorText({ kind: "x" }), '{"kind":"x"}');
});
