// C-1: destructive actions ask in the page (confirm.js), never through
// window.confirm — which tauri-plugin-dialog replaces with an async
// function, so `if (!confirm(..)) return;` always went ahead.
import { test } from "node:test";
import assert from "node:assert/strict";

// ---- a minimal DOM: just what confirm.js touches ----
class FakeEl {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.parent = null;
    this.listeners = {};
    this.attrs = {};
    this.className = "";
    this.textContent = "";
  }
  setAttribute(k, v) {
    this.attrs[k] = String(v);
  }
  appendChild(child) {
    child.parent = this;
    this.children.push(child);
    return child;
  }
  remove() {
    if (!this.parent) return;
    this.parent.children = this.parent.children.filter((c) => c !== this);
    this.parent = null;
  }
  addEventListener(type, fn) {
    (this.listeners[type] ||= []).push(fn);
  }
  focus() {
    doc.activeElement = this;
  }
  click() {
    for (const fn of this.listeners.click || []) fn({ target: this });
  }
  find(cls) {
    if (this.className.split(" ").includes(cls)) return this;
    for (const c of this.children) {
      const hit = c.find(cls);
      if (hit) return hit;
    }
    return null;
  }
}
const doc = {
  activeElement: null,
  keyListeners: new Set(),
  createElement: (tag) => new FakeEl(tag),
  addEventListener(type, fn) {
    if (type === "keydown") this.keyListeners.add(fn);
  },
  removeEventListener(type, fn) {
    if (type === "keydown") this.keyListeners.delete(fn);
  },
  key(key) {
    for (const fn of [...this.keyListeners]) fn({ key, preventDefault() {}, stopPropagation() {} });
  },
};
globalThis.document = doc;

const { askConfirm, confirmThen } = await import("../dist/js/confirm.js");

/** A fake `invoke` that records every command. */
function spyInvoke() {
  const calls = [];
  const invoke = async (cmd, args) => {
    calls.push({ cmd, args });
    return { entries: [] };
  };
  return { calls, invoke };
}

/** Start "delete folder" the way files.js does; returns the pending run. */
function deleteFolder(host, invoke) {
  return confirmThen(
    () => askConfirm("Delete folder “x” and everything in it?", { confirmLabel: "Delete", danger: true, host }),
    () => invoke("delete_path", { path: "/x" })
  );
}

test("declining the in-page confirmation performs no invoke", async () => {
  const host = new FakeEl("body");
  const { calls, invoke } = spyInvoke();
  const run = deleteFolder(host, invoke);
  const overlay = host.find("confirm-overlay");
  assert.ok(overlay, "the question is shown");
  assert.equal(doc.activeElement, overlay.find("confirm-cancel"), "Cancel has the focus");
  overlay.find("confirm-cancel").click();
  assert.equal(await run, false);
  assert.deepEqual(calls, []);
  assert.equal(host.children.length, 0, "the overlay is gone");
  assert.equal(doc.keyListeners.size, 0, "no listener left behind");
});

test("Escape and a click beside the box decline too", async () => {
  const { calls, invoke } = spyInvoke();
  let host = new FakeEl("body");
  let run = deleteFolder(host, invoke);
  doc.key("Escape");
  assert.equal(await run, false);

  host = new FakeEl("body");
  run = deleteFolder(host, invoke);
  host.find("confirm-overlay").click(); // the backdrop itself
  assert.equal(await run, false);
  assert.deepEqual(calls, []);
});

test("confirming runs the action exactly once", async () => {
  const host = new FakeEl("body");
  const { calls, invoke } = spyInvoke();
  const run = deleteFolder(host, invoke);
  const ok = host.find("confirm-ok");
  ok.click();
  ok.click(); // a double click doesn't run it twice
  assert.equal(await run, true);
  assert.deepEqual(calls, [{ cmd: "delete_path", args: { path: "/x" } }]);
});

test("the question is text, never markup", async () => {
  const host = new FakeEl("body");
  const run = askConfirm('<img src=x onerror="boom()">', { host });
  assert.equal(host.find("confirm-text").textContent, '<img src=x onerror="boom()">');
  host.find("confirm-cancel").click();
  assert.equal(await run, false);
});

test("an async window.confirm (the dialog plugin's) can't approve anything", async () => {
  const { calls, invoke } = spyInvoke();
  const pluginConfirm = async () => false; // what the plugin installs
  // The old pattern went ahead: a Promise is truthy.
  if (!pluginConfirm("Delete?")) assert.fail("unreachable");
  else await invoke("delete_path", { path: "/old-pattern" });
  assert.equal(calls.length, 1, "the bug: the old pattern deleted");

  calls.length = 0;
  assert.equal(await confirmThen(() => pluginConfirm("Delete?"), () => invoke("delete_path")), false);
  // Only exactly `true` counts: not a stray Promise, object or string.
  assert.equal(await confirmThen(() => Promise.resolve({}), () => invoke("delete_path")), false);
  assert.equal(await confirmThen(() => ({ then: undefined }), () => invoke("delete_path")), false);
  assert.equal(await confirmThen(() => "yes", () => invoke("delete_path")), false);
  assert.equal(
    await confirmThen(async () => {
      throw new Error("dialog permission denied");
    }, () => invoke("delete_path")),
    false
  );
  assert.deepEqual(calls, []);
});
