// Window registry: the config for every floating KDX window plus the
// per-window entry logic (which server events / UI commands each window
// handles). Every window — launcher or feature — loads index.html; the entry
// point (main.js) dispatches on the ?win= query param: "main" mounts the
// launcher, anything else calls mountFeature(id) from here.

import { inTauri, getCurrentWindow, onKdxEvent, onUi, emitUi } from "../bridge.js";
import { register } from "../wm.js";
import { update, updateTransfer } from "../store.js";
import { mountChrome } from "../chrome.js";
import { applySettings, loadSettings } from "./settings.js";

import { buildConnect } from "./connect.js";
import { buildChat } from "./chat.js";
import { buildFiles } from "./files.js";
import { buildTransfers } from "./transfers.js";
import { buildAddressBook } from "./addressbook.js";
import { buildSettings } from "./settings.js";
import { buildAbout } from "./about.js";
import { buildUserList } from "./userlist.js";
import { buildUserInfo } from "./userinfo.js";
import { buildMessages } from "./messages.js";
import { buildRoles } from "./roles.js";
import { buildAccounts } from "./accounts.js";
import { buildServerAdmin } from "./serveradmin.js";
import { buildServerHistory } from "./serverhistory.js";
import { buildIpRules } from "./iprules.js";
import { buildConnections } from "./connections.js";
import { buildNews } from "./news.js";
import { buildTrackers } from "./trackers.js";

// Each feature: { id, title, rect, resizable?, mount(tagRef) -> { body, initialTag? } }.
// mount() builds the module, wires its event slices, and returns the body.
// tagRef.set is assigned by the registry after the chrome mounts, so a window
// can update its titlebar tag (e.g. the chat user count) live.
// Every window is resizable; minW/minH give each one a sensible floor so its
// content never collapses. Layouts are flex-based, so any size above the
// floor works.
export const FEATURES = [
  { id: "connect", title: "Connect", rect: { x: 200, y: 24, w: 300 }, minW: 260, minH: 320, mount: mountConnect },
  { id: "chat", title: "Public Chat", rect: { x: 200, y: 24, w: 560, h: 380 }, minW: 480, minH: 260, mount: mountChat },
  { id: "files", title: "Files", rect: { x: 200, y: 430, w: 440, h: 300 }, minW: 360, minH: 240, mount: mountFiles },
  { id: "transfers", title: "File Transfers", rect: { x: 790, y: 24, w: 320, h: 360 }, minW: 280, minH: 200, mount: mountTransfers },
  { id: "addressbook", title: "Address Book", rect: { x: 200, y: 90, w: 460, h: 320 }, minW: 360, minH: 240, mount: mountAddressBook },
  { id: "settings", title: "Settings", rect: { x: 240, y: 120, w: 360 }, minW: 300, minH: 260, mount: mountSettings },
  { id: "about", title: "About KDX", rect: { x: 280, y: 150, w: 360 }, minW: 300, minH: 200, mount: mountAbout },
  { id: "userlist", title: "User List", rect: { x: 630, y: 430, w: 300, h: 320 }, minW: 260, minH: 200, mount: mountUserList },
  { id: "userinfo", title: "User Info", rect: { x: 940, y: 430, w: 280, h: 260 }, minW: 240, minH: 200, mount: mountUserInfo },
  { id: "messages", title: "Messages", rect: { x: 340, y: 120, w: 500, h: 340 }, minW: 400, minH: 240, mount: mountMessages },
  { id: "admin", title: "Administration", rect: { x: 380, y: 90, w: 520, h: 460 }, minW: 420, minH: 300, mount: mountAdmin },
  { id: "accounts", title: "Accounts", rect: { x: 420, y: 70, w: 560, h: 480 }, minW: 440, minH: 300, mount: mountAccounts },
  { id: "server", title: "Server", rect: { x: 440, y: 90, w: 460, h: 460 }, minW: 380, minH: 300, mount: mountServer },
  { id: "history", title: "Server History", rect: { x: 300, y: 80, w: 640, h: 460 }, minW: 480, minH: 300, mount: mountHistory },
  { id: "iprules", title: "IP Rules", rect: { x: 320, y: 100, w: 620, h: 440 }, minW: 460, minH: 300, mount: mountIpRules },
  { id: "connections", title: "Connections", rect: { x: 260, y: 60, w: 720, h: 460 }, minW: 560, minH: 300, mount: mountConnections },
  { id: "news", title: "Public News", rect: { x: 240, y: 60, w: 640, h: 460 }, minW: 480, minH: 300, mount: mountNews },
  { id: "trackers", title: "Trackers", rect: { x: 300, y: 120, w: 420, h: 360 }, minW: 340, minH: 240, mount: mountTrackers },
];

/** Register every feature window's config with the window manager. */
export function registerAll() {
  for (const f of FEATURES) {
    register({
      id: f.id,
      title: f.title,
      rect: f.rect,
      minW: f.minW,
      minH: f.minH,
      // Preview mode (no Tauri): build the module body inline.
      build: () => ({ body: f.mount({}).body || document.createElement("div") }),
    });
  }
}

/** Entry point for a floating feature window: mount its module + chrome. */
export function mountFeature(id) {
  applySettings(loadSettings());
  const f = FEATURES.find((x) => x.id === id);
  if (!f) {
    document.body.innerHTML = `<div class="empty">unknown window: ${id}</div>`;
    return;
  }
  const tagRef = {};
  const api = f.mount(tagRef);
  const chrome = mountChrome(document.getElementById("desktop"), {
    title: f.title,
    initialTag: api.initialTag,
    body: api.body,
  });
  tagRef.set = chrome.setTag;
}

// ---- per-window entry logic ----

function mountConnect(tagRef) {
  const api = buildConnect();
  onKdxEvent((ev) => {
    if (ev.type === "disconnected") update({ connection: "offline", session: null });
  });
  onUi((msg) => {
    if (msg.to !== "connect" && msg.to !== "*") return;
    if (msg.action === "fill") api.fill(msg);
    else if (msg.action === "submit") api.submit();
  });
  return { body: api.body };
}

function mountChat(tagRef) {
  const api = buildChat();
  onKdxEvent((ev) => {
    switch (ev.type) {
      case "chat":
        api.onChat(ev);
        break;
      case "user_list":
        api.onUsers(ev.users);
        update({ users: ev.users });
        if (tagRef.set) tagRef.set(userCountTag(ev.users.length));
        break;
      case "topic":
        api.onTopic(ev.topic);
        break;
      case "chat_invited":
        api.onInvited(ev);
        break;
      case "server_warning":
        api.onWarning(ev.text);
        break;
      case "server_error":
        api.onError(ev.text);
        break;
      case "server_info":
        api.onChat({ sender: "", text: ev.text, timestamp: Date.now() / 1000, flags: 2 });
        break;
      case "disconnected":
        update({ connection: "offline", session: null, users: [], topic: "" });
        break;
    }
  });
  onUi((msg) => {
    if (msg.to !== "chat" && msg.to !== "*") return;
    if (msg.action === "session") update({ connection: "online", session: msg.session, server: msg.server });
  });
  return { body: api.body, initialTag: userCountTag(0) };
}

function userCountTag(n) {
  return `${n} user${n === 1 ? "" : "s"}`;
}

function mountFiles(tagRef) {
  const api = buildFiles();
  onKdxEvent((ev) => {
    if (ev.type === "transfer_complete" && (ev.direction === "upload" || ev.direction === "download")) {
      api.refresh();
    }
  });
  return { body: api.body };
}

function mountTransfers(tagRef) {
  const api = buildTransfers();
  onKdxEvent((ev) => {
    if (ev.type === "transfer_progress") {
      api.onProgress(ev);
      updateTransfer(ev.id, { done: ev.done, total: ev.total });
    } else if (ev.type === "transfer_complete") {
      api.onComplete(ev);
      updateTransfer(ev.id, { status: ev.status });
    }
  });
  return { body: api.body };
}

function mountAddressBook(tagRef) {
  const api = buildAddressBook();
  return { body: api.body };
}

function mountSettings(tagRef) {
  const api = buildSettings();
  return { body: api.body };
}

function mountAbout(tagRef) {
  const api = buildAbout();
  return { body: api.body };
}

function mountUserList(tagRef) {
  const api = buildUserList();
  onKdxEvent((ev) => {
    if (ev.type === "presence") {
      api.onPresence(ev.user, ev.online);
      update({ presenceCount: api.count });
    } else if (ev.type === "disconnected") {
      update({ connection: "offline", session: null });
    }
  });
  api.refresh();
  return { body: api.body };
}

function mountUserInfo(tagRef) {
  const api = buildUserInfo();
  onUi((msg) => {
    if (msg.to !== "userinfo" && msg.to !== "*") return;
    if (msg.action === "show") api.show(msg.user);
  });
  return { body: api.body };
}

function mountMessages(tagRef) {
  const api = buildMessages();
  onKdxEvent((ev) => {
    if (ev.type === "private_message") {
      api.onMessage(ev);
      emitUi("main", "set-led", { unread: api.unread });
    } else if (ev.type === "disconnected") {
      update({ connection: "offline", session: null });
    }
  });
  onUi((msg) => {
    if (msg.to !== "messages" && msg.to !== "*") return;
    if (msg.action === "open-with") api.openWith(msg.user);
    else if (msg.action === "session") update({ connection: "online", session: msg.session, server: msg.server });
  });
  return { body: api.body };
}

function mountAdmin(tagRef) {
  const api = buildRoles();
  onUi((msg) => {
    if (msg.to !== "admin" && msg.to !== "*") return;
    if (msg.action === "open-disconnect") api.openDisconnect(msg.user);
  });
  api.refresh();
  return { body: api.body };
}

function mountAccounts(tagRef) {
  const api = buildAccounts();
  api.refresh();
  return { body: api.body };
}

function mountServer(tagRef) {
  const api = buildServerAdmin();
  api.refresh();
  return { body: api.body };
}

function mountHistory(tagRef) {
  const api = buildServerHistory();
  api.refresh();
  return { body: api.body };
}

function mountIpRules(tagRef) {
  const api = buildIpRules();
  api.refresh();
  return { body: api.body };
}

function mountConnections(tagRef) {
  const api = buildConnections();
  api.start();
  if (inTauri) {
    getCurrentWindow().onCloseRequested(() => api.stop());
  }
  return { body: api.body };
}

function mountNews(tagRef) {
  const api = buildNews();
  onUi((msg) => {
    if (msg.to !== "news" && msg.to !== "*") return;
    if (msg.action === "session") update({ connection: "online", session: msg.session, server: msg.server });
  });
  api.refresh();
  return { body: api.body };
}

function mountTrackers(tagRef) {
  const api = buildTrackers();
  api.refresh();
  return { body: api.body };
}
