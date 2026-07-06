import { invoke, onKdxEvent } from "./bridge.js";
import { initDesktop, register, open, toggle, isOpen, onChange } from "./wm.js";
import { getState, subscribe, update, updateTransfer } from "./store.js";
import { buildButtonBar } from "./buttonbar.js";
import { buildConnect } from "./windows/connect.js";
import { buildChat } from "./windows/chat.js";
import { buildFiles } from "./windows/files.js";
import { buildTransfers } from "./windows/transfers.js";
import { buildAddressBook } from "./windows/addressbook.js";
import { buildSettings, applySettings, loadSettings } from "./windows/settings.js";
import { buildAbout } from "./windows/about.js";
import { buildUserList } from "./windows/userlist.js";
import { buildUserInfo } from "./windows/userinfo.js";
import { buildMessages } from "./windows/messages.js";
import { buildRoles } from "./windows/roles.js";

const desktop = document.getElementById("desktop");

initDesktop(desktop);
applySettings(loadSettings()); // apply saved theme/prefs at startup

// Build feature instances eagerly (cheap DOM); the window manager wraps each
// in floating chrome lazily on first open. Events route to these instances
// whether or not their window is currently open.
const chat = buildChat();
const files = buildFiles();
const transfers = buildTransfers();
const connectApi = buildConnect(onLoggedIn);
const addressbook = buildAddressBook(connectApi, () => open("connect"));
const settings = buildSettings();
const about = buildAbout();
const userInfo = buildUserInfo();
const messages = buildMessages(
  () => getState().session && getState().session.username,
  (unread) => buttonBar.setLed(unread > 0)
);
function openMessagesWith(username) {
  open("messages");
  messages.openWith(username);
}
const roles = buildRoles();
const userList = buildUserList(
  (username) => {
    open("userinfo");
    userInfo.show(username);
  },
  openMessagesWith
);

// Default window positions clear the floating Button Bar (top-left).
register({
  id: "connect",
  title: "Connect",
  rect: { x: 200, y: 24, w: 300 },
  resizable: false,
  build: () => ({ body: connectApi.body }),
});
register({
  id: "chat",
  title: "Public Chat",
  tag: "0 users",
  rect: { x: 200, y: 24, w: 560, h: 380 },
  build: () => ({ body: chat.body, api: chat }),
});
register({
  id: "files",
  title: "Files",
  tag: "/",
  rect: { x: 200, y: 430, w: 440, h: 300 },
  build: () => ({ body: files.body }),
  onOpen: () => files.refresh(),
});
register({
  id: "transfers",
  title: "File Transfers",
  rect: { x: 790, y: 24, w: 320, h: 360 },
  build: () => ({ body: transfers.body }),
});
register({
  id: "addressbook",
  title: "Address Book",
  rect: { x: 200, y: 90, w: 460, h: 320 },
  build: () => ({ body: addressbook.body }),
});
register({
  id: "settings",
  title: "Settings",
  rect: { x: 240, y: 120, w: 360 },
  resizable: false,
  build: () => ({ body: settings.body }),
});
register({
  id: "about",
  title: "About KDX",
  rect: { x: 280, y: 150, w: 360 },
  resizable: false,
  build: () => ({ body: about.body }),
});
register({
  id: "userlist",
  title: "User List",
  rect: { x: 630, y: 430, w: 300, h: 320 },
  build: () => ({ body: userList.body }),
  onOpen: () => {
    userList.refresh().then(() => update({ presenceCount: userList.count }));
  },
});
register({
  id: "userinfo",
  title: "User Info",
  rect: { x: 940, y: 430, w: 280, h: 260 },
  resizable: false,
  build: () => ({ body: userInfo.body }),
});
register({
  id: "messages",
  title: "Messages",
  rect: { x: 340, y: 120, w: 500, h: 340 },
  build: () => ({ body: messages.body }),
});
register({
  id: "admin",
  title: "Administration",
  rect: { x: 380, y: 90, w: 520, h: 460 },
  build: () => ({ body: roles.body }),
  onOpen: () => roles.refresh(),
});

// The Button Bar — the always-present launcher, itself a floating window on
// the desktop.
const buttonBar = buildButtonBar(desktop, {
  onAction: (name) => {
    if (name === "disconnect") {
      invoke("disconnect").catch(() => {});
      update({ connection: "offline", session: null, presenceCount: 0 });
    } else if (name === "server") {
      toggle("connect");
    } else if (name === "exit") {
      if (window.__TAURI__) window.__TAURI__.window.getCurrentWindow().close();
    }
  },
});

// Open the Connect window on start.
open("connect");

function onLoggedIn() {
  open("chat");
  chat.focusEntry();
  // Populate the global roster (and Button Bar count) even if the User List
  // window is never opened.
  userList.refresh().then(() => update({ presenceCount: userList.count }));
}

// Reflect connection + window state in the Button Bar (on store changes and
// on window open/close/minimize).
subscribe((s) => buttonBar.update(s));
onChange(() => buttonBar.update(getState()));
buttonBar.update(getState());

// Route server events into the windows (instances always exist).
onKdxEvent((ev) => {
  switch (ev.type) {
    case "connected":
      break;
    case "chat":
      chat.onChat(ev);
      break;
    case "user_list":
      chat.onUsers(ev.users);
      setChatTag(ev.users.length);
      update({ users: ev.users });
      break;
    case "topic":
      chat.onTopic(ev.topic);
      break;
    case "presence":
      userList.onPresence(ev.user, ev.online);
      update({ presenceCount: userList.count });
      break;
    case "private_message":
      messages.onMessage(ev);
      if (!isOpen("messages")) open("messages");
      break;
    case "transfer_progress":
      transfers.onProgress(ev);
      updateTransfer(ev.id, { done: ev.done, total: ev.total });
      if (!isOpen("transfers")) open("transfers");
      break;
    case "transfer_complete":
      transfers.onComplete(ev);
      updateTransfer(ev.id, { status: ev.status });
      if (ev.direction === "upload" || ev.direction === "download") files.refresh();
      break;
    case "server_warning":
      chat.onWarning(ev.text);
      break;
    case "server_error":
      chat.onError(ev.text);
      break;
    case "server_info":
      chat.onChat({ sender: "", text: ev.text, timestamp: Date.now() / 1000, flags: 2 });
      break;
    case "disconnected":
      update({ connection: "offline", session: null, presenceCount: 0 });
      chat.onError("disconnected: " + ev.reason + " — reconnect from the Connect window");
      setChatTag(0);
      open("connect");
      break;
    default:
      console.warn("unhandled event", ev);
  }
});

function setChatTag(n) {
  const el = document.querySelector('.win[data-id="chat"] .titlebar .tag');
  if (el) el.textContent = `${n} user${n === 1 ? "" : "s"}`;
}
