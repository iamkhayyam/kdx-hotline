import { onKdxEvent } from "./bridge.js";
import { createWindow, getWindow } from "./wm.js";
import { getState, subscribe, update } from "./store.js";
import { buildConnect } from "./windows/connect.js";
import { buildChat } from "./windows/chat.js";
import { buildFiles } from "./windows/files.js";
import { buildTransfers } from "./windows/transfers.js";

const desktop = document.getElementById("desktop");
const connStatus = document.getElementById("conn-status");
const footLeft = document.getElementById("foot-left");

// Build windows.
const chat = buildChat();
const files = buildFiles();
const transfers = buildTransfers();

createWindow(desktop, {
  id: "connect",
  title: "Connect",
  x: 24,
  y: 24,
  width: 300,
  body: buildConnect(onLoggedIn),
});
const chatWin = createWindow(desktop, {
  id: "chat",
  title: "Chat — #lobby",
  tag: "0 users",
  x: 348,
  y: 24,
  width: 560,
  height: 380,
  body: chat.body,
});
createWindow(desktop, {
  id: "files",
  title: "Files",
  tag: "/",
  x: 348,
  y: 430,
  width: 420,
  height: 300,
  body: files.body,
});
createWindow(desktop, {
  id: "transfers",
  title: "Transfers",
  x: 930,
  y: 24,
  width: 320,
  height: 360,
  body: transfers.body,
});

chatWin.focus();

function onLoggedIn() {
  getWindow("chat").focus();
  chat.focusEntry();
  files.refresh();
}

// Reflect connection state in the menubar + footer.
subscribe((s) => {
  connStatus.dataset.state = s.connection;
  if (s.connection === "online" && s.server) {
    connStatus.textContent = `TLS 1.3 · kdx://${s.server.host}:${s.server.port}`;
    footLeft.textContent = `connected as class ${s.session ? s.session.class : "?"}`;
  } else if (s.connection === "connecting") {
    connStatus.textContent = "connecting…";
  } else {
    connStatus.textContent = "offline";
    footLeft.textContent = "not connected";
  }
});

// Route server events into the windows.
onKdxEvent((ev) => {
  switch (ev.type) {
    case "connected":
      break;
    case "chat":
      chat.onChat(ev);
      break;
    case "user_list":
      chat.onUsers(ev.users);
      getWindow("chat").setTag(`${ev.users.length} user${ev.users.length === 1 ? "" : "s"}`);
      update({ users: ev.users });
      break;
    case "topic":
      chat.onTopic(ev.topic);
      break;
    case "transfer_progress":
      transfers.onProgress(ev);
      getWindow("transfers").focus();
      break;
    case "transfer_complete":
      transfers.onComplete(ev);
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
      update({ connection: "offline", session: null });
      chat.onError("disconnected: " + ev.reason);
      break;
    default:
      console.warn("unhandled event", ev);
  }
});
