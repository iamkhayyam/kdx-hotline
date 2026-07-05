import { onKdxEvent } from "./bridge.js";
import { initDesktop, register, open, toggle, isOpen } from "./wm.js";
import { getState, subscribe, update } from "./store.js";
import { buildConnect } from "./windows/connect.js";
import { buildChat } from "./windows/chat.js";
import { buildFiles } from "./windows/files.js";
import { buildTransfers } from "./windows/transfers.js";

const desktop = document.getElementById("desktop");
const connStatus = document.getElementById("conn-status");
const footLeft = document.getElementById("foot-left");

initDesktop(desktop);

// Build feature instances eagerly (cheap DOM); the window manager wraps each
// in floating chrome lazily on first open. Events route to these instances
// whether or not their window is currently open.
const chat = buildChat();
const files = buildFiles();
const transfers = buildTransfers();
const connectBody = buildConnect(onLoggedIn);

register({
  id: "connect",
  title: "Connect",
  rect: { x: 24, y: 24, w: 300 },
  resizable: false,
  build: () => ({ body: connectBody }),
});
register({
  id: "chat",
  title: "Public Chat",
  tag: "0 users",
  rect: { x: 340, y: 24, w: 560, h: 380 },
  build: () => ({ body: chat.body, api: chat }),
});
register({
  id: "files",
  title: "Files",
  tag: "/",
  rect: { x: 340, y: 430, w: 440, h: 300 },
  build: () => ({ body: files.body }),
  onOpen: () => files.refresh(),
});
register({
  id: "transfers",
  title: "File Transfers",
  rect: { x: 930, y: 24, w: 320, h: 360 },
  build: () => ({ body: transfers.body }),
});

// Temporary top launcher (replaced by the Button Bar in R2).
document.querySelectorAll(".menubar .item[data-win]").forEach((item) => {
  item.style.cursor = "pointer";
  item.addEventListener("click", () => toggle(item.dataset.win));
});

// Open the Connect window on start.
open("connect");

function onLoggedIn() {
  open("chat");
  chat.focusEntry();
}

// Menubar status chip + footer.
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
    case "transfer_progress":
      transfers.onProgress(ev);
      if (!isOpen("transfers")) open("transfers");
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
