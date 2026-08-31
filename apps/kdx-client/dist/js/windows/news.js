// Public News — newsgroups with threaded posts. Left pane is the server →
// newsgroup tree; the right pane shows a newsgroup's threads (indented by
// reply depth), a reading area for the selected post, and a composer for new
// threads and replies. Creating newsgroups and deleting others' posts are
// server-enforced on USER_ADMIN; posting is gated by the group's post class.

import { invoke } from "../bridge.js";
import { getState } from "../store.js";

const CLASS_NAME = ["guest", "user", "power user", "admin"];

export function buildNews() {
  const body = document.createElement("div");
  body.className = "news-win";
  body.innerHTML = `
    <div class="news-groups">
      <div class="news-hdr">Newsgroups</div>
      <div class="news-group-list" id="news-groups"></div>
      <button class="mini" id="news-newgroup">New Newsgroup…</button>
    </div>
    <div class="news-main">
      <div class="news-toolbar">
        <span class="news-title" id="news-title">select a newsgroup</span>
        <span class="spacer"></span>
        <button class="mini" id="news-compose" disabled>New Message</button>
        <button class="mini" id="news-refresh">Refresh</button>
      </div>
      <div class="news-threads" id="news-threads"></div>
      <div class="news-reading" id="news-reading"></div>
      <form class="news-composer hidden" id="news-composer">
        <div class="news-compose-to" id="news-compose-to"></div>
        <input id="news-subject" placeholder="subject" spellcheck="false" autocomplete="off" />
        <textarea id="news-body" placeholder="message…" rows="4"></textarea>
        <div class="ab-actions">
          <button type="submit" class="btn">Post</button>
          <button type="button" class="btn" id="news-compose-cancel">Cancel</button>
        </div>
        <div class="rl-assign-result" id="news-compose-result"></div>
      </form>
      <form class="news-newgroup hidden" id="news-newgroup-form">
        <div class="ab-grid">
          <label>Name<input id="ng-name" spellcheck="false" autocomplete="off" /></label>
          <label>Read class
            <select id="ng-read">${classOptions(0)}</select>
          </label>
          <label>Post class
            <select id="ng-post">${classOptions(1)}</select>
          </label>
        </div>
        <input id="ng-desc" placeholder="description" spellcheck="false" autocomplete="off" />
        <div class="ab-actions">
          <button type="submit" class="btn">Create</button>
          <button type="button" class="btn" id="ng-cancel">Cancel</button>
        </div>
        <div class="rl-assign-result" id="ng-result"></div>
      </form>
    </div>`;

  const $ = (s) => body.querySelector(s);
  const groupsEl = $("#news-groups");
  const threadsEl = $("#news-threads");
  const readingEl = $("#news-reading");
  const titleEl = $("#news-title");
  const composer = $("#news-composer");
  const newgroupForm = $("#news-newgroup-form");

  let groups = [];
  let group = null; // selected newsgroup
  let posts = []; // posts of the selected group
  let selected = null; // selected post
  let replyTo = null; // post being replied to (null = new thread)

  async function refresh() {
    try {
      groups = await invoke("list_newsgroups");
      renderGroups();
      if (group) await openGroup(group.id);
    } catch (err) {
      groupsEl.innerHTML = `<div class="empty">${esc(err.message || String(err))}</div>`;
    }
  }

  function renderGroups() {
    if (!groups.length) {
      groupsEl.innerHTML = '<div class="empty">no newsgroups</div>';
      return;
    }
    groupsEl.innerHTML = "";
    for (const g of groups) {
      const d = document.createElement("div");
      d.className = "news-group" + (group && group.id === g.id ? " active" : "");
      d.innerHTML = `<span class="news-group-name">${esc(g.name)}</span>` +
        `<span class="news-group-meta">${CLASS_NAME[g.min_post_class] || "?"}+</span>`;
      d.title = g.description || g.name;
      d.addEventListener("click", () => openGroup(g.id));
      groupsEl.appendChild(d);
    }
  }

  async function openGroup(id) {
    group = groups.find((g) => g.id === id) || null;
    if (!group) return;
    titleEl.textContent = group.name;
    $("#news-compose").disabled = false;
    selected = null;
    readingEl.innerHTML = "";
    composer.classList.add("hidden");
    newgroupForm.classList.add("hidden");
    renderGroups();
    try {
      posts = await invoke("list_thread", { newsgroupId: id });
      renderThreads();
    } catch (err) {
      threadsEl.innerHTML = `<div class="empty">${esc(err.message || String(err))}</div>`;
    }
  }

  // Order posts as a thread tree (roots by time, replies nested under parents).
  function threadOrder() {
    const byParent = new Map();
    for (const p of posts) {
      const key = p.parent_id || "";
      if (!byParent.has(key)) byParent.set(key, []);
      byParent.get(key).push(p);
    }
    const out = [];
    const walk = (parentId, depth) => {
      for (const p of byParent.get(parentId) || []) {
        out.push({ post: p, depth });
        walk(p.id, depth + 1);
      }
    };
    walk("", 0);
    return out;
  }

  function renderThreads() {
    const ordered = threadOrder();
    if (!ordered.length) {
      threadsEl.innerHTML = '<div class="empty">no posts yet — New Message to start a thread</div>';
      return;
    }
    threadsEl.innerHTML = "";
    for (const { post, depth } of ordered) {
      const row = document.createElement("div");
      row.className = "news-thread" + (selected && selected.id === post.id ? " active" : "");
      row.style.paddingLeft = `${8 + depth * 16}px`;
      row.innerHTML =
        `<span class="news-thread-subj">${depth ? "↳ " : ""}${esc(post.subject)}</span>` +
        `<span class="news-thread-meta">${esc(post.author)} · ${fmtTime(post.timestamp)}</span>`;
      row.addEventListener("click", () => selectPost(post));
      threadsEl.appendChild(row);
    }
  }

  function selectPost(post) {
    selected = post;
    renderThreads();
    const mine = getState().session && getState().session.username === post.author;
    readingEl.innerHTML = `
      <div class="news-read-head">
        <span class="news-read-subj">${esc(post.subject)}</span>
        <span class="news-read-by">${esc(post.author)} · ${fmtTime(post.timestamp)}</span>
      </div>
      <div class="news-read-body">${esc(post.body)}</div>
      <div class="news-read-actions">
        <button class="mini" id="news-reply">Reply</button>
        ${mine ? '<button class="mini danger" id="news-delete">Delete</button>' : ""}
      </div>`;
    readingEl.querySelector("#news-reply").addEventListener("click", () => openComposer(post));
    const del = readingEl.querySelector("#news-delete");
    if (del) del.addEventListener("click", () => deletePost(post));
  }

  function openComposer(parent) {
    replyTo = parent;
    $("#news-compose-to").textContent = parent
      ? `Reply to “${parent.subject}” by ${parent.author}`
      : `New thread in ${group ? group.name : ""}`;
    $("#news-subject").value = parent ? replySubject(parent.subject) : "";
    $("#news-body").value = "";
    $("#news-compose-result").textContent = "";
    composer.classList.remove("hidden");
    newgroupForm.classList.add("hidden");
    $("#news-subject").focus();
  }

  async function deletePost(post) {
    try {
      posts = await invoke("delete_post", { postId: post.id });
      selected = null;
      readingEl.innerHTML = "";
      renderThreads();
    } catch (err) {
      readingEl.innerHTML = `<div class="empty">${esc(err.message || String(err))}</div>`;
    }
  }

  $("#news-compose").addEventListener("click", () => openComposer(null));
  $("#news-compose-cancel").addEventListener("click", () => composer.classList.add("hidden"));
  $("#news-refresh").addEventListener("click", refresh);

  composer.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!group) return;
    const subject = $("#news-subject").value.trim();
    const bodyText = $("#news-body").value;
    if (!subject) {
      $("#news-compose-result").textContent = "a subject is required";
      return;
    }
    try {
      posts = await invoke("create_post", {
        newsgroupId: group.id,
        parentId: replyTo ? replyTo.id : "",
        subject,
        body: bodyText,
      });
      composer.classList.add("hidden");
      renderThreads();
    } catch (err) {
      $("#news-compose-result").textContent = esc(err.message || String(err));
    }
  });

  // New Newsgroup (admin-only; the server enforces it).
  $("#news-newgroup").addEventListener("click", () => {
    newgroupForm.classList.remove("hidden");
    composer.classList.add("hidden");
    $("#ng-name").value = "";
    $("#ng-desc").value = "";
    $("#ng-result").textContent = "";
    $("#ng-name").focus();
  });
  $("#ng-cancel").addEventListener("click", () => newgroupForm.classList.add("hidden"));
  newgroupForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = $("#ng-name").value.trim();
    if (!name) return;
    try {
      groups = await invoke("create_newsgroup", {
        name,
        description: $("#ng-desc").value.trim(),
        minReadClass: parseInt($("#ng-read").value, 10) || 0,
        minPostClass: parseInt($("#ng-post").value, 10) || 0,
      });
      newgroupForm.classList.add("hidden");
      renderGroups();
    } catch (err) {
      $("#ng-result").textContent = esc(err.message || String(err));
    }
  });

  return { body, refresh };
}

function replySubject(s) {
  return /^re:/i.test(s) ? s : `re: ${s}`;
}
function classOptions(selected) {
  return CLASS_NAME.map(
    (name, i) => `<option value="${i}"${i === selected ? " selected" : ""}>${name}</option>`
  ).join("");
}
function fmtTime(unixSecs) {
  const d = new Date(unixSecs * 1000);
  return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}
