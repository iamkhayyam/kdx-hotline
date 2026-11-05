// Public News — newsgroups with threaded posts. Left pane is the server →
// newsgroup tree; the right pane shows a newsgroup's threads (indented by
// reply depth), a reading area for the selected post, and a composer for new
// threads and replies. Creating, editing and deleting newsgroups and deleting
// others' posts are server-enforced on USER_ADMIN (edit/delete also need read
// access to the group); posting is gated by the group's post class. The
// controls follow the same rules (moderation.js): newsgroup New/Edit/Delete
// only for USER_ADMIN, New Message/Reply only where the class may post, and
// Delete on your own posts or, with USER_ADMIN, anyone's.

import { invoke } from "../bridge.js";
import { getState, subscribe } from "../store.js";
import { esc, num, errorText } from "../html.js";
import { askConfirm, confirmThen } from "../confirm.js";
import { canManageNewsgroups, canPostTo, canDeletePost, newsgroupFormError } from "../moderation.js";

const CLASS_NAME = ["guest", "user", "power user", "admin"];

export function buildNews() {
  const body = document.createElement("div");
  body.className = "news-win";
  body.innerHTML = `
    <div class="news-groups">
      <div class="news-hdr">Newsgroups</div>
      <div class="news-group-list" id="news-groups"></div>
      <button class="mini hidden" id="news-newgroup">New Newsgroup…</button>
      <div class="news-group-admin hidden" id="news-group-admin">
        <button class="mini" id="news-editgroup" disabled>Edit…</button>
        <button class="mini danger" id="news-delgroup" disabled>Delete…</button>
      </div>
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
        <div class="news-compose-to" id="ng-head">New newsgroup</div>
        <div class="ab-grid">
          <label>Name<input id="ng-name" spellcheck="false" autocomplete="off" /></label>
          <label>Read class
            <select id="ng-read">${classOptionsHtml(0)}</select>
          </label>
          <label>Post class
            <select id="ng-post">${classOptionsHtml(1)}</select>
          </label>
        </div>
        <input id="ng-desc" placeholder="description" spellcheck="false" autocomplete="off" />
        <div class="ab-actions">
          <button type="submit" class="btn" id="ng-submit">Create</button>
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
  const groupAdmin = $("#news-group-admin");

  let groups = [];
  let group = null; // selected newsgroup
  let posts = []; // posts of the selected group
  let selected = null; // selected post
  let replyTo = null; // post being replied to (null = new thread)
  let editing = null; // newsgroup open in the editor (null = creating one)

  async function refresh() {
    try {
      groups = await invoke("list_newsgroups");
      syncSelection();
      renderGroups();
      if (group) await openGroup(group.id);
    } catch (err) {
      groupsEl.innerHTML = `<div class="empty">${esc(errorText(err))}</div>`;
    }
  }

  /** Newsgroup New/Edit/Delete: shown to USER_ADMIN, Edit/Delete live while
   * a group is open. New Message: live in a group the session may post to. */
  function updateAdminControls() {
    const session = getState().session;
    const admin = canManageNewsgroups(session);
    groupAdmin.classList.toggle("hidden", !admin);
    $("#news-newgroup").classList.toggle("hidden", !admin);
    $("#news-editgroup").disabled = !group;
    $("#news-delgroup").disabled = !group;
    $("#news-compose").disabled = !canPostTo(session, group);
  }

  /** After the group list changed: follow the open group's new name, or
   * close it if it's gone (deleted, or no longer readable). */
  function syncSelection() {
    if (!group) return;
    const fresh = groups.find((g) => g.id === group.id);
    if (fresh) {
      group = fresh;
      titleEl.textContent = fresh.name;
    } else {
      clearGroup();
    }
  }

  function clearGroup() {
    group = null;
    posts = [];
    selected = null;
    titleEl.textContent = "select a newsgroup";
    $("#news-compose").disabled = true; // no group, nothing to post to
    threadsEl.innerHTML = "";
    readingEl.innerHTML = "";
    composer.classList.add("hidden");
    if (editing) {
      editing = null;
      newgroupForm.classList.add("hidden");
    }
  }

  function renderGroups() {
    updateAdminControls();
    if (!groups.length) {
      groupsEl.innerHTML = '<div class="empty">no newsgroups</div>';
      return;
    }
    groupsEl.innerHTML = "";
    for (const g of groups) {
      const d = document.createElement("div");
      d.className = "news-group" + (group && group.id === g.id ? " active" : "");
      d.innerHTML = `<span class="news-group-name">${esc(g.name)}</span>` +
        `<span class="news-group-meta">${esc(CLASS_NAME[g.min_post_class] || "?")}+</span>`;
      d.title = g.description || g.name;
      d.addEventListener("click", () => openGroup(g.id));
      groupsEl.appendChild(d);
    }
  }

  async function openGroup(id) {
    group = groups.find((g) => g.id === id) || null;
    if (!group) return;
    titleEl.textContent = group.name;
    selected = null;
    readingEl.innerHTML = "";
    composer.classList.add("hidden");
    newgroupForm.classList.add("hidden");
    renderGroups();
    try {
      posts = await invoke("list_thread", { newsgroupId: id });
      renderThreads();
    } catch (err) {
      threadsEl.innerHTML = `<div class="empty">${esc(errorText(err))}</div>`;
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
        `<span class="news-thread-meta">${esc(post.author)} · ${esc(fmtTime(post.timestamp))}</span>`;
      row.addEventListener("click", () => selectPost(post));
      threadsEl.appendChild(row);
    }
  }

  function selectPost(post) {
    selected = post;
    renderThreads();
    const session = getState().session;
    const reply = canPostTo(session, group);
    const del = canDeletePost(session, post);
    readingEl.innerHTML = `
      <div class="news-read-head">
        <span class="news-read-subj">${esc(post.subject)}</span>
        <span class="news-read-by">${esc(post.author)} · ${esc(fmtTime(post.timestamp))}</span>
      </div>
      <div class="news-read-body">${esc(post.body)}</div>
      <div class="news-read-actions">
        ${reply ? '<button class="mini" id="news-reply">Reply</button>' : ""}
        ${del ? '<button class="mini danger" id="news-delete">Delete</button>' : ""}
      </div>`;
    const replyBtn = readingEl.querySelector("#news-reply");
    if (replyBtn) replyBtn.addEventListener("click", () => openComposer(post));
    const delBtn = readingEl.querySelector("#news-delete");
    if (delBtn) delBtn.addEventListener("click", () => deletePost(post));
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
      readingEl.innerHTML = `<div class="empty">${esc(errorText(err))}</div>`;
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
      $("#news-compose-result").textContent = errorText(err);
    }
  });

  // New / Edit Newsgroup share one form (USER_ADMIN; the server enforces
  // it, and that the editor can read the group).
  function openGroupForm(g) {
    editing = g || null;
    $("#ng-head").textContent = g ? `Edit “${g.name}”` : "New newsgroup";
    $("#ng-submit").textContent = g ? "Save" : "Create";
    $("#ng-name").value = g ? g.name : "";
    $("#ng-desc").value = g ? g.description : "";
    $("#ng-read").value = String(g ? g.min_read_class : 0);
    $("#ng-post").value = String(g ? g.min_post_class : 1);
    $("#ng-result").textContent = "";
    newgroupForm.classList.remove("hidden");
    composer.classList.add("hidden");
    $("#ng-name").focus();
  }
  function closeGroupForm() {
    editing = null;
    newgroupForm.classList.add("hidden");
  }

  $("#news-newgroup").addEventListener("click", () => openGroupForm(null));
  $("#news-editgroup").addEventListener("click", () => group && openGroupForm(group));
  $("#ng-cancel").addEventListener("click", closeGroupForm);
  newgroupForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fields = {
      name: $("#ng-name").value.trim(),
      description: $("#ng-desc").value.trim(),
      readClass: parseInt($("#ng-read").value, 10),
      postClass: parseInt($("#ng-post").value, 10),
    };
    const problem = newsgroupFormError(fields);
    if (problem) {
      $("#ng-result").textContent = problem;
      return;
    }
    const args = {
      name: fields.name,
      description: fields.description,
      minReadClass: fields.readClass,
      minPostClass: fields.postClass,
    };
    try {
      groups = editing
        ? await invoke("update_newsgroup", { id: editing.id, ...args })
        : await invoke("create_newsgroup", args);
      closeGroupForm();
      syncSelection();
      renderGroups();
    } catch (err) {
      $("#ng-result").textContent = errorText(err);
    }
  });

  // Delete Newsgroup: takes every post in it, so always confirm first.
  $("#news-delgroup").addEventListener("click", async () => {
    const g = group;
    if (!g) return;
    await confirmThen(
      () =>
        askConfirm(`Delete the newsgroup “${g.name}” and every post in it?\nThis cannot be undone.`, {
          confirmLabel: "Delete",
          danger: true,
        }),
      async () => {
        try {
          groups = await invoke("delete_newsgroup", { id: g.id });
          if (editing && editing.id === g.id) closeGroupForm();
          syncSelection();
          renderGroups();
        } catch (err) {
          const msg = document.createElement("div");
          msg.className = "empty";
          msg.textContent = errorText(err);
          readingEl.replaceChildren(msg);
        }
      }
    );
  });

  // A login (or hydration) changes who "me" is, and with it the controls.
  subscribe(updateAdminControls);

  return { body, refresh, afterHydrate: updateAdminControls };
}

function replySubject(s) {
  return /^re:/i.test(s) ? s : `re: ${s}`;
}
function classOptionsHtml(selected) {
  return CLASS_NAME.map(
    (name, i) => `<option value="${num(i)}"${i === selected ? " selected" : ""}>${esc(name)}</option>`
  ).join("");
}
function fmtTime(unixSecs) {
  const d = new Date(unixSecs * 1000);
  return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
