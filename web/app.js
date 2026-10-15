// ASU authenticator PWA. Dependency-free.
// Security rules for this file:
//  * Every piece of server/agent data is written with textContent (never
//    innerHTML), so nothing the agent controls can become markup or script.
//  * The card is rendered only from the gateway's render_card output
//    (title, effect_class, risk_lines, fields). Gateway labels and the
//    agent-chosen argument names ("arg.*", section "arguments") are shown in
//    separate sections. Agent text appears only in the separate grey
//    "Agent's explanation — untrusted" box, collapsed by default.
//  * A card that is on screen is never re-rendered or replaced while the
//    user is looking at / interacting with the list (RT-11).
"use strict";

(function () {
  const API = "/v1/authn";
  const $ = (id) => document.getElementById(id);

  // Refuse to run framed (overlay / clickjacking of the approval button).
  if (window.top !== window.self) {
    $("framed").hidden = false;
    return;
  }

  // ---------------------------------------------------------------- utils
  function b64uToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufToB64u(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function str(v) {
    if (v === null || v === undefined) return "";
    return typeof v === "string" ? v : JSON.stringify(v);
  }
  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (text !== undefined) e.textContent = str(text);
    if (cls) e.className = cls;
    return e;
  }
  function setStatus(msg, isError) {
    const s = $("status");
    s.textContent = msg || "";
    s.className = isError ? "error" : "";
  }

  async function api(path, body) {
    const opts = { credentials: "same-origin", headers: { Accept: "application/json" } };
    if (body !== undefined) {
      opts.method = "POST";
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const r = await fetch(API + path, opts);
    let data = null;
    try { data = await r.json(); } catch (_) { data = null; }
    if (!r.ok) {
      const err = new Error((data && data.detail) ? str(data.detail) : ("HTTP " + r.status));
      err.status = r.status;
      throw err;
    }
    return data;
  }

  // ------------------------------------------------- WebAuthn conversions
  function creationOptions(o) {
    const pk = Object.assign({}, o);
    pk.challenge = b64uToBuf(o.challenge);
    pk.user = Object.assign({}, o.user, { id: b64uToBuf(o.user.id) });
    pk.excludeCredentials = (o.excludeCredentials || []).map((c) => Object.assign({}, c, { id: b64uToBuf(c.id) }));
    return pk;
  }
  function requestOptions(o) {
    const pk = Object.assign({}, o);
    pk.challenge = b64uToBuf(o.challenge);
    pk.allowCredentials = (o.allowCredentials || []).map((c) => Object.assign({}, c, { id: b64uToBuf(c.id) }));
    return pk;
  }
  function attestationToJSON(cred) {
    const r = cred.response;
    return {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64u(r.clientDataJSON),
        attestationObject: bufToB64u(r.attestationObject),
        transports: typeof r.getTransports === "function" ? r.getTransports() : [],
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      authenticatorAttachment: cred.authenticatorAttachment || null,
    };
  }
  function assertionToJSON(cred) {
    const r = cred.response;
    return {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64u(r.clientDataJSON),
        authenticatorData: bufToB64u(r.authenticatorData),
        signature: bufToB64u(r.signature),
        userHandle: r.userHandle ? bufToB64u(r.userHandle) : null,
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      authenticatorAttachment: cred.authenticatorAttachment || null,
    };
  }

  // ---------------------------------------------------------- account flows
  function rememberUser(u) { try { localStorage.setItem("asu_user", u); } catch (_) { /* ignore */ } }
  function rememberedUser() { try { return localStorage.getItem("asu_user") || ""; } catch (_) { return ""; } }

  async function register(userId, addToExisting) {
    if (!window.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
    const body = { user_id: userId };
    if (!addToExisting) {
      const dn = $("display-name").value.trim();
      const tok = $("enroll-token").value.trim();
      if (dn) body.display_name = dn;
      if (tok) body.enrollment_token = tok;
    }
    const opts = await api("/register/options", body);
    const cred = await navigator.credentials.create({ publicKey: creationOptions(opts) });
    await api("/register/verify", { credential: attestationToJSON(cred) });
    rememberUser(userId);
  }

  async function login(userId) {
    if (!window.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
    const opts = await api("/login/options", { user_id: userId });
    const cred = await navigator.credentials.get({ publicKey: requestOptions(opts) });
    await api("/login/verify", { credential: assertionToJSON(cred) });
    rememberUser(userId);
  }

  // ------------------------------------------------------------- rendering
  function fmtTime(ts) {
    if (!ts) return "";
    const secs = Math.round(Number(ts) - Date.now() / 1000);
    if (secs <= 0) return "expired";
    return secs >= 120 ? "expires in " + Math.round(secs / 60) + " min" : "expires in " + secs + " s";
  }

  function renderFields(dl, items) {
    dl.textContent = "";
    for (const f of items) {
      const dt = el("dt", f.label_full || f.label);
      if (f.type) dt.appendChild(el("span", f.type, "type-tag"));
      dl.appendChild(dt);
      const dd = el("dd", f.value);
      if (f.truncated && typeof f.full === "string") {
        // Long values are shortened by the gateway; the full escaped value is
        // one explicit tap away (D-005 item 6).
        const b = el("button", "Show all " + str(f.length) + " characters", "secondary expand");
        b.type = "button";
        let open = false;
        b.addEventListener("click", () => {
          open = !open;
          dd.firstChild.textContent = open ? f.full : f.value;
          b.textContent = open ? "Show less" : "Show all " + str(f.length) + " characters";
        });
        dd.textContent = "";
        dd.appendChild(document.createTextNode(str(f.value)));
        dd.appendChild(document.createElement("br"));
        dd.appendChild(b);
      }
      dl.appendChild(dd);
    }
  }

  function grantSummary(gr) {
    const out = [];
    const bound = gr.bound_args || {};
    const free = gr.free_args || {};
    const tgt = gr.target ? "Only to / on: " + str(gr.target) : "Same target";
    out.push(tgt + " (every other argument must stay exactly as approved)");
    for (const k of Object.keys(free).sort()) {
      const r = free[k] || {};
      if (r.type === "amount") out.push("arg." + k + ": any amount up to " + str(r.max) + " " + str(gr.currency || ""));
      else if (r.type === "text") out.push("arg." + k + ": any text up to " + str(r.max_len) + " characters");
    }
    if (gr.max_total_amount) out.push("At most " + str(gr.max_total_amount) + " " + str(gr.currency || "") + " in total");
    out.push("At most " + str(gr.max_uses) + " uses, until " + new Date(Number(gr.not_after) * 1000).toLocaleString());
    out.push("Only for this agent session (" + str(gr.session_id) + "), tool " + str(gr.tool));
    if (Object.keys(bound).length === 0 && Object.keys(free).length === 0) out.push("No arguments");
    return out;
  }

  function renderApproval(ap) {
    const node = document.importNode($("tpl-approval").content, true);
    const art = node.querySelector(".approval");
    art.dataset.id = str(ap.id);
    const card = ap.card;
    const approveBtn = node.querySelector(".approve");
    const denyBtn = node.querySelector(".deny");
    const result = node.querySelector(".result");

    if (!card) {
      node.querySelector(".title").textContent = "This request could not be displayed safely.";
      node.querySelector(".badge").textContent = "unknown";
      approveBtn.disabled = true;
      approveBtn.hidden = true;
    } else {
      const badge = node.querySelector(".badge");
      badge.textContent = str(card.effect_class);
      badge.classList.add("ec-" + str(card.effect_class).replace(/[^a-z]/g, ""));
      node.querySelector(".title").textContent = str(card.title);
      const risks = node.querySelector(".risks");
      for (const line of card.risk_lines || []) risks.appendChild(el("li", line));
      const fields = card.fields || [];
      const trusted = fields.filter((f) => f.section !== "arguments");
      const args = fields.filter((f) => f.section === "arguments");
      renderFields(node.querySelector(".fields"), trusted);
      if (args.length) {
        node.querySelector(".args").hidden = false;
        renderFields(node.querySelector(".arg-fields"), args);
      }
      if (card.trusted === false) {
        art.classList.add("untrusted-card");
        risks.insertBefore(el("li", "BASELINE MODE: this card text was written by the agent."), risks.firstChild);
      }
    }
    if (ap.digest) node.querySelector(".digest").textContent = "Effect fingerprint " + str(ap.digest).slice(0, 16);
    node.querySelector(".expires").textContent = fmtTime(ap.expires_at);

    if (ap.explanation) {
      const box = node.querySelector(".explanation");
      box.hidden = false;
      box.open = false; // collapsed by default: read the trusted card first
      node.querySelector(".explanation-text").textContent = str(ap.explanation);
    }

    const grantBox = node.querySelector(".grant-box");
    if (ap.grant_request && card) {
      node.querySelector(".grant").hidden = false;
      const gr = ap.grant_request;
      const sum = node.querySelector(".grant-summary");
      for (const line of grantSummary(gr)) sum.appendChild(el("li", line));
      const items = [];
      for (const k of Object.keys(gr).sort()) items.push({ label: k, value: gr[k] });
      if (ap.grant_digest) items.push({ label: "grant fingerprint", value: str(ap.grant_digest).slice(0, 16) });
      renderFields(node.querySelector(".grant-fields"), items);
    }

    approveBtn.addEventListener("click", async () => {
      approveBtn.disabled = true; denyBtn.disabled = true;
      result.textContent = "Waiting for your passkey…";
      inFlight++;
      try {
        const grant = !!(ap.grant_request && grantBox.checked);
        const opts = await api("/approvals/" + encodeURIComponent(ap.id) + "/options", { grant: grant });
        const cred = await navigator.credentials.get({ publicKey: requestOptions(opts) });
        await api("/approvals/" + encodeURIComponent(ap.id) + "/verify", { credential: assertionToJSON(cred), grant: grant });
        result.textContent = "Approved.";
        art.classList.add("done");
      } catch (e) {
        result.textContent = "Not approved: " + e.message;
        approveBtn.disabled = false; denyBtn.disabled = false;
      } finally {
        inFlight--;
      }
    });
    denyBtn.addEventListener("click", async () => {
      approveBtn.disabled = true; denyBtn.disabled = true;
      inFlight++;
      try {
        await api("/approvals/" + encodeURIComponent(ap.id) + "/deny", {});
        result.textContent = "Denied.";
        art.classList.add("done");
      } catch (e) {
        result.textContent = "Deny failed: " + e.message;
        approveBtn.disabled = !card; denyBtn.disabled = false;
      } finally {
        inFlight--;
      }
    });
    return node;
  }

  let busy = false;
  let inFlight = 0; // approve/deny ceremonies in progress
  let lastInteraction = 0; // pointer / key activity on the pending list
  function interacting() {
    const list = $("pending");
    if (list.matches(":hover") || list.contains(document.activeElement)) return true;
    return Date.now() - lastInteraction < 15000;
  }
  async function refresh(manual) {
    if (busy) return;
    busy = true;
    try {
      let me;
      try {
        me = await api("/me");
      } catch (e) {
        if (e.status === 401) { showSignedOut(); return; }
        throw e;
      }
      $("signed-out").hidden = true;
      $("signed-in").hidden = false;
      $("who").textContent = str(me.user_id);
      // Do not touch the list while the user is mid-approval on a card or is
      // reading / pointing at it (RT-11). Manual refresh always proceeds.
      if (inFlight > 0) return;
      if (!manual && interacting()) return;
      const data = await api("/pending");
      const list = $("pending");
      const want = new Set((data.approvals || []).map((a) => str(a.id)));
      // Keyed update: a card already on screen is never rebuilt or replaced;
      // finished cards stay until the next refresh after they settle.
      for (const node of Array.from(list.children)) {
        if (!want.has(node.dataset.id) && !node.classList.contains("busy")) list.removeChild(node);
      }
      const have = new Set(Array.from(list.children).map((n) => n.dataset.id));
      for (const ap of data.approvals || []) {
        if (!have.has(str(ap.id))) {
          const frag = renderApproval(ap);
          list.appendChild(frag);
        }
      }
      $("none").hidden = list.children.length > 0;
    } catch (e) {
      setStatus(e.message, true);
    } finally {
      busy = false;
    }
  }

  function showSignedOut() {
    $("signed-in").hidden = true;
    $("signed-out").hidden = false;
    if (!$("user-id").value) $("user-id").value = rememberedUser();
  }

  // ---------------------------------------------------------------- wiring
  function wire(id, fn) {
    $(id).addEventListener("click", async () => {
      setStatus("");
      $(id).disabled = true;
      try { await fn(); } catch (e) { setStatus(e.message || String(e), true); }
      finally { $(id).disabled = false; }
    });
  }

  wire("btn-register", async () => {
    const u = $("user-id").value.trim();
    if (!u) throw new Error("Enter a user ID first.");
    await register(u, false);
    setStatus("Passkey created.");
    await refresh(true);
  });
  wire("btn-login", async () => {
    const u = $("user-id").value.trim();
    if (!u) throw new Error("Enter your user ID.");
    await login(u);
    await refresh(true);
  });
  wire("btn-add-passkey", async () => {
    await register($("who").textContent, true);
    setStatus("Passkey added.");
  });
  wire("btn-logout", async () => {
    await api("/logout", {});
    showSignedOut();
  });
  wire("btn-refresh", () => refresh(true));

  // One-time enrollment link from `asu enroll-link`: #enroll=<token>&user=<id>
  function enrollmentLink() {
    const h = window.location.hash.replace(/^#/, "");
    if (!h) return;
    const p = new URLSearchParams(h);
    const tok = p.get("enroll");
    if (!tok) return;
    if (p.get("user")) $("user-id").value = p.get("user");
    $("enroll-token").value = tok;
    $("enroll-link-note").hidden = false;
    const d = document.querySelector("#signed-out details");
    if (d) d.open = true;
    // keep the one-time secret out of history / screenshots of the URL bar
    try { history.replaceState(null, "", window.location.pathname + window.location.search); } catch (_) { /* ignore */ }
  }
  enrollmentLink();
  window.addEventListener("hashchange", enrollmentLink);

  for (const ev of ["pointerdown", "keydown", "touchstart", "wheel"]) {
    $("pending").addEventListener(ev, () => { lastInteraction = Date.now(); }, { passive: true });
  }

  refresh(true);
  setInterval(() => { if (document.visibilityState === "visible") refresh(false); }, 5000);
})();
