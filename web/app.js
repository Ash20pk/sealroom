import _sodium from "https://cdn.jsdelivr.net/npm/libsodium-wrappers-sumo@0.7.15/+esm";
import { Stage } from "./stage.js";
import {
  useSodium, hex, unhex, canonical, sha256, sha256hex, encryptTo, normalise, elements, hashToPoint, mul, setHash, psiStart,
  envelopeMessage, psiMessage, revealMessage, verifySig,
} from "./sealcrypto.js";

await _sodium.ready;
const sodium = _sodium;
useSodium(sodium);
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const enc = new TextEncoder();
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const short = (h, n = 10) => (h && h.length > n * 2 ? `${h.slice(0, n)}…${h.slice(-4)}` : h || "");
const other = (side) => (side === "incoming" ? "existing" : "incoming");

let stage = null;
try { stage = new Stage(); } catch (e) { console.warn("3D view unavailable", e); }
const S = new Proxy({}, { get: (_, k) => (...a) => (stage ? stage[k](...a) : Promise.resolve()) });

let config = null;
let model = null;
let room = null; // { check_ref, chunk, contract, keys }
const firms = { incoming: { parties: [] }, existing: { parties: [] } };
const ids = {}; // account -> { account, name, pk, sk }

async function api(path, body) {
  const r = await fetch(path, body === undefined ? {} : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || `${path} failed (${r.status})`);
  return j;
}

/* ---------- identity keys held in this page ---------- */
function loadIdentity(d) {
  const kp = sodium.crypto_sign_seed_keypair(unhex(d.seed));
  ids[d.account] = { account: d.account, name: d.name, pk: hex(kp.publicKey), sk: kp.privateKey };
  return ids[d.account];
}
const sign = (account, msg) => hex(sodium.crypto_sign_detached(enc.encode(msg), ids[account].sk));
/* ---------- firm side: seal, sign, exact match, disclose ---------- */

async function sealList(side) {
  const f = firms[side], acct = config.firms[side].account, chunk = room.chunk;
  const salt = sodium.randombytes_buf(32);
  const body = enc.encode(canonical(f.parties));
  const joined = new Uint8Array(salt.length + body.length);
  joined.set(salt); joined.set(body, salt.length);
  const commitment = hex(await sha256(joined));
  const ciphertexts = [];
  for (let k = 0, s = 0; s < Math.max(f.parties.length, 1); k++, s += chunk) {
    const entries = f.parties.slice(s, s + chunk).map((p, t) => ({ i: s + t, ...p }));
    ciphertexts.push(await encryptTo(model.signing_key, JSON.stringify({ kind: "sealroom.party_list", side, commitment, chunk: k, entries })));
  }
  f.psi = await psiStart(f.parties);
  const env = {
    firm: acct, side, commitment, count: f.parties.length, chunk, model: model.model, model_key: model.signing_key,
    ciphertexts, ciphertext_hash: await sha256hex(canonical(ciphertexts)),
    psi_blinded: f.psi.blinded, psi_hash: await setHash(f.psi.blinded),
    check_ref: room.check_ref, counterparty: config.firms[other(side)].account,
  };
  env.signature = sign(acct, envelopeMessage(room.contract, room.check_ref, side, env.counterparty, env));
  await api(`/api/check/${room.check_ref}/envelope`, { envelope: env });
  f.envelope = env;
  f.secret = { firm: acct, side, salt: hex(salt), commitment, check_ref: room.check_ref };
}

async function psiDouble(side) {
  const mine = firms[side], acct = config.firms[side].account, theirSide = other(side);
  const theirs = await api(`/api/check/${room.check_ref}/envelope/${theirSide}`);
  // Check the other firm signed this exact set with its key registered on NEAR.
  if (theirs.psi_hash !== await setHash(theirs.psi_blinded)
      || !verifySig(room.keys[theirs.firm], envelopeMessage(room.contract, room.check_ref, theirSide, theirs.counterparty, theirs), theirs.signature))
    throw new Error(`${theirs.firm}'s submission is not signed by its registered key`);
  mine.doubledTheirs = theirs.psi_blinded.map((p) => mul(mine.psi.scalar, p));
  const msg = { firm: acct, of: theirs.firm, points: mine.doubledTheirs };
  msg.signature = sign(acct, psiMessage(room.check_ref, acct, "double", await setHash(msg.points)));
  await api(`/api/check/${room.check_ref}/psi`, { kind: `${theirSide}_doubled`, message: msg });
}

async function psiIndex(side) {
  const mine = firms[side], acct = config.firms[side].account, theirAcct = config.firms[other(side)].account;
  const t = await api(`/api/check/${room.check_ref}/psi`);
  const d = t[`${side}_doubled`];
  if (!d || d.firm !== theirAcct || !verifySig(room.keys[theirAcct], psiMessage(room.check_ref, theirAcct, "double", await setHash(d.points)), d.signature))
    throw new Error(`exact-match reply is not signed by ${theirAcct}`);
  const theirs = new Set(mine.doubledTheirs);
  const index = {};
  d.points.forEach((p, k) => { if (theirs.has(p)) index[String(k)] = mine.psi.owner[k]; });
  const msg = { firm: acct, index };
  msg.signature = sign(acct, psiMessage(room.check_ref, acct, "index", await sha256hex(canonical(index))));
  await api(`/api/check/${room.check_ref}/psi`, { kind: `${side}_index`, message: msg });
  return Object.keys(index).length;
}

async function discloseMatches(side, verdict) {
  const acct = config.firms[side].account, key = side === "incoming" ? "i" : "j";
  const entries = {};
  [...new Set(verdict.pairs.map((p) => p[key]))].sort((a, b) => a - b).forEach((i) => { entries[String(i)] = firms[side].parties[i]; });
  const reveal = { firm: acct, entries, signature: sign(acct, revealMessage(room.check_ref, acct, await sha256hex(canonical(entries)))) };
  return api(`/api/check/${room.check_ref}/reveal`, { side, reveal });
}

/* ---------- lists ---------- */

function parseCSV(text) {
  const rows = []; let row = [], cell = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') q = false; else cell += c; }
    else if (c === '"') q = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") { if (c === "\r" && text[i + 1] === "\n") i++; row.push(cell); rows.push(row); row = []; cell = ""; }
    else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  const [head, ...data] = rows.filter((r) => r.some((x) => x.trim()));
  const idx = (k) => head.map((h) => h.trim().toLowerCase()).indexOf(k);
  const parties = data.map((r) => ({
    name: (r[idx("name")] || "").trim(),
    role: (r[idx("role")] || "client").trim() || "client",
    aliases: (r[idx("aliases")] || "").split(";").map((s) => s.trim()).filter(Boolean).sort(),
    related: (r[idx("related")] || "").trim(),
  })).filter((p) => p.name);
  // Same order as the Python side, so commitments and entry numbers agree.
  return parties.sort((a, b) => (a.name.toLowerCase() < b.name.toLowerCase() ? -1 : a.name.toLowerCase() > b.name.toLowerCase() ? 1 : 0));
}

function renderList(side) {
  const el = $(`#firm-${side}`);
  $(".list", el).innerHTML = firms[side].parties.map((p, i) =>
    `<li style="--i:${i}" data-i="${i}"><span class="name">${esc(p.name)}</span><span class="role">${esc(p.role)}</span></li>`).join("");
}

async function loadDemo(side, file) {
  firms[side].parties = parseCSV(await (await fetch(`/demo/${file}`)).text());
  renderList(side);
}

/* ---------- steps ---------- */

function step(name, state, detail) {
  const li = $(`#steps [data-step="${name}"]`);
  li.dataset.state = state;
  $(".detail", li)?.remove();
  if (detail) li.insertAdjacentHTML("beforeend", `<span class="detail">${detail}</span>`);
}

function updateRunButton() {
  const ready = firms.incoming.envelope && firms.existing.envelope && model;
  $("#run-check").disabled = !ready;
  const n = ["incoming", "existing"].filter((s) => firms[s].envelope).length;
  $("#check-hint").className = "hint";
  $("#check-hint").textContent = ready ? "Both lists are sealed and signed. Nothing readable leaves this page." : `Seal both lists to start (${n} of 2 sealed).`;
  if (n) step("seal", n === 2 ? "done" : "busy", `${n} of 2 sealed and signed by the firm's NEAR-registered key`);
}

/* ---------- enclave ---------- */

async function attest(fresh = false) {
  const dot = $(".dot"); dot.dataset.state = "pending";
  $("#enclave-text").textContent = "Checking the enclave…";
  step("attest", "busy");
  try {
    model = await api(`/api/attest${fresh ? "?fresh=1" : ""}`);
    dot.dataset.state = "ok";
    S.setState("ok");
    $("#enclave-text").textContent = `Enclave verified, ${model.tcb_status === "UpToDate" ? "firmware up to date" : model.tcb_status}`;
    $("#model-name").textContent = model.model;
    step("attest", "done", `Model key <span class="mono">${short(model.signing_key)}</span>`);
  } catch (e) {
    dot.dataset.state = "bad";
    S.setState("bad");
    $("#enclave-text").textContent = "Enclave not verified";
    step("attest", "fail", esc(e.message));
  }
  updateRunButton();
}

/* ---------- identity ---------- */

function identityChip(acct, registeredKey, localKey, url, label) {
  const ok = registeredKey && localKey && registeredKey === localKey;
  return `<a class="ident ${ok ? "ok" : "bad"}" href="${esc(url)}" target="_blank" rel="noopener" title="${esc(acct)}">
    <span class="ident-who">${esc(label)}</span>
    <span class="mono">${esc(acct)}</span>
    <span class="ident-key">${ok ? "Key matches NEAR registry" : registeredKey ? "Key does NOT match NEAR" : "Not registered on NEAR"} · <span class="mono">${short(registeredKey || localKey || "", 6)}</span></span>
  </a>`;
}

async function loadFirmIdentity(side) {
  const f = config.firms[side];
  let local = null;
  try { local = loadIdentity(await api(`/api/demo/identity/${f.account}`)); } catch (e) { console.warn(e); }
  $(`#firm-${side} .ident-slot`).innerHTML = identityChip(f.account, f.key, local?.pk, f.url, "Signs as");
  const ok = local && local.pk === f.key;
  step("identity", ok ? (step._ok = (step._ok || 0) + 1) === 2 ? "done" : "busy" : "fail",
    ok ? "Each firm's key is the one registered on the Sealroom contract" : esc(`No matching key for ${f.account}`));
  return ok;
}

/* ---------- conflict check ---------- */

let opening = null; // both firms seal into the same check, even when sealed at the same moment
async function ensureRoom() {
  if (room) return room;
  opening ||= api("/api/check/open", { incoming_count: firms.incoming.parties.length, existing_count: firms.existing.parties.length })
    .finally(() => { opening = null; });
  room = await opening;
  return room;
}

function setupFirm(side, file) {
  const el = $(`#firm-${side}`);
  $(".firm-name", el).textContent = config.firms[side].name || config.firms[side].account;
  loadDemo(side, file);
  $("input[type=file]", el).addEventListener("change", async (e) => {
    const f = e.target.files[0];
    if (!f || room) return;
    firms[side].parties = parseCSV(await f.text());
    renderList(side);
  });
  $(".seal-btn", el).addEventListener("click", async () => {
    if (el.dataset.sealed !== undefined || el.dataset.sealing !== undefined || !model) return;
    const btn = $(".seal-btn", el);
    btn.textContent = "Sealing…";
    el.dataset.sealing = "";
    try {
      await ensureRoom();
      await sealList(side);
    } catch (e) {
      delete el.dataset.sealing;
      btn.textContent = "Seal this list";
      $("#check-hint").className = "hint error";
      $("#check-hint").textContent = e.message;
      return;
    }
    el.dataset.sealed = "";
    await new Promise((r) => setTimeout(r, 380));
    await S.absorb($$(".list .name", el));
    btn.textContent = "Sealed and signed";
    el.insertAdjacentHTML("beforeend",
      `<p class="commit">Commitment <span class="mono">${short(firms[side].envelope.commitment, 12)}</span> · ${firms[side].envelope.ciphertexts.length} sealed chunk(s) · <a href="#" class="receipt">Save receipt</a></p>`);
    $(".receipt", el).addEventListener("click", (ev) => {
      ev.preventDefault();
      const blob = new Blob([JSON.stringify(firms[side].secret, null, 2)], { type: "application/json" });
      Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `${side}.receipt.json` }).click();
    });
    updateRunButton();
  });
}

$("#run-check").addEventListener("click", async () => {
  const btn = $("#run-check");
  btn.disabled = true;
  let current = "exact";
  try {
    step("exact", "busy", "Firms swap blinded names, each signed");
    await psiDouble("incoming"); await psiDouble("existing");
    const ni = await psiIndex("incoming"); await psiIndex("existing");
    step("exact", "done", `${ni ? `${ni} exact name match${ni > 1 ? "es" : ""}` : "No exact name matches"}, found without revealing anything else`);

    current = "send";
    step("send", "busy", `Every chunk pair goes to the enclave; the server sees ciphertext and entry numbers only`);
    S.working(true);
    const res = await api(`/api/check/${room.check_ref}/run`, {});
    S.working(false);
    step("send", "done", `${res.verdict.calls} enclave call${res.verdict.calls > 1 ? "s" : ""}${res.verdict.truncated ? ", but some replies were cut off" : ", every chunk pair covered"}`);
    step("sign", "done", `${res.calls.length} reply signature${res.calls.length > 1 ? "s" : ""} by <span class="mono">${short(res.calls[0]?.signer)}</span>`);
    current = "anchor";
    step("anchor", "busy");
    await S.drop($("#ledger-check"));
    addLedger("#ledger-check", `#${res.check_id}`, res.tx_url, `Check ${res.check_id} on NEAR`);
    step("anchor", "done", `NEAR verified both firms' and the enclave's signatures · check #${esc(res.check_id)}`);

    current = "reveal";
    step("reveal", "busy");
    await discloseMatches("incoming", res.verdict);
    const named = await discloseMatches("existing", res.verdict);
    step("reveal", "done", `Each firm disclosed only its ${res.verdict.pairs.length} matched entr${res.verdict.pairs.length === 1 ? "y" : "ies"}, signed`);
    await showVerdict(res, named.named);
    btn.textContent = "Check recorded";
    $("#check-hint").textContent = "Reload the page to run another check.";
  } catch (e) {
    S.working(false);
    step(current, "fail", esc(e.message));
    $("#check-hint").className = "hint error";
    $("#check-hint").textContent = e.message;
    btn.disabled = false; // the sealed lists and signed exact-match messages stay valid; retry is safe
  }
});

function addLedger(sel, label, href, title) {
  $(`${sel} ol`).insertAdjacentHTML("beforeend",
    `<li><a href="${esc(href || "#")}" target="_blank" rel="noopener" title="${esc(title)}">${esc(label)}</a></li>`);
}

const REL = { same_entity: "Same entity", former_name: "Former name", parent_subsidiary: "Parent and subsidiary", affiliate: "Affiliated", shared_officer: "Shared officer" };
const BASIS = { name: "the names", alias: "an alias", related_incoming: "the incoming note", related_existing: "the existing note", related_both: "both notes" };
const SEV = { high: "Direct adversity", review: "Both clients · review", low: "Both adverse · low" };
const SOURCE = { exact: "exact name match", enclave: "enclave", both: "exact match, confirmed by the enclave" };

async function showVerdict(res, named) {
  const hits = named.flatMap((c) => [$(`#firm-incoming .list li[data-i="${c.i}"]`), $(`#firm-existing .list li[data-i="${c.j}"]`)]).filter(Boolean);
  const uniq = [...new Set(hits)];
  await S.beams(uniq);
  uniq.forEach((li, i) => { li.style.setProperty("--i", i); li.classList.add("match"); });
  const v = $("#verdict");
  v.hidden = false;
  v.innerHTML = `<h3>${named.length ? `${named.length} potential conflict${named.length > 1 ? "s" : ""}` : "No conflicts found"}</h3>
    ${named.map((c) => `<div class="pair"><span class="sev ${c.severity}">${SEV[c.severity]}</span>
      <b>${esc(c.incoming.name)}</b> <span class="muted">(${esc(c.incoming.role)})</span> and <b>${esc(c.existing.name)}</b> <span class="muted">(${esc(c.existing.role)})</span>
      <span class="rel">${REL[c.relationship] || esc(c.relationship)}, ${Math.round(c.confidence * 100)}% · from ${BASIS[c.basis] || esc(c.basis)} · ${SOURCE[c.source]}</span>
      ${c.incoming.related || c.existing.related ? `<span class="rel">${[c.incoming.related, c.existing.related].filter(Boolean).map(esc).join(" · ")}</span>` : ""}</div>`).join("")}
    <div class="proof">
      <span>The server only ever saw entry numbers. Everything else in both lists stayed sealed.</span>
      ${res.verdict.truncated ? `<span class="error">Some enclave replies were cut off; there may be more pairs.</span>` : ""}
      <a href="${esc(res.tx_url)}" target="_blank" rel="noopener">See check #${esc(res.check_id)} on NEAR</a>
      <a href="/api/check/${esc(res.check_id)}/bundle" download>Download the proof bundle</a>
      <a href="#" id="go-verify">Replay every proof</a>
    </div>`;
  $("#go-verify").addEventListener("click", (e) => { e.preventDefault(); $("#kind").value = "check"; $("#ref").value = res.check_id; switchTab("verify"); $("#lookup").requestSubmit(); });
}

/* ---------- agent ---------- */

$$(".lens button").forEach((b) => b.addEventListener("click", () => {
  $$(".lens button").forEach((x) => x.setAttribute("aria-checked", x === b));
  $("#turns").dataset.lens = b.dataset.lens;
}));

function renderAgentIdentity() {
  const a = config.agent;
  $("#agent-ident").innerHTML = a.firm ? `
    <a href="${esc(a.url)}" target="_blank" rel="noopener" class="mono">${esc(a.account)}</a>
    <dl class="record small">
      <dt>Owner</dt><dd class="mono">${esc(a.owner)}</dd>
      <dt>Model</dt><dd class="mono">${esc(a.model)}</dd>
      <dt>Prompt</dt><dd>${a.prompt_matches ? "matches the hash registered on NEAR" : "<span class='error'>differs from NEAR</span>"}</dd>
      <dt>Key</dt><dd>can only call <span class="mono">seal_session</span></dd>
    </dl>` : `<span class="error">Agent not registered. Run <span class="mono">sealroom setup</span>.</span>`;
}

async function renderMember() {
  const acct = $("#person").value;
  const m = config.members.find((x) => x.account === acct);
  let local = ids[acct];
  if (!local) { try { local = loadIdentity(await api(`/api/demo/identity/${acct}`)); } catch { /* shown below */ } }
  $("#member-ident").innerHTML = identityChip(acct, m?.key, local?.pk, m?.url, m ? m.name : "Member");
}

$("#ask").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#ask button[type=submit]");
  btn.disabled = true;
  const turns = $("#turns");
  turns.innerHTML = `<li class="empty">Preparing the session for signature…</li>`;
  $("#answer").hidden = true;
  const member = $("#person").value;
  try {
    const prep = await api("/api/agent/prepare", { member, question: $("#question").value.trim(), use_verdict: $("#use-verdict").checked });
    if (!ids[member]) throw new Error(`No key for ${member} in this browser`);
    const authorization = sign(member, prep.message);
    turns.innerHTML = `<li><span class="what">Signed by ${esc(ids[member].name)}</span>
      <span class="said">Session ${esc(prep.session_id)}, agent ${esc(prep.agent)}</span>
      <span class="reason mono">${esc(prep.message)}</span></li>`;
    S.working(true);
    const res = await fetch("/api/agent/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ session_id: prep.session_id, authorization }) });
    if (!res.ok) throw new Error((await res.json()).detail);
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (line.startsWith("data: ")) onAgentEvent(JSON.parse(line.slice(6)));
      }
    }
    await agentQueue;
  } catch (err) {
    turns.insertAdjacentHTML("beforeend", `<li class="block"><span class="what">Stopped</span><span class="said">${esc(err.message)}</span></li>`);
  }
  S.working(false);
  btn.disabled = false;
});

let agentQueue = Promise.resolve();
function onAgentEvent(ev) { agentQueue = agentQueue.then(() => handleAgentEvent(ev)); }

async function handleAgentEvent(ev) {
  const turns = $("#turns");
  if (ev.type === "start") {
    const screens = Object.values(ev.policy.screens).flat();
    turns.insertAdjacentHTML("beforeend", `<li data-session="${esc(ev.session_id)}"><span class="what">Session ${esc(ev.session_id)}</span>
      <span class="reason">${screens.length ? `Walled off for ${esc(ev.member_name)}: <b>${screens.map(esc).join(", ")}</b>` : `No walls apply to ${esc(ev.member_name)}`}</span></li>`);
  } else if (ev.type === "step") {
    const t = ev.turn, a = t.action;
    const sig = `<span class="sig">Enclave-signed reply <span class="mono">${short(t.chat_id, 8)}</span></span>`;
    if (a.action === "read") {
      const d = t.decision;
      turns.insertAdjacentHTML("beforeend", `<li class="${d.allowed ? "allow" : "block"} pending">
        <span class="what">Reads ${esc(a.id)}</span>
        <span class="said">${d.allowed ? "Gets the document." : "Told: “Access to this material is not available in this session.”"}</span>
        <span class="reason"><b>${d.allowed ? "Allowed" : "Blocked"}</b>: ${esc(d.reason)}</span>${sig}</li>`);
      const li = turns.lastElementChild;
      await S.read(li, d.allowed);
      li.classList.remove("pending");
    } else {
      turns.insertAdjacentHTML("beforeend", `<li><span class="what">Answers</span>${sig}</li>`);
    }
  } else if (ev.type === "done") {
    if (ev.chain) {
      await S.drop($("#ledger-agent"));
      addLedger("#ledger-agent", `${ev.blocked}/${ev.decisions}`, ev.chain.url, "Sealed session on NEAR: blocked / decisions");
    }
    const a = $("#answer");
    a.hidden = false;
    a.innerHTML = `<h3>Answer</h3><p>${esc(ev.answer)}</p>
      <div class="proof"><span>${ev.decisions} decision${ev.decisions === 1 ? "" : "s"}, ${ev.blocked} blocked. Log root <span class="mono">${short(ev.log_root)}</span></span>
      ${ev.chain ? `<a href="${esc(ev.chain.url)}" target="_blank" rel="noopener">Sealed by ${esc(config.agent.account)} on NEAR</a>` : ""}
      <a href="#" id="verify-session">Verify the session</a></div>`;
    const sid = $("#turns [data-session]").dataset.session;
    $("#verify-session").addEventListener("click", (e) => { e.preventDefault(); $("#kind").value = "session"; $("#ref").value = sid; switchTab("verify"); $("#lookup").requestSubmit(); });
  } else if (ev.type === "error") {
    turns.insertAdjacentHTML("beforeend", `<li class="block"><span class="what">Stopped</span><span class="said">${esc(ev.message)}</span></li>`);
  }
}

/* ---------- verify ---------- */

$("#lookup").addEventListener("submit", async (e) => {
  e.preventDefault();
  const kind = $("#kind").value, ref = $("#ref").value.trim();
  const out = $("#verify-out");
  if (!ref) { out.innerHTML = `<p class="hint error">Enter a ${kind === "check" ? "check number" : "session id"}.</p>`; return; }
  out.innerHTML = `<p class="hint">Reading NEAR and replaying the proofs…</p>`;
  let body;
  try { body = await api(kind === "check" ? `/api/check/${encodeURIComponent(ref)}/verify` : `/api/session/${encodeURIComponent(ref)}/verify`); }
  catch (err) { out.innerHTML = `<p class="hint error">${esc(err.message)}</p>`; return; }
  const rec = body.record, m = (h) => `<span class="mono">${esc(h)}</span>`;
  const rows = kind === "check"
    ? [["Incoming firm", m(rec.incoming.firm)], ["Existing firm", m(rec.existing.firm)], ["Conflicts", rec.conflicts_found],
       ["Exact matches", rec.exact_matches], ["Cut off", rec.truncated ? "yes" : "no"], ["Enclave calls", rec.calls],
       ["Incoming list", m(rec.incoming.commitment)], ["Existing list", m(rec.existing.commitment)],
       ["Verdict hash", m(rec.verdict_hash)], ["Model", m(rec.engine.model)], ["Model key", m(rec.engine.model_key)],
       ["Instructions", m(rec.engine.instructions_hash)], ["Recorded by", m(rec.recorded_by)],
       ["Proof bundle", `<a href="/api/check/${esc(rec.id)}/bundle" download>download</a>`]]
    : [["Agent", m(rec.agent)], ["Member", `${esc(body.member?.name || "")} ${m(rec.member)}`], ["Firm", m(rec.firm)], ["Decisions", rec.decisions], ["Blocked", rec.blocked],
       ["Log root", m(rec.log_root)], ["Policy", m(rec.policy_hash)], ["Question", m(rec.question_hash)]];
  out.innerHTML = body.steps.map((s) => `<div class="vstep ${s.ok ? "ok" : "bad"}">${esc(s.text)}</div>`).join("")
    + `<dl class="record">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${typeof v === "string" && v.startsWith("<") ? v : esc(v)}</dd>`).join("")}</dl>`;
});

/* ---------- tabs, boot ---------- */

function switchTab(name) {
  if (stage) stage.anchor(name === "check" ? $("#stage-check") : name === "agent" ? $("#stage-agent") : null, { wall: name === "agent" });
  $$(".tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === name));
  $$(".tab").forEach((t) => (t.hidden = t.id !== `tab-${name}`));
}
$$(".tabs button").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));
$("#enclave").addEventListener("click", () => attest(true));

if (stage) stage.anchor($("#stage-check"));
config = await api("/api/config");
$("#contract-link").textContent = config.contract;
$("#contract-link").href = `${config.explorer}/address/${config.contract}`;
setupFirm("incoming", "partner_incoming.csv");
setupFirm("existing", "firm_existing.csv");
step("identity", "busy");
loadFirmIdentity("incoming");
loadFirmIdentity("existing");
$("#person").innerHTML = config.members.map((m) => `<option value="${esc(m.account)}">${esc(m.name)} (${esc(m.account.split(".")[0])})</option>`).join("");
$("#person").addEventListener("change", renderMember);
renderMember();
renderAgentIdentity();
attest();

// Test hook: lets the interop test drive the same functions the page uses.
window.__sealroom = { encryptTo, canonical, normalise, elements, hashToPoint, mul, setHash, envelopeMessage, firms };
