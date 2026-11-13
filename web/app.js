import _sodium from "https://cdn.jsdelivr.net/npm/libsodium-wrappers-sumo@0.7.15/+esm";
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

const pad = (i) => String(i).padStart(2, "0");
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

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

// Sealed names show as redaction bars: that is all the server ever sees. After a check,
// only the entries a firm disclosed come back, tagged with their conflict letters.
const barWidth = (name) => Math.min(92, 20 + name.length * 2.4);
function renderList(side) {
  const el = $(`#firm-${side}`), f = firms[side], sealed = el.dataset.sealed !== undefined;
  $(".list", el).innerHTML = f.parties.map((p, i) => {
    const m = f.matches?.[i];
    const cell = m
      ? `${m.refs.map((r) => `<span class="ref ${m.sev}">${r}</span>`).join("")}<span class="name">${esc(p.name)}</span>`
      : sealed ? `<span class="bar" role="img" aria-label="Sealed name" style="width:${barWidth(p.name)}%"></span>`
      : `<span class="name">${esc(p.name)}</span>`;
    return `<li class="row${m ? ` match ${m.sev}` : ""}" style="--i:${i}" data-i="${i}"><span class="n">${pad(i)}</span><span class="p">${cell}</span><span class="r">${esc(p.role)}</span></li>`;
  }).join("");
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
    $("#enclave-text").textContent = `Enclave verified, ${model.tcb_status === "UpToDate" ? "firmware up to date" : model.tcb_status}`;
    $("#model-name").textContent = model.model;
    step("attest", "done", `Model key <span class="mono">${short(model.signing_key)}</span>`);
  } catch (e) {
    dot.dataset.state = "bad";
    $("#enclave-text").textContent = "Enclave not verified";
    step("attest", "fail", esc(e.message));
  }
  updateRunButton();
}

/* ---------- identity ---------- */

function identityChip(acct, registeredKey, localKey, url, label) {
  const ok = registeredKey && localKey && registeredKey === localKey;
  const state = ok ? "key matches the NEAR registry" : registeredKey ? "key does not match the NEAR registry" : "not registered on NEAR";
  return `<p class="ident ${ok ? "ok" : "bad"}" title="Key ${esc(registeredKey || localKey || "")}">${label ? `${esc(label)} ` : ""}<a class="mono" href="${esc(url)}" target="_blank" rel="noopener">${esc(acct)}</a>, ${state}</p>`;
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
    delete el.dataset.sealing;
    renderList(side);
    $(".status", el).textContent = "Sealed and signed";
    const env = firms[side].envelope;
    $(".firm-foot", el).insertAdjacentHTML("beforeend",
      `<p class="commit"><span>Commitment <span class="mono ink">${short(env.commitment, 12)}</span></span><span>${plural(env.ciphertexts.length, "sealed chunk")}</span><a href="#" class="receipt">Save receipt</a></p>`);
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
    const res = await api(`/api/check/${room.check_ref}/run`, {});
    step("send", "done", `${res.verdict.calls} enclave call${res.verdict.calls > 1 ? "s" : ""}${res.verdict.truncated ? ", but some replies were cut off" : ", every chunk pair covered"}`);
    step("sign", "done", `${res.calls.length} reply signature${res.calls.length > 1 ? "s" : ""} by <span class="mono">${short(res.calls[0]?.signer)}</span>`);
    current = "anchor";
    step("anchor", "busy");
    addLedger("#ledger-check", `#${res.check_id}`, res.tx_url, `Check ${res.check_id} on NEAR`);
    step("anchor", "done", `NEAR checked both firms' and the enclave's signatures. Recorded as check #${esc(res.check_id)}`);

    current = "reveal";
    step("reveal", "busy");
    await discloseMatches("incoming", res.verdict);
    const named = await discloseMatches("existing", res.verdict);
    step("reveal", "done", `Each firm disclosed only its ${res.verdict.pairs.length} matched entr${res.verdict.pairs.length === 1 ? "y" : "ies"}, signed`);
    await showVerdict(res, named.named);
    $("#steps-title").textContent = "How this check ran";
    $(".check span").textContent = `Wall off the conflicts from check #${res.check_id}`;
    btn.textContent = "Check recorded";
    $("#check-hint").textContent = "Reload the page to run another check.";
  } catch (e) {
    step(current, "fail", esc(e.message));
    $("#check-hint").className = "hint error";
    $("#check-hint").textContent = e.message;
    btn.disabled = false; // the sealed lists and signed exact-match messages stay valid; retry is safe
  }
});

function addLedger(sel, label, href, title) {
  $$(`${sel} li.new`).forEach((li) => li.classList.remove("new"));
  $(`${sel} ol`).insertAdjacentHTML("beforeend",
    `<li class="new"><a href="${esc(href || "#")}" target="_blank" rel="noopener" title="${esc(title)}">${esc(label)}</a></li>`);
}

const REL = { same_entity: "Same entity", former_name: "Former name", parent_subsidiary: "Parent and subsidiary", affiliate: "Affiliated", shared_officer: "Shared officer" };
const BASIS = { name: "the names", alias: "an alias", related_incoming: "the incoming note", related_existing: "the existing note", related_both: "both notes" };
const SEV = { high: "Direct adversity", review: "Review", low: "Low" };
const HOW = (c) => c.source === "exact" ? "Exact name match"
  : c.source === "both" ? "Exact name match, confirmed by the enclave"
  : `Enclave, from ${BASIS[c.basis] || esc(c.basis)}`;
const letter = (k) => (k < 26 ? String.fromCharCode(65 + k) : String(k + 1));

function verdictSummary(named) {
  const n = (s) => named.filter((c) => c.severity === s).length;
  const parts = [];
  if (n("high")) parts.push(`${n("high")} ${n("high") === 1 ? "is" : "are"} direct adversity.`);
  if (n("review")) parts.push(`${n("review")} involve${n("review") === 1 ? "s" : ""} clients of both firms and need${n("review") === 1 ? "s" : ""} a review.`);
  if (n("low")) parts.push(`${n("low")} ${n("low") === 1 ? "has" : "have"} both parties adverse, which is low risk.`);
  return parts.join(" ");
}

async function showVerdict(res, named) {
  // Tag each matched entry in both registers with the letters of its conflicts.
  const rank = { high: 0, review: 1, low: 2 };
  for (const side of ["incoming", "existing"]) firms[side].matches = {};
  named.forEach((c, k) => {
    for (const [side, i] of [["incoming", c.i], ["existing", c.j]]) {
      const m = (firms[side].matches[i] ||= { refs: [], sev: c.severity });
      m.refs.push(letter(k));
      if (rank[c.severity] < rank[m.sev]) m.sev = c.severity;
    }
  });
  for (const side of ["incoming", "existing"]) renderList(side);

  const nameOf = (side) => esc(config.firms[side].name || config.firms[side].account);
  const v = $("#verdict");
  v.hidden = false;
  v.innerHTML = `<div class="verdict-head">
      <div>
        <h2 id="verdict-title" class="${named.length ? "" : "clear"}">${named.length ? plural(named.length, "potential conflict") : "No conflicts found"}</h2>
        <p>${named.length ? verdictSummary(named) : "Nothing in either list matched, by name or by relationship."}</p>
      </div>
      <div class="links">
        <a href="${esc(res.tx_url)}" target="_blank" rel="noopener">Check #${esc(res.check_id)} on NEAR</a>
        <a href="/api/check/${esc(res.check_id)}/bundle" download>Download the proof bundle</a>
        <a href="#" id="go-verify">Replay every proof</a>
      </div>
    </div>
    ${named.length ? `<div class="table-scroll"><table class="vt">
      <thead><tr><th>Conflict</th><th>${nameOf("incoming")}</th><th>${nameOf("existing")}</th><th>Relationship</th><th>How it was found</th></tr></thead>
      <tbody>${named.map((c, k) => {
        const notes = [c.incoming.related, c.existing.related].filter(Boolean).map(esc).join(". ");
        return `<tr>
          <td><span class="ref ${c.severity}">${letter(k)}</span><span class="sev ${c.severity}">${SEV[c.severity] || esc(c.severity)}</span></td>
          <td><span class="who">${esc(c.incoming.name)}</span><br><span class="sm">${esc(c.incoming.role)}, entry ${pad(c.i)}</span></td>
          <td><span class="who">${esc(c.existing.name)}</span><br><span class="sm">${esc(c.existing.role)}, entry ${pad(c.j)}</span></td>
          <td>${REL[c.relationship] || esc(c.relationship)} <span class="muted">${Math.round(c.confidence * 100)}%</span>${notes ? `<br><span class="sm">${notes}</span>` : ""}</td>
          <td class="sm">${HOW(c)}</td>
        </tr>`;
      }).join("")}</tbody>
    </table></div>` : ""}
    ${res.verdict.truncated ? `<p class="foot-note error">Some enclave replies were cut off, so there may be more conflicts than shown.</p>` : ""}
    <p class="foot-note">The server only saw entry numbers. Each firm disclosed its own matched entries, signed. Every other entry stays sealed.</p>`;
  $("#go-verify").addEventListener("click", (e) => { e.preventDefault(); $("#kind").value = "check"; syncRefLabel(); $("#ref").value = res.check_id; switchTab("verify"); $("#lookup").requestSubmit(); });
  v.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

/* ---------- agent ---------- */

$$(".lens button").forEach((b) => b.addEventListener("click", () => {
  $$(".lens button").forEach((x) => x.setAttribute("aria-checked", x === b));
  $("#turns").dataset.lens = b.dataset.lens;
}));

function renderAgentIdentity() {
  const a = config.agent;
  $("#agent-ident").innerHTML = a.firm ? `
    <dl class="rec">
      <dt>Account</dt><dd><a class="mono" href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.account)}</a></dd>
      <dt>Owner</dt><dd class="mono">${esc(a.owner)}</dd>
      <dt>Model</dt><dd class="mono">${esc(a.model)}</dd>
      <dt>Prompt</dt><dd>${a.prompt_matches ? "Matches the hash registered on NEAR" : "<span class='error'>Differs from the hash on NEAR</span>"}</dd>
      <dt>Key</dt><dd>Can only call <span class="mono">seal_session</span></dd>
    </dl>` : `<p class="error">The agent is not registered yet. Run <span class="mono">sealroom setup</span>.</p>`;
}

async function renderMember() {
  const acct = $("#person").value;
  const m = config.members.find((x) => x.account === acct);
  let local = ids[acct];
  if (!local) { try { local = loadIdentity(await api(`/api/demo/identity/${acct}`)); } catch { /* shown below */ } }
  $("#member-ident").innerHTML = identityChip(acct, m?.key, local?.pk, m?.url, "");
}

// One row of the session log. Callers pass text that is already escaped.
function turn({ cls = "", tag, what, said = "", reason = "", sig = "", mono = false }) {
  $("#turns").insertAdjacentHTML("beforeend", `<li class="${cls} enter"><span class="tag">${tag}</span>
    <span class="body"><span class="what">${what}</span>${said ? `<span class="said">${said}</span>` : ""}${reason ? `<span class="reason${mono ? " mono" : ""}">${reason}</span>` : ""}</span>
    <span class="sig" title="${sig ? "Reply signed by the enclave" : ""}">${sig}</span></li>`);
  return $("#turns").lastElementChild;
}

$("#ask").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#ask button[type=submit]");
  btn.disabled = true;
  $("#turns").innerHTML = "";
  $("#log-title").textContent = "Session log";
  $("#log-sub").textContent = "Preparing the session for signature…";
  $("#answer").hidden = true;
  const member = $("#person").value;
  try {
    const prep = await api("/api/agent/prepare", { member, question: $("#question").value.trim(), use_verdict: $("#use-verdict").checked });
    if (!ids[member]) throw new Error(`No key for ${member} in this browser`);
    const authorization = sign(member, prep.message);
    $("#log-title").innerHTML = `Session <span class="mono">${esc(prep.session_id)}</span>`;
    $("#log-sub").textContent = `Signed by ${ids[member].name}. Waiting for the agent…`;
    turn({ tag: "Signed", what: `${esc(ids[member].name)} signed the session for ${esc(prep.agent)}`, reason: esc(prep.message), mono: true });
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
    turn({ cls: "block", tag: "Stopped", what: esc(err.message) });
    $("#log-sub").textContent = "The session stopped before it was sealed.";
  }
  btn.disabled = false;
});

let agentQueue = Promise.resolve();
function onAgentEvent(ev) { agentQueue = agentQueue.then(() => handleAgentEvent(ev)); }

const REFUSAL = "Told: Access to this material is not available in this session.";
let sessionId = null;

async function handleAgentEvent(ev) {
  if (ev.type === "start") {
    sessionId = ev.session_id;
    const screens = Object.values(ev.policy.screens).flat();
    $("#log-sub").textContent = `Signed by ${ev.member_name}. ${screens.length ? `Walled off: ${screens.join(", ")}.` : `No walls apply to ${ev.member_name}.`}`;
  } else if (ev.type === "step") {
    const t = ev.turn, a = t.action, sig = esc((t.chat_id || "").slice(0, 8));
    if (a.action === "read") {
      const d = t.decision;
      turn({ cls: d.allowed ? "allow" : "block", tag: d.allowed ? "Allowed" : "Refused", what: `Asks for ${esc(a.id)}`,
        said: d.allowed ? "Gets the document." : REFUSAL, reason: esc(d.reason), sig });
    } else {
      turn({ tag: "Answers", what: "Writes the answer from what it was allowed to read", sig });
    }
  } else if (ev.type === "done") {
    if (ev.chain) addLedger("#ledger-agent", `${ev.blocked}/${ev.decisions}`, ev.chain.url, "Sealed session on NEAR: refused / reads");
    const a = $("#answer");
    a.hidden = false;
    a.innerHTML = `<h3>Answer</h3><p>${esc(ev.answer)}</p>
      <div class="links"><span>${plural(ev.decisions, "read")}, ${ev.blocked} refused</span>
      <span>Log root <span class="mono ink">${short(ev.log_root)}</span></span>
      ${ev.chain ? `<a href="${esc(ev.chain.url)}" target="_blank" rel="noopener">Sealed on NEAR by the agent</a>` : `<span class="error">Not sealed on NEAR</span>`}
      <a href="#" id="verify-session">Verify the session</a></div>`;
    $("#verify-session").addEventListener("click", (e) => { e.preventDefault(); $("#kind").value = "session"; syncRefLabel(); $("#ref").value = sessionId; switchTab("verify"); $("#lookup").requestSubmit(); });
  } else if (ev.type === "error") {
    turn({ cls: "block", tag: "Stopped", what: esc(ev.message) });
  }
}

/* ---------- verify ---------- */

const TICK = `<svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="9" r="8" fill="#1C6B45"/><path d="M5.2 9.2l2.6 2.6 5-5.2" fill="none" stroke="#fff" stroke-width="1.8"/></svg>`;
const CROSS = `<svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="9" r="8" fill="#B42318"/><path d="M6 6l6 6M12 6l-6 6" fill="none" stroke="#fff" stroke-width="1.8"/></svg>`;

function syncRefLabel() {
  const check = $("#kind").value === "check";
  $("#ref-label").textContent = check ? "Check number" : "Session id";
  $("#ref").placeholder = check ? "0" : "3edd3560df214b56";
}
$("#kind").addEventListener("change", syncRefLabel);

$("#lookup").addEventListener("submit", async (e) => {
  e.preventDefault();
  const kind = $("#kind").value, ref = $("#ref").value.trim();
  const out = $("#verify-out");
  if (!ref) { out.innerHTML = `<p class="panel state error">Enter a ${kind === "check" ? "check number" : "session id"}.</p>`; return; }
  out.innerHTML = `<p class="panel state">Reading NEAR and replaying the proofs…</p>`;
  let body;
  try { body = await api(kind === "check" ? `/api/check/${encodeURIComponent(ref)}/verify` : `/api/session/${encodeURIComponent(ref)}/verify`); }
  catch (err) { out.innerHTML = `<p class="panel state error">${esc(err.message)}</p>`; return; }
  const rec = body.record, m = (h) => `<span class="mono">${esc(h)}</span>`;
  const rows = kind === "check"
    ? [["Incoming firm", m(rec.incoming.firm)], ["Receiving firm", m(rec.existing.firm)],
       ["Conflicts", `${rec.conflicts_found}, of which ${plural(rec.exact_matches, "exact match", "exact matches")}`],
       ["Enclave calls", `${rec.calls}, ${rec.truncated ? "some cut off" : "none cut off"}`],
       ["Incoming list", m(rec.incoming.commitment)], ["Receiving list", m(rec.existing.commitment)],
       ["Verdict hash", m(rec.verdict_hash)], ["Model", m(rec.engine.model)], ["Model key", m(rec.engine.model_key)],
       ["Instructions", m(rec.engine.instructions_hash)], ["Recorded by", m(rec.recorded_by)],
       ["Proof bundle", `<a href="/api/check/${esc(rec.id)}/bundle" download>Download sealroom-check-${esc(rec.id)}.json</a>`]]
    : [["Agent", m(rec.agent)], ["Member", `${esc(body.member?.name || "")} ${m(rec.member)}`], ["Firm", m(rec.firm)],
       ["Reads", rec.decisions], ["Refused", rec.blocked],
       ["Log root", m(rec.log_root)], ["Policy", m(rec.policy_hash)], ["Question", m(rec.question_hash)]];
  const passed = body.steps.filter((s) => s.ok).length, all = passed === body.steps.length;
  const what = kind === "check" ? `Check #${esc(ref)}` : `Session ${esc(ref)}`;
  out.innerHTML = `<div class="results">
    <section class="panel checks">
      <div class="results-head"><h2>${what} ${all ? "holds up" : "does not hold up"}</h2>
        <span class="${all ? "ok" : "bad"}">${passed} of ${body.steps.length} checks passed</span></div>
      <ul class="vsteps">${body.steps.map((s) => `<li class="${s.ok ? "ok" : "bad"}">${s.ok ? TICK : CROSS}<span>${esc(s.text)}</span></li>`).join("")}</ul>
    </section>
    <section class="panel record-card">
      <h2>The record on NEAR</h2>
      <dl class="record">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${typeof v === "string" && v.startsWith("<") ? v : esc(v)}</dd>`).join("")}</dl>
    </section>
  </div>`;
});

/* ---------- tabs, boot ---------- */

function switchTab(name) {
  $$(".tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === name));
  $$(".tab").forEach((t) => (t.hidden = t.id !== `tab-${name}`));
}
$$(".tabs button").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));
$("#enclave").addEventListener("click", () => attest(true));

config = await api("/api/config");
$("#contract-link").textContent = config.contract;
$("#contract-link").href = `${config.explorer}/address/${config.contract}`;
setupFirm("incoming", "partner_incoming.csv");
setupFirm("existing", "firm_existing.csv");
step("identity", "busy");
loadFirmIdentity("incoming");
loadFirmIdentity("existing");
$("#person").innerHTML = config.members.map((m) => `<option value="${esc(m.account)}">${esc(m.name)}</option>`).join("");
$("#person").addEventListener("change", renderMember);
renderMember();
renderAgentIdentity();
attest();

// Test hook: lets the interop test drive the same functions the page uses.
window.__sealroom = { encryptTo, canonical, normalise, elements, hashToPoint, mul, setHash, envelopeMessage, firms };
