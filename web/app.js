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


/* ---------- small UI helpers ---------- */

const ICON_OK = `<svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><circle cx="7" cy="7" r="6.5" fill="#1C6B45"/><path d="M4.2 7.2l1.9 1.9 3.7-3.9" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const ICON_BAD = `<svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><circle cx="7" cy="7" r="6.5" fill="#B42318"/><path d="M4.8 4.8l4.4 4.4M9.2 4.8l-4.4 4.4" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/></svg>`;
const ICON_INFO = `<svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8 7.2V11.5M8 4.6v.1" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>`;
const ICON_DONE = `<svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7.5" fill="#3FA06C"/><path d="M4.8 8.2l2.2 2.2 4.3-4.6" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const ICON_DOWN = `<svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2.5V11M4.5 7.5L8 11l3.5-3.5M2.5 13.5h11" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
const sleep = (ms) => new Promise((r) => setTimeout(r, reduced() ? 0 : ms));
const clock = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
const firmName = (side) => config?.firms[side].name || (side === "incoming" ? "the incoming partner" : "the receiving firm");
const shortName = (side) => firmName(side).replace(/,?\s+(LLP|LLC|L\.L\.C\.|Ltd|Inc\.?|plc)$/i, "");

// Button state: label, spinner, enabled.
function setBtn(btn, { label, loading = false, disabled = loading, kind } = {}) {
  if (label !== undefined) $(".label", btn).textContent = label;
  btn.classList.toggle("loading", loading);
  btn.disabled = disabled;
  btn.setAttribute("aria-busy", loading);
  if (kind) { btn.classList.remove("primary", "dark", "ghost"); btn.classList.add(kind); }
}

function toast(html, { error = false, ms = 6000 } = {}) {
  const el = document.createElement("div");
  el.className = `toast${error ? " error" : ""}`;
  el.innerHTML = `${error ? ICON_INFO : ICON_DONE}<span>${html}</span>`;
  $("#toasts").appendChild(el);
  const close = () => { el.classList.add("out"); setTimeout(() => el.remove(), 260); };
  setTimeout(close, ms);
  return close;
}

/* ---------- lists ---------- */

// Sealed names show as redaction bars: that is all the server ever sees. After a check,
// only the entries a firm disclosed come back, tagged with their conflict letters.
const barWidth = (name) => Math.min(92, 20 + name.length * 2.4);
function renderList(side, { enter = false, reveal = false } = {}) {
  const el = $(`#firm-${side}`), f = firms[side], sealed = el.dataset.sealed !== undefined;
  let k = 0;
  $(".list", el).innerHTML = f.parties.length ? f.parties.map((p, i) => {
    const m = f.matches?.[i];
    const cell = m
      ? `${m.refs.map((r) => `<span class="ref ${m.sev}">${r}</span>`).join("")}<span class="name">${esc(p.name)}</span>`
      : sealed ? `<span class="bar" role="img" aria-label="Sealed name" style="width:${barWidth(p.name)}%"></span>`
      : `<span class="name">${esc(p.name)}</span>`;
    const cls = ["row", m ? `match ${m.sev}` : "", enter ? "enter" : "", m && reveal ? "reveal" : ""].filter(Boolean).join(" ");
    return `<li class="${cls}" style="--i:${m && reveal ? k++ : i}" data-i="${i}"><span class="n">${pad(i)}</span><span class="p">${cell}</span><span class="r">${esc(p.role)}</span></li>`;
  }).join("") : `<li class="row"><span></span><span class="p muted">This list is empty. Replace it with a CSV that has name and role columns.</span><span></span></li>`;
}

async function loadDemo(side, file) {
  firms[side].parties = parseCSV(await (await fetch(`/demo/${file}`)).text());
  renderList(side, { enter: true });
  $(`#firm-${side}`).setAttribute("aria-busy", "false");
}

/* ---------- steps and progress ---------- */

function step(name, state, detail) {
  const li = $(`#steps [data-step="${name}"]`);
  if (state) li.dataset.state = state; else delete li.dataset.state;
  $(".detail", li)?.remove();
  if (detail) li.insertAdjacentHTML("beforeend", `<span class="detail">${detail}</span>`);
  const done = $$("#steps li[data-state=done]").length, all = $$("#steps li").length;
  $("#progress-count").textContent = `${done} of ${all}`;
  $("#progress-bar").style.width = `${(done / all) * 100}%`;
}

/* ---------- the guided action ---------- */

const flow = { listsReady: 0, identities: 0, sealing: null, running: false, phase: "", startedAt: 0, error: null, done: null };
let tick = null;

function refreshAction() {
  const btn = $("#run-check"), hint = $("#check-hint");
  const nextSeal = ["incoming", "existing"].find((s) => !firms[s].envelope);
  const enclave = $("#enclave").dataset.state;
  const ready = config && model && flow.listsReady === 2;
  let s, text, err = false;
  if (flow.done !== null) { s = { label: "Start a new check", kind: "ghost" }; text = `Recorded on NEAR as check #${flow.done}.`; }
  else if (flow.running) { s = { label: `Checking… ${clock((Date.now() - flow.startedAt) / 1000)}`, loading: true }; text = flow.phase; }
  else if (enclave === "bad") { s = { label: "Check the enclave again", kind: "dark" }; text = "The enclave could not be verified, so nothing can be sealed yet."; err = true; }
  else if (flow.fatal) { s = { label: "Reload the page", kind: "dark" }; text = flow.fatal; err = true; }
  else if (!ready) { s = { label: "Getting ready…", loading: true }; text = "Checking the enclave and loading both lists."; }
  else if (flow.sealing) { s = { label: `Sealing ${shortName(flow.sealing)}'s list…`, loading: true }; text = "Encrypting each name to the enclave's key, then signing."; }
  else if (nextSeal) {
    s = { label: `Seal ${shortName(nextSeal)}'s list`, kind: "primary" };
    text = nextSeal === "incoming" ? "Each firm seals its own list. Names are encrypted in this browser before anything is sent." : "Now the receiving firm seals its list.";
  }
  else if (flow.error) { s = { label: "Try again", kind: "primary" }; text = flow.error; err = true; }
  else { s = { label: "Run conflict check", kind: "primary" }; text = "Takes about a minute. Nothing readable leaves this page."; }
  setBtn(btn, { kind: "primary", ...s });
  hint.textContent = text;
  hint.classList.toggle("error", err);
  const highlight = ready && !flow.sealing && !flow.running && flow.done === null ? nextSeal : null;
  for (const side of ["incoming", "existing"]) {
    const el = $(`#firm-${side}`), mine = firms[side];
    el.classList.toggle("is-next", side === highlight);
    const can = ready && !mine.envelope && !flow.sealing && !flow.running && flow.done === null;
    setBtn($(".seal-btn", el), { loading: flow.sealing === side, disabled: !can, label: flow.sealing === side ? "Sealing…" : "Seal this list" });
    $(".file", el).setAttribute("aria-disabled", String(!can));
  }
}

$("#run-check").addEventListener("click", () => {
  const nextSeal = ["incoming", "existing"].find((s) => !firms[s].envelope);
  if (flow.done !== null) return resetCheck();
  if (flow.fatal) return location.reload();
  if ($("#enclave").dataset.state === "bad") return attest(true);
  if (nextSeal) return sealSide(nextSeal);
  return runCheck();
});

/* ---------- enclave ---------- */

async function attest(fresh = false) {
  const b = $("#enclave");
  if (b.dataset.state === "pending" && fresh) return;
  b.dataset.state = "pending";
  $("#enclave-text").textContent = "Checking the enclave…";
  step("attest", "busy", "Asking NEAR AI Cloud for a fresh TDX quote");
  refreshAction();
  try {
    model = await api(`/api/attest${fresh ? "?fresh=1" : ""}`);
    b.dataset.state = "ok";
    const tcb = model.tcb_status === "UpToDate" ? "firmware up to date" : model.tcb_status;
    $("#enclave-text").innerHTML = `Enclave verified<span class="extra">, ${esc(tcb)}</span>`;
    $("#model-name").textContent = model.model;
    step("attest", "done", `Intel signed the quote. Model key <span class="mono">${short(model.signing_key, 8)}</span>`);
    if (fresh) toast("The enclave checked out again.");
  } catch (e) {
    model = null;
    b.dataset.state = "bad";
    $("#enclave-text").textContent = "Enclave not verified. Retry";
    step("attest", "fail", esc(e.message));
    toast(`The enclave could not be verified. ${esc(e.message)}`, { error: true });
  }
  refreshAction();
}

/* ---------- identity ---------- */

function identityChip(acct, registeredKey, localKey, url, label) {
  const ok = registeredKey && localKey && registeredKey === localKey;
  const state = ok ? "Key matches NEAR." : registeredKey ? "Key does not match NEAR." : "Not registered on NEAR.";
  return `<p class="ident ${ok ? "ok" : "bad"}" title="Key ${esc(registeredKey || localKey || "")}">${ok ? ICON_OK : ICON_BAD}<span>${label ? `${esc(label)} ` : ""}<a class="mono" href="${esc(url)}" target="_blank" rel="noopener">${esc(acct)}</a>. ${state}</span></p>`;
}

async function loadFirmIdentity(side) {
  const f = config.firms[side];
  let local = null;
  try { local = loadIdentity(await api(`/api/demo/identity/${f.account}`)); } catch (e) { console.warn(e); }
  $(`#firm-${side} .ident-slot`).innerHTML = identityChip(f.account, f.key, local?.pk, f.url, "Signs as");
  const ok = local && local.pk === f.key;
  if (!ok) { step("identity", "fail", esc(`No matching key for ${f.account}`)); return; }
  if (++flow.identities === 2) step("identity", "done", "Both keys match the Sealroom registry");
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

function sealedCount() { return ["incoming", "existing"].filter((s) => firms[s].envelope).length; }

async function sealSide(side) {
  const el = $(`#firm-${side}`);
  if (firms[side].envelope || flow.sealing || !model) return;
  flow.sealing = side;
  $(".status", el).dataset.state = "sealing";
  $(".status-text", el).textContent = "Sealing";
  step("seal", "busy", `Sealing ${esc(shortName(side))}'s list`);
  refreshAction();
  try {
    await ensureRoom();
    await sealList(side);
  } catch (e) {
    flow.sealing = null;
    $(".status", el).dataset.state = "open";
    $(".status-text", el).textContent = "Not sealed";
    step("seal", sealedCount() ? "busy" : undefined, sealedCount() ? "1 of 2 sealed" : "");
    toast(`Could not seal ${esc(shortName(side))}'s list. ${esc(e.message)}`, { error: true });
    refreshAction();
    return;
  }
  flow.sealing = null;
  el.dataset.sealed = "";
  el.classList.add("redacting");
  renderList(side);
  setTimeout(() => el.classList.remove("redacting"), 1200);
  $(".status", el).dataset.state = "sealed";
  $(".status-text", el).textContent = "Sealed and signed";
  const env = firms[side].envelope;
  $(".firm-foot", el).insertAdjacentHTML("beforeend",
    `<p class="commit"><span>Commitment <span class="mono ink">${short(env.commitment, 10)}</span></span><span>${plural(env.ciphertexts.length, "sealed chunk")}</span><a href="#" class="receipt">${ICON_DOWN}Save receipt</a></p>`);
  $(".receipt", el).addEventListener("click", (ev) => {
    ev.preventDefault();
    const blob = new Blob([JSON.stringify(firms[side].secret, null, 2)], { type: "application/json" });
    Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `${side}.receipt.json` }).click();
  });
  const n = sealedCount();
  step("seal", n === 2 ? "done" : "busy", n === 2 ? "Both lists sealed and signed" : "1 of 2 sealed and signed");
  refreshAction();
}

function setupFirm(side, file) {
  const el = $(`#firm-${side}`);
  $(".firm-name", el).textContent = firmName(side);
  loadDemo(side, file).then(() => { flow.listsReady++; refreshAction(); })
    .catch((e) => toast(`Could not load the demo list. ${esc(e.message)}`, { error: true }));
  $("input[type=file]", el).addEventListener("change", async (e) => {
    const f = e.target.files[0];
    e.target.value = "";
    if (!f || firms[side].envelope) return;
    const parties = parseCSV(await f.text());
    if (!parties.length) { toast(`${esc(f.name)} has no rows with a name. It needs name and role columns.`, { error: true }); return; }
    firms[side].parties = parties;
    renderList(side, { enter: true });
    toast(`Loaded ${plural(parties.length, "entry", "entries")} from ${esc(f.name)}.`);
  });
  $(".seal-btn", el).addEventListener("click", () => sealSide(side));
}

async function runCheck() {
  if (flow.running) return;
  flow.running = true; flow.error = null; flow.startedAt = Date.now();
  flow.phase = "Matching exact names. Neither firm learns anything but the overlap.";
  tick = setInterval(() => {
    refreshAction();
    const t = $("#steps .timer"); if (t) t.textContent = clock((Date.now() - flow.startedAt) / 1000);
  }, 500);
  refreshAction();
  let current = "exact";
  try {
    step("exact", "busy", "Firms swap blinded names, each signed");
    await psiDouble("incoming"); await psiDouble("existing");
    const ni = await psiIndex("incoming"); await psiIndex("existing");
    step("exact", "done", `${ni ? plural(ni, "exact name match", "exact name matches") : "No exact name matches"}, nothing else revealed`);

    current = "send";
    flow.phase = "The enclave is checking every pair of chunks. The server only sees ciphertext.";
    step("send", "busy", `Waiting for the enclave, <span class="timer">0:00</span>`);
    refreshAction();
    const res = await api(`/api/check/${room.check_ref}/run`, {});
    step("send", "done", `${plural(res.verdict.calls, "enclave call")}${res.verdict.truncated ? ", some replies cut off" : ", every chunk pair covered"}`);
    await sleep(220);
    step("sign", "done", `${plural(res.calls.length, "reply signature")} from <span class="mono">${short(res.calls[0]?.signer, 8)}</span>`);
    await sleep(220);
    current = "anchor";
    step("anchor", "done", `NEAR checked every signature. Recorded as check #${esc(res.check_id)}`);
    addLedger("#ledger-check", `#${res.check_id}`, res.tx_url, `Check ${res.check_id} on NEAR`);
    addRecent("check", String(res.check_id), `#${res.check_id}`);

    current = "reveal";
    flow.phase = "Each firm is disclosing its own matched entries, signed.";
    step("reveal", "busy");
    refreshAction();
    await discloseMatches("incoming", res.verdict);
    const named = await discloseMatches("existing", res.verdict);
    step("reveal", "done", `Only the ${plural(res.verdict.pairs.length, "matched entry", "matched entries")} came back, signed`);
    clearInterval(tick);
    flow.running = false;
    flow.done = res.check_id;
    $("#steps-title").textContent = "How this check ran";
    $("#use-verdict-text").textContent = `Wall off the conflicts from check #${res.check_id}`;
    showVerdict(res, named.named);
    toast(`Check #${esc(res.check_id)} recorded on NEAR. <a href="${esc(res.tx_url)}" target="_blank" rel="noopener">View transaction</a>`);
  } catch (e) {
    clearInterval(tick);
    flow.running = false;
    flow.error = `${e.message} Your sealed lists are still valid, so trying again is safe.`;
    step(current, "fail", esc(e.message));
    toast(esc(e.message), { error: true });
  }
  refreshAction();
}

function resetCheck() {
  room = null;
  flow.done = null; flow.error = null;
  for (const side of ["incoming", "existing"]) {
    const el = $(`#firm-${side}`), f = firms[side];
    delete f.envelope; delete f.secret; delete f.psi; delete f.doubledTheirs; delete f.matches;
    delete el.dataset.sealed;
    $(".status", el).dataset.state = "open";
    $(".status-text", el).textContent = "Not sealed";
    $(".commit", el)?.remove();
    renderList(side, { enter: true });
  }
  for (const s of ["seal", "exact", "send", "sign", "anchor", "reveal"]) step(s);
  $("#steps-title").textContent = "How this check runs";
  $("#verdict").hidden = true;
  $("#ledger-check li.new")?.classList.remove("new");
  refreshAction();
  $(".room").scrollIntoView({ behavior: reduced() ? "auto" : "smooth", block: "start" });
}

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

function showVerdict(res, named) {
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
  for (const side of ["incoming", "existing"]) renderList(side, { reveal: true });

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
      <thead><tr><th>Conflict</th><th>${esc(firmName("incoming"))}</th><th>${esc(firmName("existing"))}</th><th>Relationship</th><th>How it was found</th></tr></thead>
      <tbody>${named.map((c, k) => {
        const notes = [c.incoming.related, c.existing.related].filter(Boolean).map(esc).join(". ");
        return `<tr>
          <td><span class="ref ${c.severity}">${letter(k)}</span><span class="sev ${c.severity}">${SEV[c.severity] || esc(c.severity)}</span></td>
          <td data-label="${esc(firmName("incoming"))}"><span class="who">${esc(c.incoming.name)}</span><br><span class="sm">${esc(c.incoming.role)}, entry ${pad(c.i)}</span></td>
          <td data-label="${esc(firmName("existing"))}"><span class="who">${esc(c.existing.name)}</span><br><span class="sm">${esc(c.existing.role)}, entry ${pad(c.j)}</span></td>
          <td data-label="Relationship">${REL[c.relationship] || esc(c.relationship)} <span class="muted">${Math.round(c.confidence * 100)}%</span>${notes ? `<br><span class="sm">${notes}</span>` : ""}</td>
          <td class="sm" data-label="How it was found">${HOW(c)}</td>
        </tr>`;
      }).join("")}</tbody>
    </table></div>` : ""}
    ${res.verdict.truncated ? `<p class="foot-note error">Some enclave replies were cut off, so there may be more conflicts than shown.</p>` : ""}
    <p class="foot-note">The server only saw entry numbers. Each firm disclosed its own matched entries, signed. Every other entry stays sealed.</p>`;
  $("#go-verify").addEventListener("click", (e) => { e.preventDefault(); openVerify("check", res.check_id); });
  v.scrollIntoView({ behavior: reduced() ? "auto" : "smooth", block: "start" });
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
    </dl>` : `<p class="ident bad">${ICON_BAD}<span>The agent is not registered yet. Run <span class="mono">sealroom setup</span>.</span></p>`;
}

async function renderMember() {
  const acct = $("#person").value;
  const m = config.members.find((x) => x.account === acct);
  $("#member-ident").innerHTML = `<span class="sk" style="width:80%"></span>`;
  let local = ids[acct];
  if (!local) { try { local = loadIdentity(await api(`/api/demo/identity/${acct}`)); } catch { /* shown below */ } }
  if ($("#person").value !== acct) return;
  $("#member-ident").innerHTML = identityChip(acct, m?.key, local?.pk, m?.url, "");
}

// One row of the session log. Callers pass text that is already escaped.
function turn({ cls = "", tag, what, said = "", reason = "", sig = "", mono = false }) {
  $("#turns").insertAdjacentHTML("beforeend", `<li class="${cls}"><span class="tag">${tag}</span>
    <span class="body"><span class="what">${what}</span>${said ? `<span class="said">${said}</span>` : ""}${reason ? `<span class="reason${mono ? " mono" : ""}">${reason}</span>` : ""}</span>
    <span class="sig" title="${sig ? "Reply signed by the enclave" : ""}">${sig}</span></li>`);
  return $("#turns").lastElementChild;
}
function working(text) {
  const w = $("#agent-working");
  w.hidden = !text;
  if (text) $("#agent-working-text").textContent = text;
  $(".log").setAttribute("aria-busy", String(!!text));
}

let sessionId = null;
$("#ask").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#ask-btn");
  const question = $("#question").value.trim();
  if (!question) { $("#question").focus(); toast("Type a question for the agent first.", { error: true }); return; }
  setBtn(btn, { label: "Signing…", loading: true });
  $("#person").disabled = true;
  $("#log-empty").hidden = true;
  $("#turns").innerHTML = "";
  $("#answer").hidden = true;
  $("#log-title").textContent = "Session log";
  $("#log-sub").textContent = "Preparing the session for your signature.";
  working("Preparing the session…");
  const member = $("#person").value;
  try {
    const prep = await api("/api/agent/prepare", { member, question, use_verdict: $("#use-verdict").checked });
    if (!ids[member]) throw new Error(`No key for ${member} in this browser.`);
    const authorization = sign(member, prep.message);
    sessionId = prep.session_id;
    $("#log-title").innerHTML = `Session <span class="mono">${esc(prep.session_id)}</span>`;
    $("#log-sub").textContent = `Signed by ${ids[member].name}.`;
    turn({ tag: "Signed", what: `${esc(ids[member].name)} signed the session`, reason: esc(prep.message), mono: true });
    setBtn(btn, { label: "The agent is working…", loading: true });
    working("Starting the agent inside the enclave…");
    const res = await fetch("/api/agent/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ session_id: prep.session_id, authorization }) });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `The agent did not start (${res.status}).`);
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
        if (line.startsWith("data: ")) handleAgentEvent(JSON.parse(line.slice(6)));
      }
    }
  } catch (err) {
    turn({ cls: "block", tag: "Stopped", what: esc(err.message) });
    $("#log-sub").textContent = "The session stopped before it was sealed.";
    toast(esc(err.message), { error: true });
  }
  working(null);
  $("#person").disabled = false;
  setBtn(btn, { label: "Sign and ask the agent", loading: false, disabled: false });
});

// Policy ids look like "client:halverson"; show them as names.
const tidy = (t) => String(t).replace(/\b(?:client|adverse|matter):([a-z0-9][\w-]*)/gi, (_, n) => n.replace(/[-_]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()));
const sentence = (t) => { t = tidy(t); return /^\S+\.\S/.test(t) ? t : t.charAt(0).toUpperCase() + t.slice(1); };
const REFUSAL = "Told: Access to this material is not available in this session.";

function handleAgentEvent(ev) {
  if (ev.type === "start") {
    const screens = Object.values(ev.policy.screens).flat();
    $("#log-sub").textContent = `Signed by ${ev.member_name}. ${screens.length ? `Walled off: ${[...new Set(screens.map(tidy))].join(", ")}.` : `No walls apply to ${ev.member_name}.`}`;
    working("The agent is deciding what to read…");
  } else if (ev.type === "step") {
    const t = ev.turn, a = t.action, sig = esc((t.chat_id || "").slice(0, 8));
    if (a.action === "read") {
      const d = t.decision;
      turn({ cls: d.allowed ? "allow" : "block", tag: d.allowed ? "Allowed" : "Refused", what: `Asks for ${esc(a.id)}`,
        said: d.allowed ? "Gets the document." : REFUSAL, reason: esc(sentence(d.reason)), sig });
      working("The agent is deciding what to read next…");
    } else {
      turn({ tag: "Answers", what: "Writes the answer from what it was allowed to read", sig });
      working("Sealing the log on NEAR…");
      const a2 = $("#answer");
      a2.hidden = false;
      a2.innerHTML = `<h3>Answer</h3><span class="sk" style="width:92%"></span><span class="sk" style="width:84%"></span><span class="sk" style="width:60%"></span>`;
    }
  } else if (ev.type === "done") {
    working(null);
    if (ev.chain) {
      addLedger("#ledger-agent", `${ev.blocked}/${ev.decisions}`, ev.chain.url, "Sealed session on NEAR: refused / reads");
      addRecent("session", sessionId, sessionId.slice(0, 8));
      toast(`Session sealed on NEAR by the agent. <a href="${esc(ev.chain.url)}" target="_blank" rel="noopener">View transaction</a>`);
    }
    const a = $("#answer");
    a.hidden = false;
    a.innerHTML = `<h3>Answer</h3><p>${esc(ev.answer)}</p>
      <div class="links"><span>${plural(ev.decisions, "read")}, ${ev.blocked} refused</span>
      <span>Log root <span class="mono ink">${short(ev.log_root)}</span></span>
      ${ev.chain ? `<a href="${esc(ev.chain.url)}" target="_blank" rel="noopener">Sealed on NEAR by the agent</a>` : `<span class="error">Not sealed on NEAR</span>`}
      <a href="#" id="verify-session">Verify the session</a></div>`;
    const sid = sessionId;
    $("#verify-session").addEventListener("click", (e) => { e.preventDefault(); openVerify("session", sid); });
  } else if (ev.type === "error") {
    working(null);
    $("#answer").hidden = true;
    turn({ cls: "block", tag: "Stopped", what: esc(ev.message) });
    toast(esc(ev.message), { error: true });
  }
}

/* ---------- verify ---------- */

const TICK = `<svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="9" r="8" fill="#1C6B45"/><path d="M5.2 9.2l2.6 2.6 5-5.2" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
const CROSS = `<svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="9" r="8" fill="#B42318"/><path d="M6 6l6 6M12 6l-6 6" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/></svg>`;

function syncRefLabel() {
  const check = $("#kind").value === "check";
  $("#ref-label").textContent = check ? "Check number" : "Session id";
  $("#ref").placeholder = check ? "For example 2" : "For example 3edd3560df214b56";
}
$("#kind").addEventListener("change", syncRefLabel);

function addRecent(kind, ref, label) {
  $("#recent").hidden = false;
  $("#recent .chips").insertAdjacentHTML("beforeend",
    `<button type="button" data-kind="${esc(kind)}" data-ref="${esc(ref)}">${kind === "check" ? "Check " : "Session "}${esc(label)}</button>`);
}
$("#recent").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-ref]");
  if (b) openVerify(b.dataset.kind, b.dataset.ref, false);
});

function openVerify(kind, ref, swap = true) {
  $("#kind").value = kind; syncRefLabel();
  $("#ref").value = ref;
  if (swap) switchTab("verify");
  $("#lookup").requestSubmit();
}

function verifySkeleton() {
  const li = (w) => `<li><span class="sk" style="width:18px;height:18px;border-radius:50%;margin:0"></span><span class="sk" style="width:${w}%"></span></li>`;
  const rec = (w) => `<dt><span class="sk" style="width:70%"></span></dt><dd><span class="sk" style="width:${w}%"></span></dd>`;
  return `<div class="results" aria-hidden="true">
    <section class="panel checks"><div class="results-head"><h2>Replaying the proofs…</h2><span class="spin" style="display:inline-block;color:var(--link)"></span></div>
      <ul class="vsteps">${[88, 72, 80, 66, 76, 70, 52, 84].map(li).join("")}</ul></section>
    <section class="panel record-card"><h2>The record on NEAR</h2><dl class="record">${[60, 60, 30, 30, 90, 90, 90, 50].map(rec).join("")}</dl></section>
  </div>`;
}

$("#lookup").addEventListener("submit", async (e) => {
  e.preventDefault();
  const kind = $("#kind").value, ref = $("#ref").value.trim();
  const out = $("#verify-out"), btn = $("#verify-btn");
  if (!ref) { $("#ref").focus(); toast(`Enter a ${kind === "check" ? "check number" : "session id"} to verify.`, { error: true }); return; }
  if (kind === "check" && !/^\d+$/.test(ref)) { toast("A check number is a whole number, like 2.", { error: true }); $("#ref").focus(); return; }
  setBtn(btn, { label: "Verifying…", loading: true });
  out.innerHTML = verifySkeleton();
  let body;
  try { body = await api(kind === "check" ? `/api/check/${encodeURIComponent(ref)}/verify` : `/api/session/${encodeURIComponent(ref)}/verify`); }
  catch (err) {
    out.innerHTML = `<div class="panel state error">${CROSS}<div><strong>Could not verify ${kind === "check" ? `check #${esc(ref)}` : `session ${esc(ref)}`}</strong><p>${esc(err.message)}</p></div></div>`;
    setBtn(btn, { label: "Verify", loading: false, disabled: false });
    return;
  }
  setBtn(btn, { label: "Verify", loading: false, disabled: false });
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

/* ---------- tabs ---------- */

const TABS = ["check", "agent", "verify"];
function switchTab(name, { focus = false } = {}) {
  if (!TABS.includes(name)) name = "check";
  $$(".tabs button").forEach((b) => {
    const on = b.dataset.tab === name;
    b.setAttribute("aria-selected", on);
    b.tabIndex = on ? 0 : -1;
    if (on && focus) b.focus();
  });
  $$(".tab").forEach((t) => {
    const on = t.id === `tab-${name}`;
    if (on && t.hidden) { t.classList.remove("enter"); void t.offsetWidth; t.classList.add("enter"); }
    t.hidden = !on;
  });
  if (location.hash.slice(1) !== name) history.replaceState(null, "", name === "check" ? location.pathname : `#${name}`);
  if (scrollY > 0) window.scrollTo({ top: 0 });
}
$$(".tabs button").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));
$(".tabs").addEventListener("keydown", (e) => {
  const i = TABS.indexOf($(".tabs [aria-selected=true]").dataset.tab);
  const go = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: TABS.length - 1 }[e.key];
  if (go === undefined) return;
  e.preventDefault();
  switchTab(TABS[(go + TABS.length) % TABS.length], { focus: true });
});
addEventListener("hashchange", () => switchTab(location.hash.slice(1)));
$("#enclave").addEventListener("click", () => attest(true));

/* ---------- boot ---------- */

switchTab(location.hash.slice(1));
refreshAction();
attest();
try {
  config = await api("/api/config");
} catch (e) {
  flow.fatal = `Could not reach NEAR to load the firms. ${e.message}`;
  toast(esc(flow.fatal), { error: true, ms: 10000 });
  refreshAction();
  throw e;
}
$("#contract-link").textContent = config.contract;
$("#contract-link").href = `${config.explorer}/address/${config.contract}`;
setupFirm("incoming", "partner_incoming.csv");
setupFirm("existing", "firm_existing.csv");
step("identity", "busy", "Reading both firms' keys from the Sealroom contract");
loadFirmIdentity("incoming");
loadFirmIdentity("existing");
$("#person").innerHTML = config.members.map((m) => `<option value="${esc(m.account)}">${esc(m.name)}</option>`).join("");
$("#person").disabled = false;
$("#person").addEventListener("change", renderMember);
renderMember();
renderAgentIdentity();
setBtn($("#ask-btn"), { loading: false, disabled: !config.members.length });
refreshAction();

// Test hook: lets the interop test drive the same functions the page uses.
window.__sealroom = { encryptTo, canonical, normalise, elements, hashToPoint, mul, setHash, envelopeMessage, firms };
