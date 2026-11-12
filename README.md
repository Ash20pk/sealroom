# Sealroom

Conflict checks and ethical walls for legal AI, where nobody has to take anyone's word for it.

When a partner moves firms, both firms have to check the partner's old clients against the new firm's clients. Today that means one side hands its client list to the other, or to a vendor. Sealroom runs the check without either firm showing its list. Once the partner joins, it also lets them use the firm's AI research agent with the conflicted clients walled off. Every party signs with an identity registered on NEAR, and every claim can be replayed by anyone.

Built at NEAR HACKATHON for the **Privacy & Private AI** and **AI Security & Defense** tracks.

- Contract: [`v2.sealroom-64716.testnet`](https://testnet.nearblocks.io/address/v2.sealroom-64716.testnet)
- Model: an attested NEAR AI Cloud model in an Intel TDX enclave, end-to-end encrypted

## What you can check yourself

| Claim | Who enforces it | How |
|---|---|---|
| Each list really came from its firm | the NEAR contract | ed25519 signature by the firm's registered key over the list's commitment, ciphertext hash, exact-match set, counterparty and a one-time check id |
| Exact name matches are complete | cryptography, no trust | private set intersection (DH over the Ed25519 prime-order group), every message signed by the sending firm |
| The model ran in a genuine enclave | anyone, from the proof bundle | Intel-signed TDX quote binding the model key and a fresh nonce |
| The model saw exactly these lists and these instructions | anyone, from the proof bundle | every request is rebuilt byte for byte, including Sealroom's own encrypted instructions (their encryption randomness is disclosed), and must hash to what the enclave signed |
| The verdict is what the model said | anyone, from the proof bundle | responses are decrypted with the disclosed reader key and the verdict is re-derived; its hash must match the one on NEAR |
| The enclave signed every call | the NEAR contract | up to 48 TEE signatures verified on-chain per check |
| The orchestrator never saw a name | design | the model answers with entry numbers only; each firm discloses only its own matched entries, signed |
| A lawyer approved each agent session | the NEAR contract | member's signature over agent, session, question hash and policy hash |
| The agent ran its registered model and prompt | the NEAR contract | agent record pins model name and prompt hash; anything else cannot be sealed |
| The agent can't do anything else on-chain | NEAR access keys | the agent account's only key is a function-call key for `seal_session` on this contract |

## Identity

Everyone who acts in Sealroom has an identity on the contract.

- **Firm**: a NEAR account that registers its name and an ed25519 sealing key. It signs every list it submits.
- **Member**: a lawyer. A real NEAR sub-account of the firm, created with the lawyer's own key and registered by the firm. A member signs every agent session they start. A firm can deactivate a member.
- **Agent**: its own NEAR account, registered by the firm, owned by one member, pinned to a model and a prompt hash. Its only key can call `seal_session` and nothing else, with a 0.5 NEAR gas allowance. A firm can revoke it.

```
$ uv run sealroom whoami research.sr-firm-south-64716.testnet
{
  "kind": "agent",
  "firm": "sr-firm-south-64716.testnet",
  "owner": "marcus.sr-firm-south-64716.testnet",
  "model": "z-ai/glm-5.3-flash",
  "prompt_hash": "328a6291…",
  "active": true
}
```

## How a check works

```
 firm A (browser)            orchestrator (server)                 enclave (NEAR AI, TDX)     NEAR contract
 ────────────────            ─────────────────────                 ──────────────────────     ─────────────
 seal list in chunks ──┐
 blind names (PSI)     ├─ signed envelope ─► check sig vs NEAR key
 sign envelope       ──┘                     relay PSI messages ◄──► firm B (same steps)
                                             exact pairs from signed PSI transcript
                                             every chunk pair ─────────► entry numbers only ─┐
                                             verify TEE signature ◄──────────────────────────┘
                                             record_check ─────────────────────────────────────► verifies both firm sigs
                                                                                                  + every TEE sig, stores hashes
 disclose own matches, signed ─► named verdict, ranked by severity
```

1. **Attest.** Fetch the model's attestation with a fresh nonce. Check Intel's signature on the TDX quote, that the quote binds the model key and nonce, and that debug mode is off.
2. **Seal.** Each firm commits to its list (`sha256(salt ‖ list)`), splits it into numbered chunks, and encrypts each chunk to the model key in its own browser.
3. **Exact tier.** The firms run a private set intersection over normalised names and aliases ("Vale Doce S.A." equals "Vale Doce", "Müller & Söhne GmbH & Co. KG" equals "Muller and Sohne"). Each learns only which of its entries match. This floor doesn't depend on any model.
4. **Enclave tier.** Every pair of chunks goes to the model, which finds spelling variants, former names, parents and subsidiaries, affiliates and shared officers. It answers with entry numbers, a relationship type, a basis type and a confidence. Any number outside the chunks that call was shown is dropped. A reply that hits its output cap is continued until it isn't.
5. **Record.** The contract checks both firms' signatures and every TEE signature, then stores the commitments, the verdict hash and a root over the signed calls.
6. **Disclose.** Each firm reveals only its own matched entries, signed. Pairs are ranked: client vs adverse is *direct adversity*, client vs client goes to *review*, adverse vs adverse is *low*.

## How an agent session works

1. A member picks the agent and asks a question. The server builds the session: the walls from the latest conflict check, a policy hash and a question hash.
2. The member signs it in the browser. The server checks the signature against the member's key on NEAR, and that the agent is active, in the same firm, and running its registered prompt and model.
3. Every document read is decided before anything reaches the model. A refused read always gets the same reply, so the agent can't probe which clients the firm acts for. Each decision goes into a hash chain.
4. The agent seals the chain's root from its own account. The contract re-checks the member's signature, the model and the prompt hash.

## Run it

You need [uv](https://docs.astral.sh/uv/), Rust with `cargo-near`, and Node 20+ for the browser interop test. Calls to the model need a NEAR AI Cloud key with credit.

### 1. Tests, offline (about 30 seconds)

```bash
cd app && uv sync && uv run pytest -q
```

You should see **25 passed** (24 if Node isn't set up; see below). The engine tests run the full pipeline against a fake TEE that decrypts and signs the way NEAR AI does. They check the proof bundle catches seven kinds of tampering: verdict, response, instructions, envelope, exact-match transcript, firm key and a dropped call.

```bash
cd web && npm install && npm test   # browser crypto vs Python, byte for byte
cd contract && cargo test           # 13 passed: forged firm sig, replay, unattested signer, revoked agent, ...
```

### 2. Read-only against testnet (no keys)

```bash
cd app
uv run sealroom attest                                        # verify the enclave right now
uv run sealroom whoami sr-firm-south-64716.testnet            # a firm and its sealing key
uv run sealroom whoami jane.sr-firm-south-64716.testnet       # a member
uv run sealroom whoami research.sr-firm-south-64716.testnet   # the agent, pinned to model and prompt
uv run sealroom verify <check-id> --bundle <bundle.json>      # replay a check against NEAR
```

### 3. The web app

```bash
echo "NEARAI_API_KEY=sk-..." > .env
cd app && set -a && . ../.env && set +a && uv run sealroom-web
# open http://127.0.0.1:4410
```

**Conflict check.** Each firm card shows its NEAR account and whether its key matches the registry. Click **Seal this list** on both, then **Run conflict check**. The step rail shows each stage: the exact matches found by private set intersection, the enclave calls and their signatures, the record on NEAR, and each firm's signed disclosure. The verdict is ranked by severity, and its links go to the transaction, the proof bundle and a full replay.

**Agent in the Sealroom.** Pick Jane Okafor, the partner who just arrived from the other firm. Click **Sign and ask the agent**. Her signature starts the session. Reads of walled-off clients are refused, and the agent seals the log from `research.sr-firm-south-64716.testnet`. Switch to **What a reviewer sees** for the reasons behind each decision.

**Verify a record.** Enter a check number or session id to replay everything.

The demo page plays both firms and both lawyers, so it loads their keys from `.state/identity` through `/api/demo/identity`. The server never signs with them. In production each key stays on its owner's device.

### 4. Command line, one machine playing both firms

```bash
uv run sealroom check ../demo/partner_incoming.csv ../demo/firm_existing.csv --record
uv run sealroom verify-bundle ../.state/bundle-<id>.json
uv run sealroom prove <id> ../demo/firm_existing.csv ../.state/bundle-<id>.existing.secret.json
uv run sealroom agent --member jane.sr-firm-south-64716.testnet --bundle ../.state/bundle-<id>.json \
    --question "Brief me on our beverage and textile clients"
uv run sealroom verify-session ../.state/session-<sid>.json
```

### 5. Measure it

`eval/` holds three labelled cases: 45×120, 150×600 and 60×200 entries. They contain planted conflicts of all five relationship types, hard negatives (similar names that are different entities) and prompt-injection rows. `python3 eval/check_dataset.py` validates them, and `eval/make_dataset.py` regenerates them from a fixed seed.

```bash
uv run sealroom eval ../eval/small
uv run sealroom --model deepseek-ai/DeepSeek-V4.1-Flash-1017 eval ../eval/hard
```

Every eval run also replays its own proof bundle, so a score is only reported for a verdict that verifies.

### Your own deployment

```bash
export SEALROOM_OPERATOR=you.testnet SEALROOM_CONTRACT=sealroom.you.testnet \
       SEALROOM_FIRM_INCOMING=firm-a.testnet SEALROOM_FIRM_EXISTING=firm-b.testnet
cd contract && cargo near build non-reproducible-wasm
cd ../app && uv run sealroom setup
```

`setup` is idempotent. It deploys the contract, registers both firms with fresh sealing keys, creates two member sub-accounts with their own keys, and creates the agent. The agent first gets a temporary full-access key, which `setup` swaps for the scoped key and then deletes from the chain.

## Limits

- **The contract can't check an Intel quote.** It checks that the TEE signed each call with the declared key. The proof bundle carries the raw attestation report, so anyone can confirm that the key belongs to a genuine enclave (`sealroom verify-bundle`).
- **Attestation checks don't cover everything.** We don't replay RTMR3 against the app compose or check the NVIDIA GPU attestation through NRAS.
- **The access rules run on the orchestrator.** Reads are decided before a document reaches the model, and the log is sealed and member-signed. But the documents are readable by whoever runs the server. Running the orchestrator itself as a Shade Agent in a TEE is the next step.
- **The exact tier is semi-honest.** A firm that lies in its own exact-match messages can hide or invent matches on its side. Its signature makes that attributable, and its commitment can be opened later (`sealroom prove`).
- **One check is capped at 48 signed model calls.** That's the contract's on-chain verification limit, about 18 Tgas measured. Chunk size grows with list size to fit, and a check that can't cover every chunk pair is marked truncated, on-chain and in the verdict.
- **Severity uses the roles in each list.** Real conflict rules also depend on matter type, dates and jurisdiction.
- **Testnet hides panic messages.** Some nearcore releases (testnet runs 2.14.0-rc) report contract panics as a bare `unreachable` trap. The contract logs `sealroom: <reason>` before it panics, and the CLI and server read that log back.

## Layout

```
contract/       NEAR contract (Rust): identity registry, check records, session seals
app/sealroom/   engine (conflict.py), PSI (psi.py), proof bundles (bundle.py), identity,
                E2EE + attestation, agent + access rules (room.py), CLI, web server, eval
web/            the browser app; sealcrypto.js mirrors the Python crypto
demo/           demo lists, agent library, labels
eval/           labelled cases and the generator
```
