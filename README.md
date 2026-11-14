# Sealroom

Private record matching and controlled AI access across organizations.

Sealroom helps organizations compare sensitive records without exchanging their full datasets, then apply access rules to the AI agents that use related documents. It combines private matching, confidential AI analysis on NEAR AI Cloud, and signatures and audit commitments recorded on NEAR.

The working prototype demonstrates this through conflict checks between law firms. Legal services are the example, not the limit of the approach. Other industries could adapt the matching and access-control components to their own records, policies and review processes.

- **Live demo:** https://54-226-24-21.sslip.io (fictional legal records, NEAR testnet). A check takes about two minutes; availability and rate limits apply. Do not upload confidential data to this shared demo.
- **Contract:** [`v2.sealroom-64716.testnet`](https://testnet.nearblocks.io/address/v2.sealroom-64716.testnet)
- **Default model:** `z-ai/glm-5.3-flash`, with inputs encrypted to its attested model key
- **Overview:** [How it works (PDF)](docs/sealroom-how-it-works.pdf)

Built at [NEAR HACKATHON](https://nearhackathon.com) for the **Privacy & Private AI**, **AI Security & Defense**, **Open Innovation**, and **Agent Economy** tracks.

## The user flow

1. Each organization prepares its records in its own browser.
2. Sealroom checks the AI environment before the browser encrypts records for analysis.
3. The organizations compare exact matches privately; protected AI analysis looks for less obvious relationships.
4. Each organization signs and discloses its own matched entries for review, rather than handing over its full list.
5. Reviewers can check the signed evidence against the hashes recorded on NEAR.
6. A member can ask the AI research agent questions, with restricted document reads blocked by the application's access rules.

### One example: a partner moves between law firms

The partner's former clients must be checked against the receiving firm's clients and adverse parties. Neither firm wants to exchange its full client list. Sealroom finds exact overlaps and possible relationships such as former names, parent companies or shared officers. The firms disclose matched entries, review the suggested conflicts, and use the result to screen the partner's research-agent session from affected client documents.

The model reads decrypted records inside its protected execution environment and returns entry numbers, relationship types and confidence values. It does not return the full lists. After matching, signed disclosures reveal matched records to the application and the reviewing parties.

```text
  [Organization A: browser]       [Organization B: browser]
              \                         /
               +--- two prepared inputs --+
               |                         |
          blinded names             encrypted chunks
               v                         v
       [Private set matching]     [NEAR AI Cloud TEE]
          exact overlaps          suggested relationships
               |                  signed, numbered results
               +------------+------------+
                            v
                   [Merge the results]
                            |
                            v
                     [NEAR contract]
               submission and call signatures;
               commitments and verdict hash
                            |
                            v
              [Signed disclosure of matched entries]
                            |
                            v
                [Human review and agent access rules]
```

The two matching paths feed the same verdict; the AI receives encrypted record chunks, not just the exact-match results. Private set matching assumes honest execution by the participating organizations. Signatures make messages attributable; they do not prove that an organization supplied a complete or truthful list.

## Beyond the legal example

The same pattern could support other workflows where organizations need to find relationships without sharing every record:

| Potential application | What organizations could compare | What would need adapting |
|---|---|---|
| Banking and investment | Borrower or counterparty names to identify overlapping exposures | Financial schemas, consent, exposure calculations and risk policies |
| Consulting and professional services | Client relationships to flag competing engagements | Engagement details, confidentiality labels and conflict policies |
| Procurement and supply chains | Supplier names, aliases and ownership relationships | Supplier identifiers, relationship evidence and review rules |
| Research partnerships | Organization or project records to identify overlap | Domain identifiers, data permissions and disclosure policies |

These are potential applications, not demonstrated deployments or validated market demand. The current matching prompt, severity rules, sample data and research-agent prompt are legal-specific. Supporting another industry means adapting and testing those pieces, not simply changing the labels. Sealroom does not currently implement credit-risk calculations, general due diligence or clinical-data matching.

## AI agents with information boundaries

Private comparison is only the first part. Organizations also need to control which documents an AI agent may read afterward. In the legal demo, a member signs a research session and the application screens document reads using the conflict check's result. Restricted content is refused before it enters the model's context, and access decisions form a hash chain whose root is sealed on NEAR.

This is a reusable access-control pattern, demonstrated here with client-level labels. It currently trusts the application server to enforce the rules and hold the document library. The contract records authorization and log commitments; it cannot inspect the server's off-chain behavior. [Session details](#how-an-agent-session-works) and [limits](#limits) explain the boundary.

## Judge it in 2 minutes

Start with the [demo](https://54-226-24-21.sslip.io) and [testnet contract](https://testnet.nearblocks.io/address/v2.sealroom-64716.testnet). After local setup, the commands below provide a short verification path; installation and network calls may take longer than two minutes.

You need Git, [uv](https://docs.astral.sh/uv/) with Python 3.12, and Node 20+ with npm for the browser interoperability test. No model API key or transaction-signing key is needed for the offline tests or public chain reads.

```bash
git clone https://github.com/Ash20pk/sealroom.git
cd sealroom
(cd web && npm ci)
cd app
uv sync
uv run pytest -q
# Expected on this reviewed code: 37 passed, including browser interoperability.

uv run sealroom whoami research.sr-firm-south-64716.testnet
# Inspect the registered agent, owner, model and prompt hash.

uv run sealroom verify 10
# Read an existing check from testnet; this alone is not a full bundle replay.

uv run sealroom attest
# Live Intel quote, nonce/key binding, RTMR replay and NVIDIA NRAS checks.
# Requires network access to NEAR AI, Intel collateral and NVIDIA NRAS.
```

### Evidence snapshot

Reviewed against source commit `988c3fd` on 2026-11-14:

- **34 Python tests passed locally**, including the browser crypto interoperability test. Rerunning that test separately does not add another test to the count.
- **All three labelled datasets passed structural validation.** This checks the datasets, not the model's matching accuracy.
- **11 stored check records** (IDs 0-10) were returned by a public testnet read on 2026-11-14. Stored records are distinct from a fresh end-to-end run or a replay of their proof bundles.
- **Live attestation was verified during the earlier review that day**, including Intel TDX, RTMR0-3 replay and NVIDIA NRAS. Run `sealroom attest` to check the current environment.
- **13 Rust contract tests passed** with `cargo test`.
- **Hosted CI passed** on GitHub Actions for this commit: the Python suite with browser interoperability, and dataset validation.

## What you can check yourself

| Claim | Where it is checked | Scope |
|---|---|---|
| An organization signed its submission | NEAR contract | Its registered ed25519 key signs the list commitment, ciphertext hash, blinded-set hash, counterparty and one-time check reference. This authenticates the submission, not the truth of its contents. |
| Exact overlaps can be recomputed | Signed PSI transcript | DH over the Ed25519 prime-order group matches normalized names and aliases under the semi-honest assumption. |
| Model and gateway keys are bound to TDX evidence | Attestation verifier | Intel quote verification checks the signing identity, fresh nonce and debug mode. The contract does not independently verify Intel quotes. |
| The reported compose is bound to the quote | Attestation verifier | Event logs replay to RTMR0-3; the measured compose hash must match the supplied compose. This does not establish a reviewed application allowlist. |
| GPU evidence passes NVIDIA's appraisal | Attestation verifier | NRAS tokens are checked using NVIDIA's published keys, with overall and per-GPU results and nonce checks. GPU evidence is not hash-bound to the CPU quote. |
| Signed calls used the submitted ciphertexts and disclosed instructions | Proof-bundle verifier | Requests are rebuilt byte for byte and checked against signed request/response hashes. This does not prove that a party encrypted truthful or complete source records. |
| The verdict follows from the signed replies and exact-match transcript | Proof-bundle verifier | Responses are decrypted, validated and merged again; the derived verdict is compared with the recorded hash. This is not proof that every suggested relationship is correct. |
| Submitted inference signatures are valid | NEAR contract | Up to 48 call signatures are checked against the model/gateway keys declared in the record. Off-chain attestation establishes whether those keys belong to a genuine enclave. |
| Full record names need not reach the matching relay | Browser encryption and numbered model output | Inputs are encrypted to the model key. Later signed disclosure reveals matched names to the application and reviewing parties. |
| A member authorized a session | NEAR contract | The member signs the agent, session, question hash and policy hash. |
| Declared session configuration matches the agent registry | Application and NEAR contract | The application checks its running configuration; the contract compares the submitted model and prompt hash with registered values. The contract cannot inspect actual off-chain execution. |
| The demo agent's signing key has limited on-chain authority | NEAR access keys | Its function-call key is restricted to `seal_session` on the configured contract, with a gas allowance. This is not a general business-spending policy. |

`record_check` authenticates the registered organizations' signatures and verifies the submitted call signatures. The proof-bundle verifier separately checks hardware evidence, reconstructs requests and derives the verdict. A chain record alone is not proof of genuine hardware or correct matching.

### Why a contract and not the NEAR Agent API

Sealroom uses native NEAR accounts and scoped function-call keys. Its custom contract records signed multi-party checks and member-authorized session logs. These application-specific records explain its role; Sealroom does not claim to integrate the Agent API or replace its wallet and transaction-policy features:

- **Call signatures checked on-chain.** `record_check` verifies submitted inference signatures against the declared model and gateway keys. The off-chain attestation verifier establishes their hardware binding.
- **Declared model and prompt pinning.** An agent record fixes its model name and prompt hash; sealing rejects different submitted values. The application checks the configuration it runs.
- **Firm, member and agent hierarchy.** Firms register their sealing keys, members are sub-accounts with their own keys, and agents are owned by one member and revocable by the firm.
- **Signed sessions.** `seal_session` re-checks the member's signature over the agent, session, question hash and policy hash, and stores the root of the decision log.

## Identity

The prototype registers organizations, people and agents on the contract. The code calls an organization a `firm`; the demo uses law firms and lawyers. These existing API names are retained below.

- **Firm**: a NEAR account that registers its name and an ed25519 sealing key. It signs every list it submits.
- **Member**: a person, demonstrated as a lawyer. Setup creates a real NEAR sub-account with its own key and registers it with the firm. A member signs each agent session they start; the firm can deactivate them.
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

The implemented check uses legal-party records (`name`, `role`, `aliases`, `related`). The roles and severity rules below belong to the legal example.

1. **Attest.** Fetch the model's attestation with a fresh nonce. Check Intel's signature on the TDX quote, that the quote binds the model key and nonce, and that debug mode is off. Replay the event log to the quote's RTMRs so the app compose each instance runs is bound to its quote, and have NVIDIA's NRAS appraise the GPUs.
2. **Seal.** Each firm commits to its list (`sha256(salt ‖ list)`), splits it into numbered chunks, and encrypts each chunk to the model key in its own browser.
3. **Exact tier.** The firms run a private set intersection over normalised names and aliases ("Vale Doce S.A." equals "Vale Doce", "Müller & Söhne GmbH & Co. KG" equals "Muller and Sohne"). Each learns only which of its entries match. This floor doesn't depend on any model.
4. **Enclave tier.** Every pair of chunks goes to the model, which finds spelling variants, former names, parents and subsidiaries, affiliates and shared officers. It answers with entry numbers, a relationship type, a basis type and a confidence. Any number outside the chunks that call was shown is dropped. Full replies trigger bounded continuation attempts; if limits are reached, the check is marked truncated.
5. **Record.** The contract checks both firms' signatures and every TEE signature, then stores the commitments, the verdict hash and a root over the signed calls.
6. **Disclose.** Each firm reveals only its own matched entries, signed. Pairs are ranked: client vs adverse is *direct adversity*, client vs client goes to *review*, adverse vs adverse is *low*.

## How an agent session works

In the legal demo, the application turns conflict results into document-access screens for the selected member. An ethical wall is a rule separating information a person or session must not combine. The library, labels and agent prompt in this prototype are legal-specific; other domains need their own policy mapping.

1. A member picks the agent and asks a question. The server builds the session: the walls from the latest conflict check, a policy hash and a question hash.
2. The member signs it in the browser. The server checks the signature against the member's key on NEAR, and that the agent is active, in the same firm, and running its registered prompt and model.
3. Every document read is decided before anything reaches the model. A refused read always gets the same reply, so the agent can't probe which clients the firm acts for. Each decision goes into a hash chain.
4. The agent seals the decision log's root from its own account. The contract verifies the member's authorization and checks that the declared model and prompt hash match the registry; it does not attest the server's execution.

The application enforces document access; NEAR restricts the agent key and stores the session seal. The setup script gives the function-call key a 0.5 NEAR gas allowance. That allowance covers on-chain gas, not inference bills or arbitrary business expenses. A uniform refusal avoids revealing the specific access-rule reason; it is not a guarantee against every metadata or inference leak.

## Run it

Python tests and public read-only commands use [uv](https://docs.astral.sh/uv/) and Python 3.12. Install Node 20+ and the `web/` dependencies for browser interoperability. Contract tests require Rust; deployment additionally requires `cargo-near`, `near-cli-rs`, funded testnet accounts and the relevant signing keys. New model inference needs a NEAR AI Cloud key with credit.

### 1. Tests, offline (about 30 seconds)

```bash
(cd web && npm ci)
cd app
uv sync
uv run pytest -q
```

With the browser dependencies installed, the reviewed code returns **37 passed**. Without Node or the interop dependencies, that test can be skipped (36 passed, 1 skipped). The engine tests run the full pipeline against a fake TEE that decrypts and signs the way NEAR AI does. They check the proof bundle catches seven kinds of tampering: verdict, response, instructions, envelope, exact-match transcript, firm key and a dropped call. The attestation tests replay a real NEAR AI Cloud event log and check that a tampered RTMR3 event, app compose or info block is caught, and that NRAS tokens with the wrong key, wrong nonce, a failed GPU or a missing GPU are refused.

```bash
# From the repository root, run each command separately:
(cd web && npm ci && npm test)       # reruns the interop test already in pytest
(cd contract && cargo test)         # contract signature, replay and revocation tests
```

### 2. Read-only verification

```bash
cd app
uv run sealroom attest                                        # verify the enclave right now
uv run sealroom whoami sr-firm-south-64716.testnet            # a firm and its sealing key
uv run sealroom whoami jane.sr-firm-south-64716.testnet       # a member
uv run sealroom whoami research.sr-firm-south-64716.testnet   # the agent, pinned to model and prompt
uv run sealroom verify <check-id> --bundle <bundle.json>      # replay a downloaded bundle against NEAR
```

Public chain reads use no transaction-signing key. The public model attestation endpoint worked without an API key during review; provider access policies may change. Full hardware verification uses network services for Intel collateral and NVIDIA appraisal. A full replay also needs the corresponding proof bundle, not just a check ID.

### 3. The web app

```bash
# From the repository root, configure NEARAI_API_KEY in a local .env file.
# Do not commit credentials. On-chain actions also need setup/signing keys.
cd app
set -a
. ../.env
set +a
uv run sealroom-web
# open http://127.0.0.1:4410
```

**Conflict check.** Each firm card shows its NEAR account and whether its key matches the registry. Click **Seal this list** on both, then **Run conflict check**. The step rail shows each stage: the exact matches found by private set intersection, the enclave calls and their signatures, the record on NEAR, and each firm's signed disclosure. The verdict is ranked by severity, and its links go to the transaction, the proof bundle and a full replay.

**Agent in the Sealroom.** Pick Jane Okafor, the partner who just arrived from the other firm. Click **Sign and ask the agent**. Her signature starts the session. Reads of walled-off clients are refused, and the agent seals the log from `research.sr-firm-south-64716.testnet`. Switch to **What a reviewer sees** for the reasons behind each decision.

**Verify a record.** Enter a check number or session id to replay everything.

The shared demo plays both firms and both lawyers. Its server stores demo identity files and serves their keys to the browser through `/api/demo/identity/{account}`; the browser signs with them. These are demonstration identities, not independent organizations. A production deployment would need separate key custody, authentication and access controls. Later matched-entry disclosures and the agent document library are readable by the application server.

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

Every eval run replays its own proof bundle before it is scored ([`eval.py` `_run_result`](app/src/sealroom/eval.py#L70)). A run whose bundle fails replay, including a truncated one, reports the failed steps and no precision or recall, and `sealroom eval` exits non-zero ([`cli.py` `cmd_eval`](app/src/sealroom/cli.py#L223)). [`tests/test_eval.py`](app/tests/test_eval.py) tampers with the verdict and with a signed response and checks that neither run carries a score. The replay skips re-fetching hardware collateral because the model's attestation is verified live at the start of the eval. Dataset validation alone is not a precision/recall result. Running these model evaluations consumes NEAR AI Cloud credit.

### Host the web demo (free)

`render.yaml` deploys the web app to Render's free plan from this repo: **New > Blueprint**, pick the repo, and fill in two secrets.

- `NEARAI_API_KEY`: a NEAR AI Cloud key with credit. Every run calls the model, so this is the one thing that costs money.
- `SEALROOM_KEYS`: a base64 tar.gz with `near-credentials/testnet/*.json` (a `record_check`-only key for the operator and the agent's `seal_session`-only key) and `identity/*.json` (the demo firms and lawyers). The server never gets a full-access key.

The server caps runs per visitor and per day (`SEALROOM_RUNS_PER_IP_HOUR`, `SEALROOM_RUNS_PER_DAY`) and runs one check in the enclave at a time. A free instance sleeps after 15 idle minutes and takes about a minute to wake. Proof bundles kept on the server are lost when it sleeps; the records on NEAR are not.

### Your own deployment

```bash
export SEALROOM_OPERATOR=you.testnet SEALROOM_CONTRACT=sealroom.you.testnet \
       SEALROOM_FIRM_INCOMING=firm-a.testnet SEALROOM_FIRM_EXISTING=firm-b.testnet
cd contract && cargo near build non-reproducible-wasm
cd ../app && uv run sealroom setup
```

`setup` is idempotent. It deploys the contract, registers both firms with fresh sealing keys, creates two member sub-accounts with their own keys, and creates the agent. The agent first gets a temporary full-access key, which `setup` swaps for the scoped key and then deletes from the chain.

## Limits

- **Hardware verification is off-chain.** The contract checks signatures under declared model/gateway keys; it cannot verify an Intel quote or independently establish that those keys belong to an enclave. The proof-bundle verifier performs hardware checks separately and needs online collateral/appraisal services. Its `--offline` option skips hardware re-verification; it is not an equivalent full verification.
- **The GPU evidence isn't hash-bound to the TDX quote.** Both carry our fresh nonce, and NVIDIA verifies the GPUs, but nothing in the quote commits to the GPU evidence. That those GPUs sit behind that CVM rests on NEAR AI's deployment.
- **We check that the compose is bound, not what it says.** The proof bundle keeps the raw report, so each model instance's compose hash can be recomputed, and `sealroom attest` prints them. Pinning it to a reviewed allowlist is up to whoever relies on the check.
- **The access rules run on the orchestrator.** Reads are decided before a document reaches the model, and the log is sealed and member-signed. But the documents are readable by whoever runs the server. Running the orchestrator itself as a Shade Agent in a TEE is the next step.
- **The exact tier is semi-honest.** A firm that lies in its own exact-match messages can hide or invent matches on its side. Its signature makes that attributable, and its commitment can be opened later (`sealroom prove`).
- **One check is capped at 48 signed model calls.** That's the contract's on-chain verification limit, about 18 Tgas measured. Chunk size grows with list size to fit, and a check that can't cover every chunk pair is marked truncated, on-chain and in the verdict. The contract enforces the cap ([`lib.rs` L328](contract/src/lib.rs#L328)) and stores the flag it is given; [`truncated_check_at_the_call_cap_is_recorded_as_truncated`](contract/src/lib.rs#L519) records a 48-call truncated check and reads the flag back, and `more_calls_than_the_cap_rejected` refuses a 49th call. The flag is derived off-chain, and the bundle verifier re-derives it from the signed calls.
- **Domain rules need validation.** Severity uses the legal roles in each list; real conflicts also depend on matter type, dates and jurisdiction. The current prompts and data model are not a validated solution for every industry. Suggested relationships require human review, and signed inference is not proof of semantic accuracy.
- **Testnet hides panic messages.** Some nearcore releases (testnet runs 2.14.0-rc) report contract panics as a bare `unreachable` trap. The contract logs `sealroom: <reason>` before it panics, and the CLI and server read that log back.

## Layout

```
contract/       NEAR contract (Rust): identity registry, check records, session seals
app/src/sealroom/  engine (conflict.py), PSI (psi.py), proof bundles (bundle.py), identity,
                   E2EE + attestation, agent + access rules (room.py), CLI, web server, eval
web/            the browser app; sealcrypto.js mirrors the Python crypto
demo/           demo lists, agent library, labels
eval/           labelled cases and the generator
```

## Reach me

Built by Aswin Kumar. Questions, feedback, or want to try it on real conflict data? Get in touch.

- X: [@ash20pk](https://x.com/ash20pk)
- LinkedIn: [Aswin Kumar](https://www.linkedin.com/in/aswin-kumar-7399971b3/)
- Email: [ash20pk@gmail.com](mailto:ash20pk@gmail.com)
- GitHub: [@Ash20pk](https://github.com/Ash20pk)
