# Live run evidence

Plain-text evidence that the production path runs for real: check #10, a conflict check on the demo lists with encrypted inference on NEAR AI Cloud, recorded on NEAR testnet on 2026-11-14; its proof bundle; a full replay of that bundle against the on-chain record; and a fresh attestation of the model. Every file is unedited command output.

The replay, attestation and test runs were done on the application code in this repository, together with the tests in `app/tests/test_agent.py` and the contract truncation tests, which change no application code. Contract: [`v2.sealroom-64716.testnet`](https://testnet.nearblocks.io/address/v2.sealroom-64716.testnet). Model: `z-ai/glm-5.3-flash`.

| File | What it shows | Code that produced it |
|---|---|---|
| [`attest.txt`](attest.txt) | Intel TDX quote verified by dcap-qvl against Intel PCS collateral (TCB `UpToDate`); `report_data` binds the model signing key and our fresh nonce `8d0de6e8…`; debug off; event log replays to RTMR0-3 with three compose hashes bound; NVIDIA NRAS verified the GPUs | [`attest.py` L77-83](../../app/src/sealroom/attest.py#L77) (report_data, dcap-qvl), [L91-112](../../app/src/sealroom/attest.py#L91) (RTMR replay), [L172](../../app/src/sealroom/attest.py#L172) (NRAS) |
| [`tx-check-10.txt`](tx-check-10.txt) | The `record_check` transaction for check #10, read back from the testnet archival RPC: `SuccessValue` 10 (`MTA=`), and the `check_recorded` event with 5 conflicts. The contract checked both firm signatures and the TEE signature inside this call. [NearBlocks](https://testnet.nearblocks.io/txns/Hxct7d9zMuc5uV7PVs1Hfc6cUZpaeZrJi8McrJLkPJ6P) | [`lib.rs` `record_check`](../../contract/src/lib.rs#L297), TEE signature check at [L340](../../contract/src/lib.rs#L340) |
| [`bundle-10.json`](bundle-10.json) | The proof bundle for check #10: 1 exact match by PSI, 1 signed enclave call, 5 pairs | [`bundle.py` `build`](../../app/src/sealroom/bundle.py#L34) |
| [`verify-10.txt`](verify-10.txt) | `sealroom verify 10 --bundle` with hardware re-verification on: quotes, firm signatures, PSI transcript, all calls rebuilt byte for byte with valid TEE signatures, verdict re-derived, every chunk pair covered, and the on-chain record matches the bundle | [`bundle.py` `verify`](../../app/src/sealroom/bundle.py#L113) |
| [`pytest.txt`](pytest.txt) | `pytest -v`: 38 passed, including browser crypto interoperability, the eval verify-before-score tests and the agent refusal test | `app/tests/` |
| [`cargo-test.txt`](cargo-test.txt) | `cargo test`: 16 contract tests passed, including the truncation tests | [`contract/src/lib.rs`](../../contract/src/lib.rs) tests module |

## Check it yourself

```bash
cd app
uv run sealroom verify 10 --bundle ../docs/evidence/bundle-10.json
```

This reads check #10 from testnet and replays the bundle against it. It needs network access to NEAR testnet RPC, Intel PCS and NVIDIA NRAS, and no keys.

## What this does not show

- The bundle contains this check's reader seed and per-call ephemeral secrets, by design, so a verifier can decrypt the replies and rebuild each request. Anyone holding it can read check #10's demo records, which are fictional.
- It covers the conflict-check path only. No agent session (`seal_session`) was run for this evidence.
- One machine played both firms, using the demo identities. This is the CLI path, not two independent organizations.
- This is one run on a small demo list (1 chunk pair). It is not a precision/recall measurement; see `sealroom eval`.
