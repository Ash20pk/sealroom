//! Sealroom: an on-chain record of private conflict checks and barrier sessions.
//!
//! The contract never sees client data. It stores commitments (hashes) of each
//! party's input, a hash of the verdict, and the TEE signature that NEAR AI Cloud
//! produced for the inference that computed it. Anyone can later check that a
//! verdict came from an attested model and was not altered.

use near_sdk::borsh::BorshSerialize;
use near_sdk::store::{IterableMap, LookupMap};
use near_sdk::{env, near, require, AccountId, BorshStorageKey, PanicOnDefault};

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
enum Key {
    Firms,
    Checks,
    Sessions,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Attestation {
    /// Model that produced the verdict, e.g. "deepseek-ai/DeepSeek-V3.1".
    pub model: String,
    /// NEAR AI Cloud chat id; the signature is fetched from /v1/signature/{chat_id}.
    pub chat_id: String,
    /// Signed text, as returned by NEAR AI Cloud ("<request_hash>:<response_hash>").
    pub signed_text: String,
    /// Signature over `signed_text` by the TEE's signing key.
    pub signature: String,
    /// Signing address bound to the TEE in the attestation report.
    pub signing_address: String,
    /// sha256 of the attestation report the signing address was taken from.
    pub report_hash: String,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct ConflictCheck {
    pub id: u64,
    pub requester: AccountId,
    pub counterparty: AccountId,
    /// sha256(salt || canonical list) of each side's input. Salts stay with each firm.
    pub requester_commitment: String,
    pub counterparty_commitment: String,
    pub verdict_hash: String,
    pub conflicts_found: u32,
    pub attestation: Attestation,
    pub recorded_at_ns: u64,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct SessionSeal {
    pub session_id: String,
    pub firm: AccountId,
    /// Root of the hash chain over every barrier decision in the session.
    pub log_root: String,
    pub decisions: u32,
    pub blocked: u32,
    pub sealed_at_ns: u64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Sealroom {
    firms: LookupMap<AccountId, String>,
    checks: IterableMap<u64, ConflictCheck>,
    sessions: LookupMap<String, SessionSeal>,
    next_check_id: u64,
}

fn require_hex32(label: &str, v: &str) {
    require!(
        v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()),
        format!("{label} must be a 32-byte hex sha256")
    );
}

#[near]
impl Sealroom {
    #[init]
    pub fn new() -> Self {
        Self {
            firms: LookupMap::new(Key::Firms),
            checks: IterableMap::new(Key::Checks),
            sessions: LookupMap::new(Key::Sessions),
            next_check_id: 0,
        }
    }

    /// A firm registers itself under its own account.
    pub fn register_firm(&mut self, name: String) {
        require!(!name.is_empty() && name.len() <= 120, "name must be 1-120 chars");
        self.firms.insert(env::predecessor_account_id(), name);
    }

    pub fn firm_name(&self, account_id: AccountId) -> Option<String> {
        self.firms.get(&account_id).cloned()
    }

    /// Record a completed conflict check. Called by the requesting firm.
    pub fn record_check(
        &mut self,
        counterparty: AccountId,
        requester_commitment: String,
        counterparty_commitment: String,
        verdict_hash: String,
        conflicts_found: u32,
        attestation: Attestation,
    ) -> u64 {
        let requester = env::predecessor_account_id();
        require!(self.firms.contains_key(&requester), "requester is not a registered firm");
        require!(self.firms.contains_key(&counterparty), "counterparty is not a registered firm");
        require!(requester != counterparty, "a firm cannot check against itself");
        require_hex32("requester_commitment", &requester_commitment);
        require_hex32("counterparty_commitment", &counterparty_commitment);
        require_hex32("verdict_hash", &verdict_hash);
        require_hex32("report_hash", &attestation.report_hash);
        require!(!attestation.signature.is_empty(), "attestation signature missing");

        let id = self.next_check_id;
        self.next_check_id += 1;
        let check = ConflictCheck {
            id,
            requester,
            counterparty,
            requester_commitment,
            counterparty_commitment,
            verdict_hash,
            conflicts_found,
            attestation,
            recorded_at_ns: env::block_timestamp(),
        };
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"sealroom\",\"version\":\"1.0.0\",\"event\":\"check_recorded\",\"data\":{{\"id\":{id},\"conflicts\":{}}}}}",
            check.conflicts_found
        ));
        self.checks.insert(id, check);
        id
    }

    pub fn get_check(&self, id: u64) -> Option<ConflictCheck> {
        self.checks.get(&id).cloned()
    }

    pub fn list_checks(&self, from: Option<u64>, limit: Option<u64>) -> Vec<ConflictCheck> {
        let from = from.unwrap_or(0);
        let limit = limit.unwrap_or(50).min(100);
        (from..self.next_check_id)
            .take(limit as usize)
            .filter_map(|i| self.checks.get(&i).cloned())
            .collect()
    }

    /// Anchor the decision log of one agent session. A session can be sealed once.
    pub fn seal_session(&mut self, session_id: String, log_root: String, decisions: u32, blocked: u32) {
        let firm = env::predecessor_account_id();
        require!(self.firms.contains_key(&firm), "caller is not a registered firm");
        require!(!session_id.is_empty() && session_id.len() <= 64, "session_id must be 1-64 chars");
        require!(!self.sessions.contains_key(&session_id), "session already sealed");
        require!(blocked <= decisions, "blocked cannot exceed decisions");
        require_hex32("log_root", &log_root);
        self.sessions.insert(
            session_id.clone(),
            SessionSeal { session_id, firm, log_root, decisions, blocked, sealed_at_ns: env::block_timestamp() },
        );
    }

    pub fn get_session(&self, session_id: String) -> Option<SessionSeal> {
        self.sessions.get(&session_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    const H: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn as_caller(who: &str) {
        testing_env!(VMContextBuilder::new().predecessor_account_id(who.parse().unwrap()).build());
    }

    fn att() -> Attestation {
        Attestation {
            model: "m".into(),
            chat_id: "c".into(),
            signed_text: "a:b".into(),
            signature: "0xsig".into(),
            signing_address: "0xaddr".into(),
            report_hash: H.into(),
        }
    }

    fn two_firms() -> Sealroom {
        as_caller("firm-a.testnet");
        let mut c = Sealroom::new();
        c.register_firm("Firm A".into());
        as_caller("firm-b.testnet");
        c.register_firm("Firm B".into());
        c
    }

    #[test]
    fn records_and_reads_a_check() {
        let mut c = two_firms();
        as_caller("firm-a.testnet");
        let id = c.record_check("firm-b.testnet".parse().unwrap(), H.into(), H.into(), H.into(), 2, att());
        let got = c.get_check(id).unwrap();
        assert_eq!(got.conflicts_found, 2);
        assert_eq!(got.requester.as_str(), "firm-a.testnet");
        assert_eq!(c.list_checks(None, None).len(), 1);
    }

    #[test]
    #[should_panic(expected = "requester is not a registered firm")]
    fn unregistered_requester_rejected() {
        let mut c = two_firms();
        as_caller("stranger.testnet");
        c.record_check("firm-b.testnet".parse().unwrap(), H.into(), H.into(), H.into(), 0, att());
    }

    #[test]
    #[should_panic(expected = "verdict_hash must be a 32-byte hex sha256")]
    fn bad_hash_rejected() {
        let mut c = two_firms();
        as_caller("firm-a.testnet");
        c.record_check("firm-b.testnet".parse().unwrap(), H.into(), H.into(), "nope".into(), 0, att());
    }

    #[test]
    #[should_panic(expected = "session already sealed")]
    fn session_seals_once() {
        let mut c = two_firms();
        as_caller("firm-a.testnet");
        c.seal_session("s1".into(), H.into(), 5, 1);
        assert_eq!(c.get_session("s1".into()).unwrap().blocked, 1);
        c.seal_session("s1".into(), H.into(), 6, 1);
    }
}
