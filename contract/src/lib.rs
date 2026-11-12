//! Sealroom: an on-chain registry of who is who, and a record of private
//! conflict checks and agent sessions.
//!
//! Identity
//!   firm    a NEAR account that registers itself and an ed25519 sealing key.
//!           Every list it submits is signed with that key; the contract checks it.
//!   member  a lawyer, registered by their firm with their own signing key.
//!           A member signs each agent session they start.
//!   agent   a NEAR account registered by a firm, owned by one member, pinned to
//!           a model and a prompt hash. Only the agent itself can seal its sessions.
//!
//! The contract never sees client data. For a check it stores each firm's
//! commitment, the verdict hash, and it verifies on-chain both firms' signatures
//! and every TEE signature over the inference that computed the verdict.

use near_sdk::borsh::BorshSerialize;
use near_sdk::store::{IterableMap, LookupMap, LookupSet};
use near_sdk::{env, near, AccountId, BorshStorageKey, PanicOnDefault};

pub const MAX_CALLS: usize = 48;

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
enum Key {
    Firms,
    Members,
    Agents,
    Checks,
    Sessions,
    Refs,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Firm {
    pub name: String,
    /// ed25519 public key, hex. Signs the firm's envelopes.
    pub key: String,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Member {
    pub firm: AccountId,
    pub name: String,
    pub key: String,
    pub active: bool,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Agent {
    pub firm: AccountId,
    pub owner: AccountId,
    pub name: String,
    pub model: String,
    /// sha256 of the agent's system prompt; a session run with any other prompt is refused.
    pub prompt_hash: String,
    pub active: bool,
}

/// One firm's signed submission to a check.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Envelope {
    pub firm: AccountId,
    /// sha256(salt || canonical list). The salt stays with the firm.
    pub commitment: String,
    /// sha256 over the ciphertexts the firm sealed to the model key.
    pub ciphertext_hash: String,
    /// sha256 over the firm's blinded exact-match set.
    pub psi_hash: String,
    /// ed25519 signature by the firm's registered key over `envelope_message`.
    pub signature: String,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Engine {
    pub model: String,
    /// Attested model key (signs provider-kind responses, and is the E2EE recipient).
    pub model_key: String,
    /// Attested gateway key (signs gateway-kind responses).
    pub gateway_key: String,
    /// sha256 of the raw attestation report both keys were taken from.
    pub report_hash: String,
    /// sha256 of the matching instructions sent to the model.
    pub instructions_hash: String,
}

/// One signed inference: the TEE's signature over "<..>:<request sha256>:<response sha256>".
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct SignedCall {
    pub signed_text: String,
    pub signature: String,
    pub signer: String,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct ConflictCheck {
    pub id: u64,
    pub check_ref: String,
    pub incoming: Envelope,
    pub existing: Envelope,
    pub verdict_hash: String,
    pub conflicts_found: u32,
    pub exact_matches: u32,
    /// True if any model call hit its output cap even after splitting.
    pub truncated: bool,
    pub engine: Engine,
    pub calls: u32,
    /// sha256 over every verified call's signed text, in order.
    pub calls_root: String,
    pub recorded_by: AccountId,
    pub recorded_at_ns: u64,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct SessionSeal {
    pub session_id: String,
    pub firm: AccountId,
    pub agent: AccountId,
    pub member: AccountId,
    /// Root of the hash chain over every access decision in the session.
    pub log_root: String,
    pub decisions: u32,
    pub blocked: u32,
    pub policy_hash: String,
    pub question_hash: String,
    pub sealed_at_ns: u64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Sealroom {
    operator: AccountId,
    firms: LookupMap<AccountId, Firm>,
    members: LookupMap<AccountId, Member>,
    agents: LookupMap<AccountId, Agent>,
    checks: IterableMap<u64, ConflictCheck>,
    sessions: LookupMap<String, SessionSeal>,
    refs: LookupSet<String>,
    next_check_id: u64,
}

/// Fail with a reason that survives: log it, then panic. Some nearcore releases
/// report guest panics as a bare `unreachable` trap, which loses the message.
fn fail(msg: &str) -> ! {
    env::log_str(&format!("sealroom: {msg}"));
    env::panic_str(msg)
}

macro_rules! ensure {
    ($cond:expr, $msg:expr $(,)?) => {
        if !$cond {
            fail(&$msg)
        }
    };
}

fn unhex<const N: usize>(label: &str, v: &str) -> [u8; N] {
    let v = v.strip_prefix("0x").unwrap_or(v);
    ensure!(
        v.len() == N * 2 && v.bytes().all(|b| b.is_ascii_hexdigit()),
        format!("{label} must be {N} bytes of hex")
    );
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&v[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn require_hex32(label: &str, v: &str) {
    unhex::<32>(label, v);
}

fn verify(label: &str, key_hex: &str, message: &str, sig_hex: &str) {
    let key = unhex::<32>(&format!("{label} key"), key_hex);
    let sig = unhex::<64>(&format!("{label} signature"), sig_hex);
    ensure!(env::ed25519_verify(&sig, message.as_bytes(), &key), format!("{label} signature is invalid"));
}

/// The exact text a firm signs for its submission. Mirrored in app/src/sealroom/identity.py and web/app.js.
pub fn envelope_message(contract: &str, check_ref: &str, side: &str, counterparty: &str, e: &Envelope) -> String {
    format!(
        "sealroom/envelope/v1|{contract}|{check_ref}|{}|{side}|{counterparty}|{}|{}|{}",
        e.firm, e.commitment, e.ciphertext_hash, e.psi_hash
    )
}

/// The exact text a member signs to start an agent session.
pub fn session_message(contract: &str, agent: &str, session_id: &str, question_hash: &str, policy_hash: &str) -> String {
    format!("sealroom/session/v1|{contract}|{agent}|{session_id}|{question_hash}|{policy_hash}")
}

#[near]
impl Sealroom {
    #[init]
    pub fn new(operator: AccountId) -> Self {
        Self {
            operator,
            firms: LookupMap::new(Key::Firms),
            members: LookupMap::new(Key::Members),
            agents: LookupMap::new(Key::Agents),
            checks: IterableMap::new(Key::Checks),
            sessions: LookupMap::new(Key::Sessions),
            refs: LookupSet::new(Key::Refs),
            next_check_id: 0,
        }
    }

    pub fn operator(&self) -> AccountId {
        self.operator.clone()
    }

    pub fn set_operator(&mut self, operator: AccountId) {
        ensure!(env::predecessor_account_id() == self.operator, "only the operator");
        self.operator = operator;
    }

    // ---------- identity ----------

    /// A firm registers itself, or rotates its sealing key, from its own account.
    pub fn register_firm(&mut self, name: String, key: String) {
        ensure!(!name.is_empty() && name.len() <= 120, "name must be 1-120 chars");
        require_hex32("key", &key);
        let me = env::predecessor_account_id();
        ensure!(!self.members.contains_key(&me) && !self.agents.contains_key(&me), "account is already a member or agent");
        self.firms.insert(me, Firm { name, key: key.to_lowercase() });
    }

    pub fn get_firm(&self, account_id: AccountId) -> Option<Firm> {
        self.firms.get(&account_id).cloned()
    }

    /// A firm adds (or updates) one of its lawyers.
    pub fn add_member(&mut self, member: AccountId, name: String, key: String) {
        let firm = env::predecessor_account_id();
        ensure!(self.firms.contains_key(&firm), "caller is not a registered firm");
        ensure!(!name.is_empty() && name.len() <= 120, "name must be 1-120 chars");
        require_hex32("key", &key);
        ensure!(!self.firms.contains_key(&member) && !self.agents.contains_key(&member), "account is already a firm or agent");
        if let Some(m) = self.members.get(&member) {
            ensure!(m.firm == firm, "member belongs to another firm");
        }
        self.members.insert(member, Member { firm, name, key: key.to_lowercase(), active: true });
    }

    pub fn remove_member(&mut self, member: AccountId) {
        let firm = env::predecessor_account_id();
        let m = self.members.get_mut(&member).unwrap_or_else(|| fail("no such member"));
        ensure!(m.firm == firm, "member belongs to another firm");
        m.active = false;
    }

    pub fn get_member(&self, account_id: AccountId) -> Option<Member> {
        self.members.get(&account_id).cloned()
    }

    /// A firm registers an agent account, owned by one of its active members.
    pub fn register_agent(&mut self, agent: AccountId, owner: AccountId, name: String, model: String, prompt_hash: String) {
        let firm = env::predecessor_account_id();
        ensure!(self.firms.contains_key(&firm), "caller is not a registered firm");
        let o = self.members.get(&owner).unwrap_or_else(|| fail("owner is not a member"));
        ensure!(o.firm == firm && o.active, "owner must be an active member of this firm");
        ensure!(!name.is_empty() && name.len() <= 120, "name must be 1-120 chars");
        ensure!(!model.is_empty() && model.len() <= 120, "model must be 1-120 chars");
        require_hex32("prompt_hash", &prompt_hash);
        ensure!(!self.firms.contains_key(&agent) && !self.members.contains_key(&agent), "account is already a firm or member");
        if let Some(a) = self.agents.get(&agent) {
            ensure!(a.firm == firm, "agent belongs to another firm");
        }
        self.agents.insert(agent, Agent { firm, owner, name, model, prompt_hash: prompt_hash.to_lowercase(), active: true });
    }

    pub fn revoke_agent(&mut self, agent: AccountId) {
        let firm = env::predecessor_account_id();
        let a = self.agents.get_mut(&agent).unwrap_or_else(|| fail("no such agent"));
        ensure!(a.firm == firm, "agent belongs to another firm");
        a.active = false;
    }

    pub fn get_agent(&self, account_id: AccountId) -> Option<Agent> {
        self.agents.get(&account_id).cloned()
    }

    // ---------- conflict checks ----------

    /// Record a completed check. Anyone may submit it (normally the operator),
    /// because every claim in it is checked here: both firms signed this exact
    /// submission for this check_ref, and the TEE signed every inference.
    #[allow(clippy::too_many_arguments)]
    pub fn record_check(
        &mut self,
        check_ref: String,
        incoming: Envelope,
        existing: Envelope,
        verdict_hash: String,
        conflicts_found: u32,
        exact_matches: u32,
        truncated: bool,
        engine: Engine,
        calls: Vec<SignedCall>,
    ) -> u64 {
        ensure!(
            check_ref.len() >= 16 && check_ref.len() <= 64 && check_ref.bytes().all(|b| b.is_ascii_hexdigit()),
            "check_ref must be 16-64 hex chars"
        );
        ensure!(!self.refs.contains(&check_ref), "check_ref already used");
        ensure!(incoming.firm != existing.firm, "a firm cannot check against itself");
        let me = env::current_account_id();
        for (side, e, other) in [("incoming", &incoming, &existing), ("existing", &existing, &incoming)] {
            let firm = self.firms.get(&e.firm).unwrap_or_else(|| fail(&format!("{side} firm is not registered")));
            require_hex32("commitment", &e.commitment);
            require_hex32("ciphertext_hash", &e.ciphertext_hash);
            require_hex32("psi_hash", &e.psi_hash);
            let msg = envelope_message(me.as_str(), &check_ref, side, other.firm.as_str(), e);
            verify(&format!("{side} firm"), &firm.key, &msg, &e.signature);
        }
        require_hex32("verdict_hash", &verdict_hash);
        require_hex32("report_hash", &engine.report_hash);
        require_hex32("instructions_hash", &engine.instructions_hash);
        ensure!(exact_matches <= conflicts_found, "exact matches cannot exceed conflicts");
        ensure!(!calls.is_empty() && calls.len() <= MAX_CALLS, format!("1-{MAX_CALLS} signed calls required"));

        let model_key = engine.model_key.trim_start_matches("0x").to_lowercase();
        let gateway_key = engine.gateway_key.trim_start_matches("0x").to_lowercase();
        let mut root_input = Vec::new();
        for (i, c) in calls.iter().enumerate() {
            let signer = c.signer.trim_start_matches("0x").to_lowercase();
            if signer == model_key {
                ensure!(c.signed_text.starts_with(&format!("{}:", engine.model)), format!("call {i}: model signature over another model"));
            } else {
                ensure!(signer == gateway_key, format!("call {i}: signer is neither the attested model nor gateway key"));
            }
            verify(&format!("call {i} TEE"), &signer, &c.signed_text, &c.signature);
            root_input.extend_from_slice(c.signed_text.as_bytes());
            root_input.push(b'\n');
        }

        let id = self.next_check_id;
        self.next_check_id += 1;
        self.refs.insert(check_ref.clone());
        let check = ConflictCheck {
            id,
            check_ref,
            incoming,
            existing,
            verdict_hash,
            conflicts_found,
            exact_matches,
            truncated,
            engine,
            calls: calls.len() as u32,
            calls_root: hex(&env::sha256(&root_input)),
            recorded_by: env::predecessor_account_id(),
            recorded_at_ns: env::block_timestamp(),
        };
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"sealroom\",\"version\":\"2.0.0\",\"event\":\"check_recorded\",\"data\":{{\"id\":{id},\"conflicts\":{conflicts_found}}}}}"
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

    // ---------- agent sessions ----------

    /// Sealed by the agent's own account. The member who started the session
    /// must have signed it, and the agent must have run its registered model and prompt.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_session(
        &mut self,
        session_id: String,
        member: AccountId,
        log_root: String,
        decisions: u32,
        blocked: u32,
        policy_hash: String,
        question_hash: String,
        model: String,
        prompt_hash: String,
        authorization: String,
    ) {
        let agent_id = env::predecessor_account_id();
        let agent = self.agents.get(&agent_id).unwrap_or_else(|| fail("caller is not a registered agent"));
        ensure!(agent.active, "agent has been revoked");
        ensure!(agent.model == model, "agent ran a model other than the one registered");
        ensure!(agent.prompt_hash == prompt_hash.to_lowercase(), "agent ran a prompt other than the one registered");
        let m = self.members.get(&member).unwrap_or_else(|| fail("member is not registered"));
        ensure!(m.active, "member is not active");
        ensure!(m.firm == agent.firm, "member and agent belong to different firms");
        ensure!(!session_id.is_empty() && session_id.len() <= 64, "session_id must be 1-64 chars");
        ensure!(!self.sessions.contains_key(&session_id), "session already sealed");
        ensure!(blocked <= decisions, "blocked cannot exceed decisions");
        require_hex32("log_root", &log_root);
        require_hex32("policy_hash", &policy_hash);
        require_hex32("question_hash", &question_hash);
        let msg = session_message(env::current_account_id().as_str(), agent_id.as_str(), &session_id, &question_hash, &policy_hash);
        verify("member", &m.key, &msg, &authorization);
        self.sessions.insert(
            session_id.clone(),
            SessionSeal {
                session_id,
                firm: agent.firm.clone(),
                agent: agent_id,
                member,
                log_root,
                decisions,
                blocked,
                policy_hash,
                question_hash,
                sealed_at_ns: env::block_timestamp(),
            },
        );
    }

    pub fn get_session(&self, session_id: String) -> Option<SessionSeal> {
        self.sessions.get(&session_id).cloned()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    const H: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REF: &str = "0123456789abcdef";
    const CONTRACT: &str = "sealroom.testnet";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn pk(k: &SigningKey) -> String {
        hex(k.verifying_key().as_bytes())
    }
    fn sign(k: &SigningKey, msg: &str) -> String {
        hex(&k.sign(msg.as_bytes()).to_bytes())
    }

    fn as_caller(who: &str) {
        testing_env!(VMContextBuilder::new()
            .current_account_id(CONTRACT.parse().unwrap())
            .predecessor_account_id(who.parse().unwrap())
            .build());
    }

    fn setup() -> Sealroom {
        as_caller("op.testnet");
        let mut c = Sealroom::new("op.testnet".parse().unwrap());
        as_caller("north.testnet");
        c.register_firm("North".into(), pk(&key(1)));
        as_caller("south.testnet");
        c.register_firm("South".into(), pk(&key(2)));
        c.add_member("jane.testnet".parse().unwrap(), "Jane Okafor".into(), pk(&key(3)));
        c.register_agent("agent.testnet".parse().unwrap(), "jane.testnet".parse().unwrap(), "Research".into(), "m".into(), H.into());
        c
    }

    fn envelope(firm: &str, side: &str, other: &str, k: &SigningKey) -> Envelope {
        let mut e = Envelope { firm: firm.parse().unwrap(), commitment: H.into(), ciphertext_hash: H.into(), psi_hash: H.into(), signature: String::new() };
        e.signature = sign(k, &envelope_message(CONTRACT, REF, side, other, &e));
        e
    }

    fn engine(model_key: &SigningKey) -> Engine {
        Engine { model: "m".into(), model_key: pk(model_key), gateway_key: pk(&key(9)), report_hash: H.into(), instructions_hash: H.into() }
    }

    fn call(k: &SigningKey) -> SignedCall {
        let text = format!("m:{H}:{H}");
        SignedCall { signature: sign(k, &text), signed_text: text, signer: pk(k) }
    }

    fn record(c: &mut Sealroom, inc: Envelope, ext: Envelope, calls: Vec<SignedCall>) -> u64 {
        c.record_check(REF.into(), inc, ext, H.into(), 2, 1, false, engine(&key(8)), calls)
    }

    #[test]
    fn records_a_check_signed_by_both_firms_and_the_tee() {
        let mut c = setup();
        as_caller("op.testnet");
        let id = record(
            &mut c,
            envelope("north.testnet", "incoming", "south.testnet", &key(1)),
            envelope("south.testnet", "existing", "north.testnet", &key(2)),
            vec![call(&key(8)), call(&key(8))],
        );
        let got = c.get_check(id).unwrap();
        assert_eq!(got.calls, 2);
        assert_eq!(got.recorded_by.as_str(), "op.testnet");
        assert_eq!(c.list_checks(None, None).len(), 1);
    }

    #[test]
    #[should_panic(expected = "existing firm signature is invalid")]
    fn forged_firm_signature_rejected() {
        let mut c = setup();
        as_caller("op.testnet");
        // Signed by the operator's key, not South's.
        record(
            &mut c,
            envelope("north.testnet", "incoming", "south.testnet", &key(1)),
            envelope("south.testnet", "existing", "north.testnet", &key(7)),
            vec![call(&key(8))],
        );
    }

    #[test]
    #[should_panic(expected = "incoming firm signature is invalid")]
    fn envelope_cannot_be_replayed_against_another_firm() {
        let mut c = setup();
        as_caller("op.testnet");
        // North signed for counterparty "west", not "south".
        record(
            &mut c,
            envelope("north.testnet", "incoming", "west.testnet", &key(1)),
            envelope("south.testnet", "existing", "north.testnet", &key(2)),
            vec![call(&key(8))],
        );
    }

    #[test]
    #[should_panic(expected = "check_ref already used")]
    fn check_ref_used_once() {
        let mut c = setup();
        as_caller("op.testnet");
        for _ in 0..2 {
            record(
                &mut c,
                envelope("north.testnet", "incoming", "south.testnet", &key(1)),
                envelope("south.testnet", "existing", "north.testnet", &key(2)),
                vec![call(&key(8))],
            );
        }
    }

    #[test]
    #[should_panic(expected = "signer is neither the attested model nor gateway key")]
    fn unattested_signer_rejected() {
        let mut c = setup();
        as_caller("op.testnet");
        record(
            &mut c,
            envelope("north.testnet", "incoming", "south.testnet", &key(1)),
            envelope("south.testnet", "existing", "north.testnet", &key(2)),
            vec![call(&key(6))],
        );
    }

    #[test]
    #[should_panic(expected = "call 0 TEE signature is invalid")]
    fn tampered_call_rejected() {
        let mut c = setup();
        as_caller("op.testnet");
        let mut bad = call(&key(8));
        bad.signed_text = format!("m:{H}:{}", "b".repeat(64));
        record(
            &mut c,
            envelope("north.testnet", "incoming", "south.testnet", &key(1)),
            envelope("south.testnet", "existing", "north.testnet", &key(2)),
            vec![bad],
        );
    }

    fn seal(c: &mut Sealroom, member_key: &SigningKey, prompt: &str) {
        let msg = session_message(CONTRACT, "agent.testnet", "s1", H, H);
        c.seal_session("s1".into(), "jane.testnet".parse().unwrap(), H.into(), 5, 1, H.into(), H.into(), "m".into(), prompt.into(), sign(member_key, &msg));
    }

    #[test]
    fn agent_seals_a_member_authorised_session() {
        let mut c = setup();
        as_caller("agent.testnet");
        seal(&mut c, &key(3), H);
        let s = c.get_session("s1".into()).unwrap();
        assert_eq!(s.member.as_str(), "jane.testnet");
        assert_eq!(s.firm.as_str(), "south.testnet");
    }

    #[test]
    #[should_panic(expected = "caller is not a registered agent")]
    fn only_the_agent_can_seal() {
        let mut c = setup();
        as_caller("south.testnet");
        seal(&mut c, &key(3), H);
    }

    #[test]
    #[should_panic(expected = "member signature is invalid")]
    fn session_needs_the_members_signature() {
        let mut c = setup();
        as_caller("agent.testnet");
        seal(&mut c, &key(4), H);
    }

    #[test]
    #[should_panic(expected = "agent ran a prompt other than the one registered")]
    fn agent_pinned_to_its_prompt() {
        let mut c = setup();
        as_caller("agent.testnet");
        seal(&mut c, &key(3), &"b".repeat(64));
    }

    #[test]
    #[should_panic(expected = "agent has been revoked")]
    fn revoked_agent_cannot_seal() {
        let mut c = setup();
        as_caller("south.testnet");
        c.revoke_agent("agent.testnet".parse().unwrap());
        as_caller("agent.testnet");
        seal(&mut c, &key(3), H);
    }

    #[test]
    #[should_panic(expected = "member belongs to another firm")]
    fn firm_cannot_take_over_another_firms_member() {
        let mut c = setup();
        as_caller("north.testnet");
        c.add_member("jane.testnet".parse().unwrap(), "Jane".into(), pk(&key(5)));
    }

    #[test]
    #[should_panic(expected = "session already sealed")]
    fn session_seals_once() {
        let mut c = setup();
        as_caller("agent.testnet");
        seal(&mut c, &key(3), H);
        seal(&mut c, &key(3), H);
    }
}
