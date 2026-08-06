//! Driver for the atomic claim script (`lua/claim.lua`, architecture.md §9.1).
//!
//! Task 3.1 built the script and the raw invocation (`ClaimScript::claim`). Task 3.2
//! added the typed wrapper (`ClaimRequest` / `ClaimOutcome`, via `ClaimScript::submit`)
//! and the cap-metadata seeding used by `POST /v1/budgets`. Task 3.3 wires `submit`
//! into the proxy request path with the status codes from architecture.md §4.3.

use alloy::primitives::{keccak256, Address};
use redis::aio::ConnectionManager;
use redis::{RedisResult, Script};

/// The Redis stream every reservation is appended to, inside the same atomic
/// execution as the spend increment (architecture.md §9.3).
pub const RESERVATIONS_KEY: &str = "tg:reservations";

const CLAIM_LUA: &str = include_str!("lua/claim.lua");

pub fn nonce_key(nonce: &str) -> String {
    format!("tg:nonce:{nonce}")
}

pub fn spent_key(cap_hash: &str) -> String {
    format!("tg:cap:{cap_hash}:spent")
}

pub fn meta_key(cap_hash: &str) -> String {
    format!("tg:cap:{cap_hash}:meta")
}

/// Phase 3's payer-level stand-in for a capability hash. `POST /v1/budgets` seeds
/// meta under this hash and the proxy route looks it up under the same hash, so
/// the two must compute it identically; shared here rather than duplicated so
/// they cannot drift apart.
pub fn payer_cap_hash(payer: &Address) -> String {
    keccak256(payer.as_slice()).to_string()
}

/// Writes `tg:cap:{cap_hash}:meta` from already-parsed base units. This is what
/// `POST /v1/budgets` seeds for the payer-level stand-in (architecture.md §5.1's
/// key shape; Phase 5 replaces the source of these keys with a real capability
/// chain, but the shape is unchanged).
pub async fn seed_cap_meta(
    conn: &mut ConnectionManager,
    cap_hash: &str,
    max_total: u128,
    max_per_request: u128,
) -> RedisResult<()> {
    redis::cmd("HSET")
        .arg(meta_key(cap_hash))
        .arg("max_total")
        .arg(max_total.to_string())
        .arg("max_per_request")
        .arg(max_per_request.to_string())
        .exec_async(conn)
        .await
}

/// The revocation set (architecture.md §5.2: revocation is off-chain, and that is
/// sufficient because the gateway is the enforcement point). Members are capability struct
/// hashes in `0x`-prefixed lowercase hex, the form `B256`'s `Display` produces.
pub const REVOKED_KEY: &str = "tg:revoked";

/// Writes a verified capability's own limits into `tg:cap:{hash}:meta` (Task 5.4). The
/// capability is self-describing and signed, so presenting it is the only registration step
/// there is — which is what makes `delegate()` a pure local signature with no server round
/// trip (architecture.md §7.3).
///
/// **No TTL, deliberately.** `expiry` is written as an ordinary field for the boot rebuild
/// and the dashboard, but the key does not expire: expiring `:meta` while `:spent` survived
/// would orphan the counter, and an expired capability would then surface as the claim
/// script's `missing_meta` rather than the 403 `capability_expired` architecture.md §4.3
/// requires. Expiry is enforced ahead of the claim by `capability::verify::verify_chain`,
/// which is the only place that can produce the right status code.
///
/// Must only be called on a chain that has already passed `verify_chain`: this writes the
/// limits the claim script then enforces, so writing it for an unverified chain would let a
/// caller install its own caps.
pub async fn upsert_capability_meta(
    conn: &mut ConnectionManager,
    cap_hash: &str,
    max_total: u128,
    max_per_request: u128,
    expiry: u64,
) -> RedisResult<()> {
    redis::cmd("HSET")
        .arg(meta_key(cap_hash))
        .arg("max_total")
        .arg(max_total.to_string())
        .arg("max_per_request")
        .arg(max_per_request.to_string())
        .arg("expiry")
        .arg(expiry.to_string())
        .exec_async(conn)
        .await
}

/// Adds a capability to the revocation set (Task 5.5). The member format must match what
/// `fetch_revoked` queries: `B256`'s `Display`, i.e. `0x` and lowercase hex.
pub async fn add_revoked(conn: &mut ConnectionManager, cap_hash: &str) -> RedisResult<()> {
    redis::cmd("SADD")
        .arg(REVOKED_KEY)
        .arg(cap_hash)
        .exec_async(conn)
        .await
}

/// Which of `hashes` are revoked, in one round trip. `SMISMEMBER` rather than `SMEMBERS`:
/// the revocation set grows without bound over a deployment's life and there is no reason to
/// transfer it to answer a question about at most four hashes.
pub async fn fetch_revoked(
    conn: &mut ConnectionManager,
    hashes: &[String],
) -> RedisResult<std::collections::HashSet<String>> {
    if hashes.is_empty() {
        return Ok(std::collections::HashSet::new());
    }

    let mut cmd = redis::cmd("SMISMEMBER");
    cmd.arg(REVOKED_KEY);
    for hash in hashes {
        cmd.arg(hash);
    }
    let flags: Vec<bool> = cmd.query_async(conn).await?;

    Ok(hashes
        .iter()
        .zip(flags)
        .filter(|(_, revoked)| *revoked)
        .map(|(hash, _)| hash.clone())
        .collect())
}

/// `max_total` and current `spent` for one level, for the 429 body. A level that has never
/// been charged has no counter yet, which reads as zero rather than as an error.
pub async fn read_level_state(
    conn: &mut ConnectionManager,
    cap_hash: &str,
) -> RedisResult<(u128, u128)> {
    let max_total: Option<String> = redis::cmd("HGET")
        .arg(meta_key(cap_hash))
        .arg("max_total")
        .query_async(conn)
        .await?;
    let spent: Option<String> = redis::cmd("GET")
        .arg(spent_key(cap_hash))
        .query_async(conn)
        .await?;

    Ok((
        max_total.and_then(|v| v.parse().ok()).unwrap_or(0),
        spent.and_then(|v| v.parse().ok()).unwrap_or(0),
    ))
}

/// Credits `amount` back to every given cap level after an upstream failure
/// (Task 4.4, architecture.md §4.2 step 7: 2xx promotes, everything else
/// voids and credits back). Deliberately does not touch `tg:nonce:{nonce}`:
/// the EIP-3009 signature is still replayable until `validBefore`, so
/// releasing the nonce here would reopen the free-shopping window the atomic
/// claim exists to close. The claimed request simply never settles.
pub async fn void(conn: &mut ConnectionManager, cap_hashes: &[String], amount: u128) -> RedisResult<()> {
    for cap_hash in cap_hashes {
        redis::cmd("DECRBY")
            .arg(spent_key(cap_hash))
            .arg(amount.to_string())
            .exec_async(conn)
            .await?;
    }
    Ok(())
}

/// architecture.md §9.2 rule 2: the nonce TTL must never be a constant, or the
/// Redis guard can expire while the EIP-3009 signature is still validly
/// replayable. `now` and `valid_before` are unix seconds; `clock_skew_seconds`
/// is the same tolerance `x402::validate::validate_fields` already applied.
///
/// By the time this runs, `validate_fields` step 1 has already rejected a
/// `valid_before` at or before `now + clock_skew`, so a non-positive result here
/// means that invariant was violated somewhere upstream. Asserted, not just
/// checked, for exactly that reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TtlError {
    #[error("validity window already elapsed: valid_before + clock_skew <= now")]
    AlreadyElapsed,
}

pub fn nonce_ttl_secs(valid_before: u64, now: u64, clock_skew_seconds: u64) -> Result<u64, TtlError> {
    let ttl = valid_before as i128 + clock_skew_seconds as i128 - now as i128;
    if ttl <= 0 {
        return Err(TtlError::AlreadyElapsed);
    }
    debug_assert!(ttl > 0, "checked above; nonce TTL must be positive");
    Ok(ttl as u64)
}

/// One invocation's worth of input. `cap_hashes` is root-first and may hold any
/// number of levels: Phase 3 passes exactly one (the payer), Phase 5 passes the
/// whole capability chain without the script changing.
pub struct ClaimArgs<'a> {
    pub nonce: &'a str,
    pub payer: &'a str,
    pub provider_slug: &'a str,
    pub amount: u128,
    pub ttl_secs: u64,
    /// The full EIP-3009 payload, already serialised as JSON. It is carried
    /// through the stream untouched and lands in `authorisations.payload`
    /// (JSONB, NOT NULL), so the caller owes valid JSON here.
    pub payload_json: &'a str,
    /// The payment signature as 0x hex, landing in `authorisations.signature`
    /// (BYTEA, NOT NULL) once the drain decodes it. The Phase 6 settler rebuilds
    /// v/r/s from this.
    pub signature_hex: &'a str,
    pub cap_hashes: &'a [String],
}

/// The claim script, hashed once at construction.
pub struct ClaimScript {
    script: Script,
}

impl ClaimScript {
    pub fn new() -> Self {
        ClaimScript {
            script: Script::new(CLAIM_LUA),
        }
    }

    /// `SCRIPT LOAD` at startup so the first real request pays for an `EVALSHA`
    /// and not for a `NOSCRIPT` round trip. Returns the server-side SHA1.
    pub async fn load(&self, conn: &mut ConnectionManager) -> RedisResult<String> {
        self.script.load_async(conn).await
    }

    /// Invokes the script. `invoke_async` issues `EVALSHA` and falls back to
    /// loading plus a retry if the server answers `NOSCRIPT`.
    ///
    /// The reply is the raw array the script returns: `["replay"]`,
    /// `["missing_meta", level, hash]`, `["cap_exceeded", level, hash, limit]`,
    /// `["insufficient", level, hash, remaining]`, or `["ok", stream_id]`.
    pub async fn claim(
        &self,
        conn: &mut ConnectionManager,
        args: ClaimArgs<'_>,
    ) -> RedisResult<Vec<String>> {
        let mut invocation = self.script.prepare_invoke();

        // KEYS[1], then KEYS[2..n+1], then KEYS[n+2], then KEYS[n+3..2n+2].
        invocation.key(nonce_key(args.nonce));
        for cap_hash in args.cap_hashes {
            invocation.key(spent_key(cap_hash));
        }
        invocation.key(RESERVATIONS_KEY);
        for cap_hash in args.cap_hashes {
            invocation.key(meta_key(cap_hash));
        }

        // ARGV[1..8] are fixed; the variadic capability block is ARGV[9..].
        invocation
            .arg(args.amount.to_string())
            .arg(args.ttl_secs)
            .arg(args.cap_hashes.len())
            .arg(args.nonce)
            .arg(args.payer)
            .arg(args.provider_slug)
            .arg(args.payload_json)
            .arg(args.signature_hex);
        for cap_hash in args.cap_hashes {
            invocation.arg(cap_hash.as_str());
        }

        invocation.invoke_async(conn).await
    }
}

impl Default for ClaimScript {
    fn default() -> Self {
        Self::new()
    }
}

/// One capability level, root first. Phase 3 passes exactly one, keyed by the
/// payer (`POST /v1/budgets`'s stand-in); Phase 5 fills this from a verified
/// capability chain without changing the script or this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapLevel {
    pub cap_hash: String,
}

/// The typed request into the claim script. Carries the same fixed fields as
/// `ClaimArgs` plus the level list in the higher-level shape callers naturally
/// have on hand.
pub struct ClaimRequest<'a> {
    pub nonce: &'a str,
    pub amount: u128,
    pub levels: Vec<CapLevel>,
    pub provider_slug: &'a str,
    pub payer: &'a str,
    pub ttl_secs: u64,
    pub payload_json: &'a str,
    pub signature_hex: &'a str,
}

/// The claim script's reply, parsed. `MissingMeta` is not in `architecture.md`
/// §4.3's failure table because that table assumes a capability chain has
/// already been through Task 5.4's meta upsert; in Phase 3, an unfunded payer
/// (one who never called `/v1/budgets`) hits exactly this path, and Task 3.1's
/// script deliberately treats a missing level as an error, never a silent pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    Ok { stream_id: String },
    Replay,
    CapExceeded { level: usize, cap_hash: String, limit: u128 },
    Insufficient { level: usize, cap_hash: String, remaining: u128 },
    MissingMeta { level: usize, cap_hash: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("unexpected claim script reply: {0:?}")]
    UnexpectedReply(Vec<String>),
}

fn parse_outcome(raw: Vec<String>) -> Result<ClaimOutcome, ClaimError> {
    fn get(raw: &[String], i: usize) -> Result<&str, ClaimError> {
        raw.get(i)
            .map(String::as_str)
            .ok_or_else(|| ClaimError::UnexpectedReply(raw.to_vec()))
    }
    fn parse<T: std::str::FromStr>(raw: &[String], i: usize) -> Result<T, ClaimError> {
        get(raw, i)?
            .parse()
            .map_err(|_| ClaimError::UnexpectedReply(raw.to_vec()))
    }

    match get(&raw, 0)? {
        "ok" => Ok(ClaimOutcome::Ok {
            stream_id: get(&raw, 1)?.to_string(),
        }),
        "replay" => Ok(ClaimOutcome::Replay),
        "cap_exceeded" => Ok(ClaimOutcome::CapExceeded {
            level: parse(&raw, 1)?,
            cap_hash: get(&raw, 2)?.to_string(),
            limit: parse(&raw, 3)?,
        }),
        "insufficient" => Ok(ClaimOutcome::Insufficient {
            level: parse(&raw, 1)?,
            cap_hash: get(&raw, 2)?.to_string(),
            remaining: parse(&raw, 3)?,
        }),
        "missing_meta" => Ok(ClaimOutcome::MissingMeta {
            level: parse(&raw, 1)?,
            cap_hash: get(&raw, 2)?.to_string(),
        }),
        _ => Err(ClaimError::UnexpectedReply(raw)),
    }
}

impl ClaimScript {
    /// The typed entry point: converts a `ClaimRequest` into the raw `ClaimArgs`
    /// call and parses the reply into a `ClaimOutcome`.
    pub async fn submit(
        &self,
        conn: &mut ConnectionManager,
        request: ClaimRequest<'_>,
    ) -> Result<ClaimOutcome, ClaimError> {
        let cap_hashes: Vec<String> = request.levels.into_iter().map(|l| l.cap_hash).collect();
        let raw = self
            .claim(
                conn,
                ClaimArgs {
                    nonce: request.nonce,
                    payer: request.payer,
                    provider_slug: request.provider_slug,
                    amount: request.amount,
                    ttl_secs: request.ttl_secs,
                    payload_json: request.payload_json,
                    signature_hex: request.signature_hex,
                    cap_hashes: &cap_hashes,
                },
            )
            .await?;
        parse_outcome(raw)
    }
}

#[cfg(test)]
mod claim {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::Mutex;

    /// Every test here appends to the single shared `tg:reservations` stream, so
    /// the ones that assert on its length must not overlap.
    static STREAM_LOCK: Mutex<()> = Mutex::const_new(());

    /// Distinct nonces and cap hashes per test, so runs do not collide with each
    /// other or with leftovers from a previous run.
    fn unique(tag: &str) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the unix epoch")
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{tag}-{nanos}-{n}")
    }

    async fn connect() -> ConnectionManager {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        redis::Client::open(url)
            .expect("redis url should parse")
            .get_connection_manager()
            .await
            .expect("redis should be reachable; start it with ./scripts/dev.sh")
    }

    async fn seed_meta(conn: &mut ConnectionManager, cap_hash: &str, max_total: u128, max_per_request: u128) {
        seed_cap_meta(conn, cap_hash, max_total, max_per_request)
            .await
            .expect("seeding cap meta should succeed");
    }

    async fn spent(conn: &mut ConnectionManager, cap_hash: &str) -> u128 {
        let raw: Option<String> = redis::cmd("GET")
            .arg(spent_key(cap_hash))
            .query_async(conn)
            .await
            .expect("reading spend should succeed");
        raw.map(|v| v.parse().expect("spend should be an integer"))
            .unwrap_or(0)
    }

    async fn stream_len(conn: &mut ConnectionManager) -> u64 {
        redis::cmd("XLEN")
            .arg(RESERVATIONS_KEY)
            .query_async(conn)
            .await
            .expect("XLEN should succeed")
    }

    async fn ttl(conn: &mut ConnectionManager, nonce: &str) -> i64 {
        redis::cmd("TTL")
            .arg(nonce_key(nonce))
            .query_async(conn)
            .await
            .expect("TTL should succeed")
    }

    /// Shaped like the real thing: nested objects and quoted hex, so the round trip
    /// through redis-rs, Lua and XADD is actually exercised rather than trivially
    /// satisfied by a bare token.
    const PAYLOAD_JSON: &str = r#"{"x402Version":1,"scheme":"exact","network":"eip155:84532","payload":{"authorization":{"from":"0x00000000000000000000000000000000000000a1","to":"0x0000000000000000000000000000000000000001","value":"1000","validAfter":"0","validBefore":"99999999999","nonce":"0xab"}}}"#;

    const SIGNATURE_HEX: &str = "0x1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff001c";

    fn args<'a>(nonce: &'a str, amount: u128, cap_hashes: &'a [String]) -> ClaimArgs<'a> {
        ClaimArgs {
            nonce,
            payer: "0x00000000000000000000000000000000000000a1",
            provider_slug: "mock-ok",
            amount,
            ttl_secs: 360,
            payload_json: PAYLOAD_JSON,
            signature_hex: SIGNATURE_HEX,
            cap_hashes,
        }
    }

    #[tokio::test]
    #[ignore = "requires a live redis"]
    async fn first_claim_returns_ok_and_a_replay_leaves_spend_unchanged() {
        let mut conn = connect().await;
        let _guard = STREAM_LOCK.lock().await;

        let cap = unique("cap");
        let nonce = unique("nonce");
        let caps = vec![cap.clone()];
        seed_meta(&mut conn, &cap, 1_000_000, 100_000).await;

        let script = ClaimScript::new();

        let first = script.claim(&mut conn, args(&nonce, 1_000, &caps)).await.unwrap();
        assert_eq!(first[0], "ok", "first claim of a fresh nonce should succeed");
        assert_eq!(first.len(), 2, "ok carries the stream id");
        let after_first = spent(&mut conn, &cap).await;
        assert_eq!(after_first, 1_000);

        let second = script.claim(&mut conn, args(&nonce, 1_000, &caps)).await.unwrap();
        assert_eq!(second, vec!["replay".to_string()]);
        assert_eq!(
            spent(&mut conn, &cap).await,
            after_first,
            "a replay must not move the spend counter"
        );
    }

    #[tokio::test]
    #[ignore = "requires a live redis"]
    async fn amount_over_max_per_request_returns_cap_exceeded_naming_the_level() {
        let mut conn = connect().await;
        let _guard = STREAM_LOCK.lock().await;

        // Root is generous, the leaf is not: the leaf is level 1 and must be the
        // one named.
        let root = unique("cap-root");
        let leaf = unique("cap-leaf");
        let caps = vec![root.clone(), leaf.clone()];
        seed_meta(&mut conn, &root, 1_000_000, 100_000).await;
        seed_meta(&mut conn, &leaf, 1_000_000, 5_000).await;

        let nonce = unique("nonce");
        let reply = ClaimScript::new()
            .claim(&mut conn, args(&nonce, 6_000, &caps))
            .await
            .unwrap();

        assert_eq!(reply[0], "cap_exceeded");
        assert_eq!(reply[1], "1", "the leaf is level 1, root-first and 0-based");
        assert_eq!(reply[2], leaf);
        assert_eq!(reply[3], "5000", "the limit that tripped");

        assert_eq!(spent(&mut conn, &root).await, 0, "no level may be charged");
        assert_eq!(spent(&mut conn, &leaf).await, 0);
        let exists: i64 = redis::cmd("EXISTS")
            .arg(nonce_key(&nonce))
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(exists, 0, "a rejected claim must not consume the nonce");
    }

    #[tokio::test]
    #[ignore = "requires a live redis"]
    async fn spend_accumulating_past_max_total_returns_insufficient_with_remaining() {
        let mut conn = connect().await;
        let _guard = STREAM_LOCK.lock().await;

        let cap = unique("cap");
        let caps = vec![cap.clone()];
        // Room for exactly three charges of 1_000, with 500 left over.
        seed_meta(&mut conn, &cap, 3_500, 1_000).await;

        let script = ClaimScript::new();
        for i in 0..3 {
            let nonce = unique(&format!("nonce-{i}"));
            let reply = script.claim(&mut conn, args(&nonce, 1_000, &caps)).await.unwrap();
            assert_eq!(reply[0], "ok", "charge {i} should fit");
        }
        assert_eq!(spent(&mut conn, &cap).await, 3_000);

        let nonce = unique("nonce-over");
        let reply = script.claim(&mut conn, args(&nonce, 1_000, &caps)).await.unwrap();

        assert_eq!(reply[0], "insufficient");
        assert_eq!(reply[1], "0");
        assert_eq!(reply[2], cap);
        assert_eq!(reply[3], "500", "remaining is max_total - spent, not the shortfall");
        assert_eq!(spent(&mut conn, &cap).await, 3_000, "a refusal charges nothing");
    }

    #[tokio::test]
    #[ignore = "requires a live redis"]
    async fn a_successful_claim_sets_the_nonce_ttl_charges_and_appends_to_the_stream() {
        let mut conn = connect().await;
        let _guard = STREAM_LOCK.lock().await;

        let cap = unique("cap");
        let caps = vec![cap.clone()];
        seed_meta(&mut conn, &cap, 1_000_000, 100_000).await;

        let before = stream_len(&mut conn).await;
        let nonce = unique("nonce");
        let reply = ClaimScript::new()
            .claim(&mut conn, args(&nonce, 2_500, &caps))
            .await
            .unwrap();

        assert_eq!(reply[0], "ok");

        let observed_ttl = ttl(&mut conn, &nonce).await;
        assert!(
            observed_ttl > 0 && observed_ttl <= 360,
            "nonce TTL should be the requested 360s or just under, got {observed_ttl}"
        );
        assert_eq!(spent(&mut conn, &cap).await, 2_500);
        assert_eq!(stream_len(&mut conn).await, before + 1, "one reservation appended");

        // The stream entry must carry everything the Task 3.4 drain needs to build a
        // complete `authorisations` row, because that row is the Phase 6 settler's
        // only input.
        let entries: Vec<(String, Vec<String>)> = redis::cmd("XRANGE")
            .arg(RESERVATIONS_KEY)
            .arg(&reply[1])
            .arg(&reply[1])
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(entries.len(), 1, "the returned stream id should address one entry");
        let fields: std::collections::HashMap<&str, &str> = entries[0]
            .1
            .chunks(2)
            .map(|pair| (pair[0].as_str(), pair[1].as_str()))
            .collect();

        assert_eq!(fields["nonce"], nonce);
        assert_eq!(fields["payer"], "0x00000000000000000000000000000000000000a1");
        assert_eq!(fields["provider"], "mock-ok");
        assert_eq!(fields["amount"], "2500");
        assert_eq!(fields["cap_hashes"], cap);
        // Byte-identical, quotes and all: the drain re-parses this as JSONB.
        assert_eq!(fields["payload"], PAYLOAD_JSON, "payload must survive the round trip verbatim");
        assert_eq!(fields["signature"], SIGNATURE_HEX);
    }

    #[tokio::test]
    #[ignore = "requires a live redis"]
    async fn a_level_without_meta_is_an_error_not_a_silent_pass() {
        let mut conn = connect().await;
        let _guard = STREAM_LOCK.lock().await;

        let seeded = unique("cap-seeded");
        let unseeded = unique("cap-unseeded");
        let caps = vec![seeded.clone(), unseeded.clone()];
        seed_meta(&mut conn, &seeded, 1_000_000, 100_000).await;

        let nonce = unique("nonce");
        let reply = ClaimScript::new()
            .claim(&mut conn, args(&nonce, 1_000, &caps))
            .await
            .unwrap();

        assert_eq!(reply[0], "missing_meta");
        assert_eq!(reply[1], "1");
        assert_eq!(reply[2], unseeded);
        assert_eq!(spent(&mut conn, &seeded).await, 0, "an unmetered level charges nothing");
    }

    /// The v1 race in architecture.md §9.1: check-then-decrement across three round
    /// trips lets two requests both pass the cap check. This must be concurrent to
    /// mean anything.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "requires a live redis"]
    async fn one_hundred_concurrent_claims_stop_exactly_at_max_total() {
        let mut conn = connect().await;
        let _guard = STREAM_LOCK.lock().await;

        const AMOUNT: u128 = 1_000;
        const PERMITTED: u128 = 50;

        let cap = unique("cap");
        seed_meta(&mut conn, &cap, AMOUNT * PERMITTED, AMOUNT).await;

        let script = std::sync::Arc::new(ClaimScript::new());
        let caps = std::sync::Arc::new(vec![cap.clone()]);

        let mut handles = Vec::with_capacity(100);
        for i in 0..100 {
            let script = script.clone();
            let caps = caps.clone();
            let mut conn = conn.clone();
            let nonce = unique(&format!("nonce-race-{i}"));
            handles.push(tokio::spawn(async move {
                script
                    .claim(&mut conn, args(&nonce, AMOUNT, &caps))
                    .await
                    .expect("claim should not error")
            }));
        }

        let mut ok = 0;
        let mut insufficient = 0;
        for handle in handles {
            let reply = handle.await.expect("claim task should not panic");
            match reply[0].as_str() {
                "ok" => ok += 1,
                "insufficient" => insufficient += 1,
                other => panic!("unexpected outcome {other}"),
            }
        }

        assert_eq!(ok, 50, "exactly the permitted number of claims may succeed");
        assert_eq!(insufficient, 50);
        assert_eq!(
            spent(&mut conn, &cap).await,
            AMOUNT * PERMITTED,
            "total spend must never exceed max_total"
        );
    }
}

/// Task 5.4: a charge draws down every capability in the chain, not just the leaf
/// (architecture.md §5.2). These exercise the claim script through the same variadic level
/// list the request path builds from a verified chain.
#[cfg(test)]
mod multilevel {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique(tag: &str) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the unix epoch")
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{tag}-{nanos}-{n}")
    }

    async fn connect() -> ConnectionManager {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        redis::Client::open(url)
            .expect("redis url should parse")
            .get_connection_manager()
            .await
            .expect("redis should be reachable; start it with ./scripts/dev.sh")
    }

    async fn spent(conn: &mut ConnectionManager, cap_hash: &str) -> u128 {
        let raw: Option<String> = redis::cmd("GET")
            .arg(spent_key(cap_hash))
            .query_async(conn)
            .await
            .expect("reading spend should succeed");
        raw.map(|v| v.parse().expect("spend should be an integer"))
            .unwrap_or(0)
    }

    const PAYLOAD_JSON: &str = r#"{"x402Version":1,"scheme":"exact","network":"eip155:84532"}"#;
    const SIGNATURE_HEX: &str = "0x1b";

    /// A supervisor -> lead -> worker chain, each level seeded with its own limits.
    async fn chain(
        conn: &mut ConnectionManager,
        limits: [(u128, u128); 3],
    ) -> Vec<String> {
        let hashes: Vec<String> = (0..3).map(|i| unique(&format!("cap-level-{i}"))).collect();
        for (hash, (max_total, max_per_request)) in hashes.iter().zip(limits) {
            upsert_capability_meta(conn, hash, max_total, max_per_request, 1_800_000_000)
                .await
                .expect("seeding capability meta should succeed");
        }
        hashes
    }

    async fn claim(
        conn: &mut ConnectionManager,
        nonce: &str,
        amount: u128,
        hashes: &[String],
    ) -> ClaimOutcome {
        ClaimScript::new()
            .submit(
                conn,
                ClaimRequest {
                    nonce,
                    amount,
                    levels: hashes
                        .iter()
                        .map(|cap_hash| CapLevel {
                            cap_hash: cap_hash.clone(),
                        })
                        .collect(),
                    provider_slug: "mock-ok",
                    payer: "0x00000000000000000000000000000000000000a1",
                    ttl_secs: 360,
                    payload_json: PAYLOAD_JSON,
                    signature_hex: SIGNATURE_HEX,
                },
            )
            .await
            .expect("claim should not error")
    }

    #[tokio::test]
    #[ignore = "requires a live redis"]
    async fn one_charge_increments_every_level() {
        let mut conn = connect().await;
        let hashes = chain(&mut conn, [(1_000_000, 100_000); 3]).await;

        let outcome = claim(&mut conn, &unique("nonce"), 10_000, &hashes).await;
        assert!(matches!(outcome, ClaimOutcome::Ok { .. }));

        for (level, hash) in hashes.iter().enumerate() {
            assert_eq!(
                spent(&mut conn, hash).await,
                10_000,
                "level {level} must be charged, not just the leaf"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires a live redis"]
    async fn a_void_credits_every_level_back() {
        let mut conn = connect().await;
        let hashes = chain(&mut conn, [(1_000_000, 100_000); 3]).await;

        assert!(matches!(
            claim(&mut conn, &unique("nonce"), 10_000, &hashes).await,
            ClaimOutcome::Ok { .. }
        ));
        void(&mut conn, &hashes, 10_000)
            .await
            .expect("voiding should succeed");

        for (level, hash) in hashes.iter().enumerate() {
            assert_eq!(
                spent(&mut conn, hash).await,
                0,
                "level {level} must be credited back; an upstream failure charges nobody"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires a live redis"]
    async fn a_leaf_with_a_small_max_total_trips_first_and_names_level_two() {
        let mut conn = connect().await;
        // Ancestors are generous; the worker's own budget is what runs out.
        let hashes = chain(
            &mut conn,
            [(1_000_000, 100_000), (1_000_000, 100_000), (15_000, 100_000)],
        )
        .await;

        assert!(matches!(
            claim(&mut conn, &unique("nonce"), 10_000, &hashes).await,
            ClaimOutcome::Ok { .. }
        ));

        match claim(&mut conn, &unique("nonce"), 10_000, &hashes).await {
            ClaimOutcome::Insufficient {
                level,
                cap_hash,
                remaining,
            } => {
                assert_eq!(level, 2, "the leaf is level 2, root-first and 0-based");
                assert_eq!(cap_hash, hashes[2]);
                assert_eq!(remaining, 5_000);
            }
            other => panic!("expected the leaf to trip, got {other:?}"),
        }

        // The refused charge moved nothing anywhere.
        assert_eq!(spent(&mut conn, &hashes[0]).await, 10_000);
    }

    /// The supervisor's pool emptying stops a worker that still has room of its own. This is
    /// the behaviour the delegation tree exists to show.
    #[tokio::test]
    #[ignore = "requires a live redis"]
    async fn a_root_with_a_small_max_total_trips_even_when_the_leaf_has_room() {
        let mut conn = connect().await;
        let hashes = chain(
            &mut conn,
            [(15_000, 100_000), (1_000_000, 100_000), (1_000_000, 100_000)],
        )
        .await;

        assert!(matches!(
            claim(&mut conn, &unique("nonce"), 10_000, &hashes).await,
            ClaimOutcome::Ok { .. }
        ));

        match claim(&mut conn, &unique("nonce"), 10_000, &hashes).await {
            ClaimOutcome::Insufficient {
                level,
                cap_hash,
                remaining,
            } => {
                assert_eq!(level, 0, "the root is what said no");
                assert_eq!(cap_hash, hashes[0]);
                assert_eq!(remaining, 5_000);
            }
            other => panic!("expected the root to trip, got {other:?}"),
        }

        // The leaf had plenty left and is untouched by the refusal.
        assert_eq!(spent(&mut conn, &hashes[2]).await, 10_000);
    }

    #[tokio::test]
    #[ignore = "requires a live redis"]
    async fn a_per_request_cap_at_any_level_names_that_level() {
        let mut conn = connect().await;
        let hashes = chain(
            &mut conn,
            [(1_000_000, 100_000), (1_000_000, 5_000), (1_000_000, 100_000)],
        )
        .await;

        match claim(&mut conn, &unique("nonce"), 10_000, &hashes).await {
            ClaimOutcome::CapExceeded {
                level,
                cap_hash,
                limit,
            } => {
                assert_eq!(level, 1);
                assert_eq!(cap_hash, hashes[1]);
                assert_eq!(limit, 5_000);
            }
            other => panic!("expected a per-request cap to trip, got {other:?}"),
        }

        for hash in &hashes {
            assert_eq!(spent(&mut conn, hash).await, 0, "a refusal charges nothing");
        }
    }
}

#[cfg(test)]
mod ttl {
    use super::*;

    #[test]
    fn ttl_equals_valid_before_minus_now_plus_skew() {
        let ttl = nonce_ttl_secs(1_000, 700, 60).expect("validity has not elapsed");
        assert_eq!(ttl, 1_000 - 700 + 60);
    }

    #[test]
    fn a_payload_whose_validity_already_elapsed_errors() {
        // valid_before + clock_skew (560) is behind now (700): already elapsed.
        let err = nonce_ttl_secs(500, 700, 60).unwrap_err();
        assert_eq!(err, TtlError::AlreadyElapsed);
    }

    #[test]
    fn exactly_zero_ttl_is_also_an_error() {
        // valid_before + clock_skew == now: the boundary must not be granted a TTL of 0.
        let err = nonce_ttl_secs(640, 700, 60).unwrap_err();
        assert_eq!(err, TtlError::AlreadyElapsed);
    }
}

