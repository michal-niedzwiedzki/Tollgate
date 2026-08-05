//! Driver for the atomic claim script (`lua/claim.lua`, architecture.md §9.1).
//!
//! This task owns the script and the plumbing that loads and invokes it. The typed
//! `ClaimRequest` / `ClaimOutcome` wrapper and the cap-metadata seeding endpoint are
//! Task 3.2, so `claim` deliberately returns the raw reply array for now.

use redis::aio::ConnectionManager;
use redis::{RedisResult, Script};

// The items below carrying `allow(dead_code)` are exercised by this module's tests
// and get their production caller in Task 3.2 (the typed wrapper and the cap-meta
// seeding endpoint) and Task 3.3 (the request path). The attributes come off as
// each one gains that caller.

/// The Redis stream every reservation is appended to, inside the same atomic
/// execution as the spend increment (architecture.md §9.3).
#[allow(dead_code)]
pub const RESERVATIONS_KEY: &str = "tg:reservations";

const CLAIM_LUA: &str = include_str!("lua/claim.lua");

#[allow(dead_code)]
pub fn nonce_key(nonce: &str) -> String {
    format!("tg:nonce:{nonce}")
}

#[allow(dead_code)]
pub fn spent_key(cap_hash: &str) -> String {
    format!("tg:cap:{cap_hash}:spent")
}

#[allow(dead_code)]
pub fn meta_key(cap_hash: &str) -> String {
    format!("tg:cap:{cap_hash}:meta")
}

/// One invocation's worth of input. `cap_hashes` is root-first and may hold any
/// number of levels: Phase 3 passes exactly one (the payer), Phase 5 passes the
/// whole capability chain without the script changing.
#[allow(dead_code)]
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
    #[allow(dead_code)]
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
        redis::cmd("HSET")
            .arg(meta_key(cap_hash))
            .arg("max_total")
            .arg(max_total.to_string())
            .arg("max_per_request")
            .arg(max_per_request.to_string())
            .exec_async(conn)
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
