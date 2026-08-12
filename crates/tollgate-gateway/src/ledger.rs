//! Drains `tg:reservations` into `authorisations` (architecture.md §9.3): Redis
//! is a projection, Postgres is the truth, and this stream is the crash-safe
//! bridge between them. Runs as a background task started at gateway boot.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::{Address, Bytes, B256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol;
use alloy::sol_types::SolStruct;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::Value;
use sqlx::PgPool;
use tollgate_core::types::{bytea_to_address, bytea_to_b256, numeric_to_u256};

use crate::policy::RESERVATIONS_KEY;

const CONSUMER_GROUP: &str = "tg-writer";
const CONSUMER_NAME: &str = "gateway";
const BATCH_SIZE: usize = 100;
const BLOCK_MS: usize = 1000;

/// How long a `tg:outcome:{nonce}` marker survives, generously longer than any
/// realistic drain lag. Bridges the race between the proxy request path
/// finishing before the drain has inserted a row for that nonce yet: see
/// `mark_outcome` and `insert_reservation`.
const OUTCOME_MARKER_TTL_SECS: u64 = 3600;

sol! {
    /// The per-charge spend receipt (Task 7.1, prd.md F6). What the chain cannot show:
    /// *which* endpoint was called, on whose delegated budget, and whether the upstream
    /// actually returned 200. A `Transfer` event proves money moved; this proves what it
    /// bought.
    ///
    /// Signed by the gateway, so its trust story is different from a capability's: a
    /// capability is signed by an agent and the gateway is the verifier, whereas here the
    /// gateway is the *attester* and the payer, the provider and whoever funded the run are
    /// all verifiers. `GET /v1/gateway-key` publishes the address that closes that loop.
    ///
    /// `capabilityHash` is `0x0` when the charge carried no capability chain — the permanent
    /// payer-level path of NOTES.md D1. That mirrors `authorisations.capability_hash` being
    /// SQL NULL for exactly those rows, which is what lets `GET /v1/receipts/{nonce}`
    /// reconstruct the signed body from the row byte-for-byte.
    #[derive(Debug)]
    struct Receipt {
        bytes32 nonce;
        address payer;
        bytes32 capabilityHash;
        string providerSlug;
        uint256 amount;
        uint16 upstreamStatus;
        uint64 timestamp;
    }
}

/// A receipt and the gateway signature over it. The two travel together everywhere: in the
/// `X-Tollgate-Receipt` response header, and out of `GET /v1/receipts/{nonce}`. Handing back
/// a signature without the exact body it covers would make it unverifiable.
#[derive(Debug)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    pub signature: Vec<u8>,
}

/// Signs `receipt` under the Tollgate EIP-712 domain — the same domain a capability and a
/// revocation use, so `chainId` is the cross-chain replay guard here too (architecture.md
/// §10). The struct's own type hash is what keeps the three apart: a signature over a
/// `Receipt` can never be read as a `Capability`.
pub fn sign_receipt(
    signer: &PrivateKeySigner,
    chain_id: u64,
    receipt: Receipt,
) -> Result<SignedReceipt, alloy::signers::Error> {
    let signing_hash = receipt.eip712_signing_hash(&crate::capability::domain(chain_id));
    let signature = signer.sign_hash_sync(&signing_hash)?;
    Ok(SignedReceipt {
        receipt,
        signature: signature.as_bytes().to_vec(),
    })
}

impl SignedReceipt {
    /// The wire form, used identically by the response header and the lookup endpoint so a
    /// client has one shape to parse and one shape to verify against.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "nonce": self.receipt.nonce.to_string(),
            "payer": self.receipt.payer.to_string(),
            "capability_hash": self.receipt.capabilityHash.to_string(),
            "provider_slug": self.receipt.providerSlug,
            "amount": self.receipt.amount.to_string(),
            "upstream_status": self.receipt.upstreamStatus,
            "timestamp": self.receipt.timestamp,
            "signature": alloy::hex::encode_prefixed(&self.signature),
        })
    }

    /// Base64 of `to_json`, for `X-Tollgate-Receipt`. Base64 so the JSON's quotes and braces
    /// cannot collide with header syntax, matching how `X-PAYMENT` carries its payload.
    pub fn to_header_value(&self) -> String {
        BASE64.encode(self.to_json().to_string())
    }

    /// `(issued_at, signature)` — everything the promotion path must persist beyond the
    /// columns it already writes.
    pub fn stored(&self) -> (u64, &[u8]) {
        (self.receipt.timestamp, self.signature.as_slice())
    }
}

/// A receipt as it travels between the request path and the ledger: `(issued_at, signature)`,
/// the two things a promotion has to persist beyond the columns it already writes.
type StoredReceipt = (u64, Vec<u8>);

/// Where a reservation ends up once the proxy round trip is known:
/// architecture.md §4.2 step 7. A 2xx promotes it to `queued`, settleable;
/// anything else voids it. `upstream_status` is `None` only when no HTTP
/// response was ever received at all (a timeout or a connector failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationOutcome {
    Queued { upstream_status: i32 },
    Voided { upstream_status: Option<i32> },
}

impl ReservationOutcome {
    fn status_str(&self) -> &'static str {
        match self {
            ReservationOutcome::Queued { .. } => "queued",
            ReservationOutcome::Voided { .. } => "voided",
        }
    }

    fn upstream_status(&self) -> Option<i32> {
        match self {
            ReservationOutcome::Queued { upstream_status } => Some(*upstream_status),
            ReservationOutcome::Voided { upstream_status } => *upstream_status,
        }
    }

    /// `status:code`, with an empty code when no HTTP response was received, and
    /// `:issued_at:signature` appended when a receipt was signed for this charge.
    /// Paired with `from_marker` so the two halves cannot drift apart.
    ///
    /// The receipt rides inside the marker rather than in a key of its own because the
    /// marker's whole purpose is to carry what the drain must apply when the row did not
    /// exist yet, and a receipt is exactly that. One key means one write and no new
    /// ordering invariant between two keys that could be read half-applied.
    fn marker_value(&self, receipt: Option<(u64, &[u8])>) -> String {
        let outcome = match self.upstream_status() {
            Some(code) => format!("{}:{code}", self.status_str()),
            None => format!("{}:", self.status_str()),
        };
        match receipt {
            Some((issued_at, signature)) => {
                format!(
                    "{outcome}:{issued_at}:{}",
                    alloy::hex::encode_prefixed(signature)
                )
            }
            None => outcome,
        }
    }

    fn from_marker(marker: &str) -> Option<(Self, Option<StoredReceipt>)> {
        let mut parts = marker.splitn(4, ':');
        let status = parts.next()?;
        let upstream_status = parts.next()?.parse::<i32>().ok();

        let outcome = match status {
            "queued" => ReservationOutcome::Queued {
                upstream_status: upstream_status?,
            },
            "voided" => ReservationOutcome::Voided { upstream_status },
            _ => return None,
        };

        // A marker written before Task 7.1, or for a void, carries no receipt. That is not a
        // parse failure: the outcome half must still be applied.
        let receipt = match (parts.next(), parts.next()) {
            (Some(issued_at), Some(signature)) => Some((
                issued_at.parse::<u64>().ok()?,
                alloy::hex::decode(signature).ok()?,
            )),
            _ => None,
        };

        Some((outcome, receipt))
    }
}

fn outcome_marker_key(nonce_hex: &str) -> String {
    format!("tg:outcome:{nonce_hex}")
}

/// Writes the small marker `insert_reservation` consults after inserting, for
/// the case where the request path decided this nonce's outcome before the
/// drain had inserted a row at all.
///
/// **The caller must write this marker before attempting `apply_outcome_update`.**
/// That ordering is load-bearing: it is what lets the drain's post-INSERT read
/// (see `insert_reservation`) be guaranteed to observe a marker whenever the
/// request path's own UPDATE found no row to update.
pub async fn mark_outcome(
    redis: &mut ConnectionManager,
    nonce_hex: &str,
    outcome: &ReservationOutcome,
    receipt: Option<(u64, &[u8])>,
) -> redis::RedisResult<()> {
    redis::cmd("SET")
        .arg(outcome_marker_key(nonce_hex))
        .arg(outcome.marker_value(receipt))
        .arg("EX")
        .arg(OUTCOME_MARKER_TTL_SECS)
        .query_async(redis)
        .await
}

/// The request path's own idempotent attempt at the same update, for the
/// common case where the drain's row already landed by the time the proxy
/// round trip finishes. `WHERE status = 'reserved'` makes the transition
/// one-way (`reserved -> queued` or `reserved -> voided` only) and makes a
/// racing `mark_outcome` + drain insert safe: whichever of this UPDATE and
/// the drain's INSERT runs second is a no-op against the other's result.
/// `receipt` is `Some` only for a promotion (Task 7.1 signs at 2xx and nowhere else), and
/// `COALESCE` keeps it that way: whichever of the two promotion paths runs second cannot
/// blank a signature the first already stored.
pub async fn apply_outcome_update(
    pg: &PgPool,
    nonce: &[u8],
    outcome: &ReservationOutcome,
    receipt: Option<(u64, &[u8])>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE authorisations
            SET status = $1,
                upstream_status = $2,
                receipt_sig = COALESCE($4, receipt_sig),
                receipt_issued_at = COALESCE($5, receipt_issued_at)
         WHERE nonce = $3 AND status = 'reserved'",
    )
    .bind(outcome.status_str())
    .bind(outcome.upstream_status())
    .bind(nonce)
    .bind(receipt.map(|(_, signature)| signature))
    .bind(receipt.map(|(issued_at, _)| issued_at as i64))
    .execute(pg)
    .await?;
    Ok(result.rows_affected())
}

/// Rebuilds every Redis capability counter from Postgres before the gateway serves
/// anything (Task 5.6, architecture.md §9.3).
///
/// "Rebuild at boot, not lazily. A cold-start miss that lets an agent overspend is exactly
/// the bug that surfaces later, once it's in use." A gateway that started with empty
/// counters would treat every capability as unspent and let an agent spend its whole budget
/// a second time, which is why this is awaited before the listener binds rather than being
/// spawned alongside it.
///
/// Redis loss is survivable but not lossless: reservations that had been claimed and not yet
/// drained into Postgres are gone with the stream. That window is seconds, and it is stated
/// here rather than papered over — §9.3 is explicit that exactly-once across a Redis wipe is
/// not on offer.
pub async fn rebuild_counters(
    redis: &mut ConnectionManager,
    pg: &PgPool,
) -> Result<(), tollgate_core::Error> {
    // Steps 4 and 5 come from one pass over `capabilities`: a capability's limits and its
    // revocation state are columns of the same row.
    let capabilities = tollgate_core::db::list_capabilities(pg).await?;
    let mut meta_rebuilt = 0usize;
    let mut revoked_rebuilt = 0usize;

    for stored in &capabilities {
        let capability = &stored.capability;
        let hash = capability.hash.to_string();

        match (
            u128::try_from(capability.max_total_wei),
            u128::try_from(capability.max_per_req_wei),
        ) {
            (Ok(max_total), Ok(max_per_request)) => {
                crate::policy::upsert_capability_meta(
                    redis,
                    &hash,
                    max_total,
                    max_per_request,
                    capability.expiry,
                )
                .await?;
                meta_rebuilt += 1;
            }
            // Unreachable for anything this gateway accepted, since the request path parses
            // the same limits as u128 before seeding. Skipping is still the right response:
            // an unparseable level must not become an unmetered one.
            _ => {
                tracing::warn!(%hash, "capability limits exceed u128; meta not rebuilt");
            }
        }

        if stored.revoked_at.is_some() {
            crate::policy::add_revoked(redis, &hash).await?;
            revoked_rebuilt += 1;
        }
    }

    // Step 3, last: the counters are what the claim script enforces against, so they are
    // restored only once the limits they are checked against are already in place.
    let spend = tollgate_core::db::spend_by_capability(pg).await?;
    let mut total = alloy::primitives::U256::ZERO;
    for (hash, amount) in &spend {
        redis::cmd("SET")
            .arg(crate::policy::spent_key(&hash.to_string()))
            .arg(amount.to_string())
            .exec_async(redis)
            .await?;
        total += *amount;
    }

    tracing::info!(
        capabilities = capabilities.len(),
        meta_rebuilt,
        revoked_rebuilt,
        levels_with_spend = spend.len(),
        reconstructed_spend_wei = %total,
        "rebuilt capability counters from postgres"
    );

    Ok(())
}

/// Creates the consumer group if needed, replays anything left pending from a
/// previous run, then loops reading and applying new entries forever.
///
/// Uses its own connection rather than the shared `AppState` one: a `BLOCK
/// 1000` read must be allowed to sit on the wire for a full second, but
/// `ConnectionManager`'s default response timeout is 500ms, shorter than that
/// block — every blocking read would time out client-side before Redis could
/// ever reply. The response timeout here is set comfortably longer than the
/// block duration to give BLOCK_MS room to actually elapse.
pub async fn run(redis_url: String, pg: PgPool) {
    let client = match redis::Client::open(redis_url.as_str()) {
        Ok(client) => client,
        Err(err) => {
            tracing::error!(error = %err, "failed to build redis client for ledger drain; not started");
            return;
        }
    };
    let config = ConnectionManagerConfig::new()
        .set_response_timeout(Some(Duration::from_millis(BLOCK_MS as u64 + 1000)));
    let mut redis = match ConnectionManager::new_with_config(client, config).await {
        Ok(conn) => conn,
        Err(err) => {
            tracing::error!(error = %err, "failed to connect to redis for ledger drain; not started");
            return;
        }
    };

    if let Err(err) = ensure_group(&mut redis).await {
        tracing::error!(error = %err, "failed to create tg-writer consumer group; ledger drain not started");
        return;
    }

    replay_pending(&mut redis, &pg, RESERVATIONS_KEY).await;

    loop {
        match read_group(&mut redis, RESERVATIONS_KEY, ">", Some(BLOCK_MS)).await {
            Ok(entries) => apply_batch(&mut redis, &pg, RESERVATIONS_KEY, entries).await,
            Err(err) => {
                tracing::error!(error = %err, "XREADGROUP failed; retrying");
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        }
    }
}

/// Replays this consumer's pending list once, at startup.
///
/// A previous run may have `XREADGROUP`'d entries into the PEL without acking them — a crash,
/// or an insert that failed. Those are redelivered here before any new entry is taken.
///
/// **The cursor is what makes this terminate.** `apply_batch` deliberately leaves an entry
/// un-acked when it cannot be applied (Task 3.4: "never let one bad entry stall the drain"),
/// which is right for the steady-state `>` loop because that always advances. Re-reading from
/// `"0"` every iteration does not advance: an entry that can *never* apply — a `provider_slug`
/// whose row was deleted, a payload a later migration cannot parse, a row hitting a new CHECK
/// constraint — is redelivered forever, this loop never ends, and the drain never reaches the
/// `>` loop at all. No reservation is written to Postgres for the remaining life of the
/// process, while the request path happily keeps returning 200.
///
/// Paging forward from the last id read means a permanently-unappliable entry is passed over
/// once per boot instead. It stays in the PEL for an operator to inspect or `XACK`, and every
/// entry behind it still lands.
async fn replay_pending(redis: &mut ConnectionManager, pg: &PgPool, stream: &str) {
    let mut cursor = "0".to_string();
    loop {
        match read_group(redis, stream, &cursor, None).await {
            Ok(entries) if entries.is_empty() => break,
            Ok(entries) => {
                // Advance past this page before applying it, so the next read cannot return
                // the same entries regardless of which of them applied.
                if let Some((last_id, _)) = entries.last() {
                    cursor = last_id.clone();
                }
                apply_batch(redis, pg, stream, entries).await;
            }
            Err(err) => {
                tracing::error!(error = %err, "failed to read pending reservations at startup");
                break;
            }
        }
    }
}

async fn ensure_group(redis: &mut ConnectionManager) -> redis::RedisResult<()> {
    let result: redis::RedisResult<()> = redis::cmd("XGROUP")
        .arg("CREATE")
        .arg(RESERVATIONS_KEY)
        .arg(CONSUMER_GROUP)
        .arg("0")
        .arg("MKSTREAM")
        .query_async(redis)
        .await;

    match result {
        Ok(()) => Ok(()),
        // The group already exists from a previous boot; not an error.
        Err(e) if e.code() == Some("BUSYGROUP") => Ok(()),
        Err(e) => Err(e),
    }
}

async fn read_group(
    redis: &mut ConnectionManager,
    stream: &str,
    id: &str,
    block_ms: Option<usize>,
) -> redis::RedisResult<Vec<(String, HashMap<String, String>)>> {
    let mut cmd = redis::cmd("XREADGROUP");
    cmd.arg("GROUP").arg(CONSUMER_GROUP).arg(CONSUMER_NAME);
    if let Some(ms) = block_ms {
        cmd.arg("BLOCK").arg(ms);
    }
    cmd.arg("COUNT")
        .arg(BATCH_SIZE)
        .arg("STREAMS")
        .arg(stream)
        .arg(id);

    let value: Value = cmd.query_async(redis).await?;
    Ok(parse_stream_reply(value))
}

/// Parses the raw `XREADGROUP` reply for a single stream:
/// `[[stream_name, [[entry_id, [field, value, ...]], ...]]]`, or `Nil` when a
/// blocking read times out with nothing new.
fn parse_stream_reply(value: Value) -> Vec<(String, HashMap<String, String>)> {
    let Value::Array(streams) = value else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for stream in streams {
        let Value::Array(stream_pair) = stream else {
            continue;
        };
        let Some(Value::Array(entries)) = stream_pair.into_iter().nth(1) else {
            continue;
        };

        for entry in entries {
            let Value::Array(mut entry_pair) = entry else {
                continue;
            };
            if entry_pair.len() != 2 {
                continue;
            }
            let field_values = entry_pair.pop().unwrap();
            let id_value = entry_pair.pop().unwrap();

            let Ok(id) = redis::from_redis_value::<String>(id_value) else {
                continue;
            };
            let Value::Array(kv) = field_values else {
                continue;
            };

            let mut fields = HashMap::new();
            let mut iter = kv.into_iter();
            while let (Some(k), Some(v)) = (iter.next(), iter.next()) {
                if let (Ok(k), Ok(v)) = (
                    redis::from_redis_value::<String>(k),
                    redis::from_redis_value::<String>(v),
                ) {
                    fields.insert(k, v);
                }
            }
            out.push((id, fields));
        }
    }
    out
}

async fn apply_batch(
    redis: &mut ConnectionManager,
    pg: &PgPool,
    stream: &str,
    entries: Vec<(String, HashMap<String, String>)>,
) {
    for (id, fields) in entries {
        match insert_reservation(redis, pg, &fields).await {
            Ok(()) => {
                if let Err(err) = ack(redis, stream, &id).await {
                    tracing::error!(error = %err, entry_id = %id, "failed to XACK a committed reservation");
                }
            }
            Err(err) => {
                // Never let one bad entry stall the drain: log it and move on
                // to the next entry in this batch. It stays in the PEL,
                // un-acked, and is replayed from the startup pending-drain on
                // the next restart.
                tracing::error!(error = %err, entry_id = %id, "failed to apply reservation; leaving unacked");
            }
        }
    }
}

async fn ack(redis: &mut ConnectionManager, stream: &str, id: &str) -> redis::RedisResult<()> {
    redis::cmd("XACK")
        .arg(stream)
        .arg(CONSUMER_GROUP)
        .arg(id)
        .query_async(redis)
        .await
}

async fn insert_reservation(
    redis: &mut ConnectionManager,
    pg: &PgPool,
    fields: &HashMap<String, String>,
) -> Result<(), String> {
    let get = |key: &str| {
        fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("stream entry missing field {key}"))
    };

    let nonce_hex = get("nonce")?;
    let payer_hex = get("payer")?;
    let provider_slug = get("provider")?;
    let amount = get("amount")?;
    let payload = get("payload")?;
    let signature_hex = get("signature")?;

    let nonce = B256::from_str(nonce_hex).map_err(|e| format!("bad nonce {nonce_hex}: {e}"))?;
    let payer = Address::from_str(payer_hex).map_err(|e| format!("bad payer {payer_hex}: {e}"))?;
    let signature =
        Bytes::from_str(signature_hex).map_err(|e| format!("bad signature {signature_hex}: {e}"))?;

    // Every level this charge drew against, root first, as written by the claim script in
    // the same atomic execution as the decrement. Task 5.6 rebuilds each level's spend by
    // summing `amount_wei` across this array, so a charge that omitted it would silently
    // under-count its ancestors after a restart.
    //
    // Levels that are not capabilities (the payer-level case, keyed by `keccak(payer)`) are
    // recorded here too. The column carries no foreign key precisely so that it can hold
    // them, which keeps the boot rebuild to a single code path.
    let chain_hashes: Vec<Vec<u8>> = fields
        .get("cap_hashes")
        .map(String::as_str)
        .unwrap_or_default()
        .split(',')
        .filter(|hash| !hash.is_empty())
        .map(|hash| {
            B256::from_str(hash)
                .map(|h| h.as_slice().to_vec())
                .map_err(|e| format!("bad cap hash {hash}: {e}"))
        })
        .collect::<Result<_, _>>()?;

    // The leaf is "which agent spent this", which is the question the
    // `(capability_hash, created_at DESC)` index exists to answer.
    //
    // Resolved through a subquery rather than bound directly: the column is a foreign key
    // onto `capabilities`, and a payer-level hash has no row there. The subquery yields NULL
    // in that case instead of a constraint violation — which would otherwise be a permanently
    // unappliable entry, stalling this drain for every later reservation.
    let leaf_hash: Option<Vec<u8>> = chain_hashes.last().cloned();

    // The nonce is the idempotency key end to end (architecture.md §9.4): a
    // reservation already landed from an earlier, unacked delivery is not an
    // error. This is also the other half of the outcome race: if the request
    // path's own `apply_outcome_update` already updated this row (the common
    // case, where the drain inserted first), this INSERT becomes the no-op.
    sqlx::query(
        "INSERT INTO authorisations
           (nonce, payer, provider_slug, amount_wei, payload, signature, status,
            capability_hash, chain_hashes)
         VALUES ($1, $2, $3, $4::NUMERIC, $5::JSONB, $6, 'reserved',
                 (SELECT hash FROM capabilities WHERE hash = $7), $8)
         ON CONFLICT (nonce) DO NOTHING",
    )
    .bind(nonce.as_slice())
    .bind(payer.as_slice())
    .bind(provider_slug)
    .bind(amount)
    .bind(payload)
    .bind(signature.as_ref())
    .bind(leaf_hash)
    .bind(&chain_hashes)
    .execute(pg)
    .await
    .map_err(|e| format!("insert failed: {e}"))?;

    // Read the marker *after* the INSERT, never before. This ordering is what
    // closes the race, and the reasoning is worth stating exactly because
    // reading it earlier looks equivalent and is not:
    //
    //   The request path always SETs its marker before attempting its own
    //   UPDATE. So if that UPDATE ran before this INSERT — matching no row and
    //   silently doing nothing — then the marker was written before the UPDATE,
    //   hence before this INSERT, hence before this read. It is therefore
    //   impossible for that UPDATE to have missed *and* this read to miss too.
    //
    // Reading before the INSERT left exactly that hole: both sides could read
    // before the other wrote, and the row stayed 'reserved' forever with no
    // retry to rescue it.
    let marker: Option<String> = redis::cmd("GET")
        .arg(outcome_marker_key(nonce_hex))
        .query_async(redis)
        .await
        .map_err(|e| format!("failed to read outcome marker: {e}"))?;

    if let Some((outcome, receipt)) = marker.as_deref().and_then(ReservationOutcome::from_marker) {
        // `WHERE status = 'reserved'` inside makes this idempotent against the
        // request path having already applied the same transition. The receipt
        // comes along for the ride: this is the branch where the request path's
        // own UPDATE found no row, so it is the only chance to persist the
        // signature it already handed to the caller in a response header.
        let receipt = receipt
            .as_ref()
            .map(|(issued_at, signature)| (*issued_at, signature.as_slice()));
        apply_outcome_update(pg, nonce.as_slice(), &outcome, receipt)
            .await
            .map_err(|e| format!("failed to apply outcome marker: {e}"))?;
    }

    Ok(())
}

/// What `GET /v1/receipts/{nonce}` found. A charge with no receipt is a different answer from
/// a nonce this gateway has never seen, and the caller deserves to be told which.
pub enum ReceiptLookup {
    UnknownNonce,
    /// The charge exists but was never promoted, so no receipt was ever signed: it was voided
    /// on an upstream failure, or it is still in flight.
    NotIssued { status: String },
    Issued {
        receipt: SignedReceipt,
        /// Populated by the settler once the batch lands (Task 6.4), NULL until then.
        tx_hash: Option<B256>,
    },
}

#[derive(sqlx::FromRow)]
struct ReceiptRow {
    payer: Vec<u8>,
    capability_hash: Option<Vec<u8>>,
    provider_slug: Option<String>,
    amount_wei: String,
    upstream_status: Option<i32>,
    receipt_issued_at: Option<i64>,
    receipt_sig: Option<Vec<u8>>,
    tx_hash: Option<Vec<u8>>,
    status: String,
}

/// Rebuilds the exact `Receipt` that was signed, from the row's own columns.
///
/// Every field is read back from where the signing path wrote it — including
/// `capability_hash`, whose SQL NULL becomes the `0x0` that was signed for a payer-level
/// charge. A field reconstructed even slightly differently would produce a body the stored
/// signature does not cover, so this function and `handle_proxy_request`'s call to
/// `sign_receipt` are two halves of one contract.
pub async fn fetch_receipt(pg: &PgPool, nonce: B256) -> Result<ReceiptLookup, String> {
    let row: Option<ReceiptRow> = sqlx::query_as(
        "SELECT payer, capability_hash, provider_slug, amount_wei::TEXT AS amount_wei,
                upstream_status, receipt_issued_at, receipt_sig, tx_hash, status
         FROM authorisations WHERE nonce = $1",
    )
    .bind(nonce.as_slice())
    .fetch_optional(pg)
    .await
    .map_err(|e| format!("receipt lookup failed: {e}"))?;

    let Some(row) = row else {
        return Ok(ReceiptLookup::UnknownNonce);
    };

    let (Some(signature), Some(issued_at)) = (row.receipt_sig, row.receipt_issued_at) else {
        return Ok(ReceiptLookup::NotIssued { status: row.status });
    };

    let upstream_status = row
        .upstream_status
        .and_then(|code| u16::try_from(code).ok())
        .ok_or_else(|| "a signed receipt must have an upstream status".to_string())?;

    let receipt = Receipt {
        nonce,
        payer: bytea_to_address(&row.payer).map_err(|e| e.to_string())?,
        capabilityHash: row
            .capability_hash
            .as_deref()
            .map(bytea_to_b256)
            .transpose()
            .map_err(|e| e.to_string())?
            .unwrap_or(B256::ZERO),
        providerSlug: row.provider_slug.unwrap_or_default(),
        amount: numeric_to_u256(&row.amount_wei).map_err(|e| e.to_string())?,
        upstreamStatus: upstream_status,
        timestamp: issued_at as u64,
    };

    Ok(ReceiptLookup::Issued {
        receipt: SignedReceipt {
            receipt,
            signature,
        },
        tx_hash: row
            .tx_hash
            .as_deref()
            .map(bytea_to_b256)
            .transpose()
            .map_err(|e| e.to_string())?,
    })
}

#[cfg(test)]
mod outcome_race {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_SLUG: &str = "test-outcome-race";

    async fn pg_pool() -> PgPool {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/tollgate".to_string());
        PgPool::connect(&url)
            .await
            .expect("postgres should be reachable; start it with ./scripts/dev.sh")
    }

    async fn redis_conn() -> ConnectionManager {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        redis::Client::open(url)
            .expect("redis url should parse")
            .get_connection_manager()
            .await
            .expect("redis should be reachable; start it with ./scripts/dev.sh")
    }

    /// A fresh 32-byte nonce per run, so repeated runs never collide with each
    /// other's rows (the nonce is the table's primary key).
    fn unique_nonce() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the unix epoch")
            .as_nanos();
        format!("0x{nanos:064x}")
    }

    /// The payout address must be a full 20 bytes. A shorter one inserts fine —
    /// the column is a bare `BYTEA` — but then every later `list_providers` call
    /// fails to decode the whole table, which took out an unrelated
    /// `tollgate-core` test for as long as the row survived. This helper never
    /// deletes the row (its three tests run concurrently and share it), so
    /// `DO UPDATE` is what repairs a database that already holds the old
    /// malformed one.
    async fn ensure_provider(pg: &PgPool) {
        sqlx::query(
            "INSERT INTO providers (slug, upstream_url, price_wei, payout_address)
             VALUES ($1, 'http://127.0.0.1:9000', 1000::NUMERIC, '\\x00000000000000000000000000000000000000a1')
             ON CONFLICT (slug) DO UPDATE SET payout_address = EXCLUDED.payout_address",
        )
        .bind(TEST_SLUG)
        .execute(pg)
        .await
        .expect("seeding the test provider should succeed");
    }

    fn stream_fields(nonce_hex: &str) -> HashMap<String, String> {
        HashMap::from([
            ("nonce".to_string(), nonce_hex.to_string()),
            (
                "payer".to_string(),
                "0x00000000000000000000000000000000000000a1".to_string(),
            ),
            ("provider".to_string(), TEST_SLUG.to_string()),
            ("amount".to_string(), "1000".to_string()),
            (
                "payload".to_string(),
                r#"{"payload":{"authorization":{"value":"1000"}}}"#.to_string(),
            ),
            ("signature".to_string(), "0x1b2c3d".to_string()),
        ])
    }

    async fn status_of(pg: &PgPool, nonce_hex: &str) -> Option<(String, Option<i32>)> {
        let nonce = B256::from_str(nonce_hex).unwrap();
        sqlx::query_as::<_, (String, Option<i32>)>(
            "SELECT status, upstream_status FROM authorisations WHERE nonce = $1",
        )
        .bind(nonce.as_slice())
        .fetch_optional(pg)
        .await
        .expect("status query should succeed")
    }

    async fn cleanup(pg: &PgPool, redis: &mut ConnectionManager, nonce_hex: &str) {
        let nonce = B256::from_str(nonce_hex).unwrap();
        sqlx::query("DELETE FROM authorisations WHERE nonce = $1")
            .bind(nonce.as_slice())
            .execute(pg)
            .await
            .ok();
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(outcome_marker_key(nonce_hex))
            .query_async(redis)
            .await;
    }

    /// The interleaving that used to strand a reservation at `reserved`
    /// forever: the request path finished, wrote its marker, and ran its own
    /// UPDATE against a row the drain had not inserted yet (matching nothing),
    /// and only then did the drain insert. Nothing retried afterwards.
    #[tokio::test]
    #[ignore = "requires live postgres and redis"]
    async fn a_marker_written_before_the_row_exists_is_still_applied() {
        let pg = pg_pool().await;
        let mut redis = redis_conn().await;
        ensure_provider(&pg).await;
        let nonce_hex = unique_nonce();

        // Request path: marker, then an UPDATE that matches no row at all.
        let outcome = ReservationOutcome::Voided {
            upstream_status: Some(500),
        };
        mark_outcome(&mut redis, &nonce_hex, &outcome, None)
            .await
            .expect("marking the outcome should succeed");
        let nonce = B256::from_str(&nonce_hex).unwrap();
        let rows = apply_outcome_update(&pg, nonce.as_slice(), &outcome, None)
            .await
            .expect("the update should not error");
        assert_eq!(rows, 0, "no row exists yet, so this UPDATE must match nothing");

        // Drain arrives afterwards.
        insert_reservation(&mut redis, &pg, &stream_fields(&nonce_hex))
            .await
            .expect("the drain insert should succeed");

        let observed = status_of(&pg, &nonce_hex).await;
        cleanup(&pg, &mut redis, &nonce_hex).await;

        assert_eq!(
            observed,
            Some(("voided".to_string(), Some(500))),
            "a reservation whose outcome was decided before its row existed must not be left reserved"
        );
    }

    /// The common ordering, which must keep working: the drain inserts first,
    /// then the request path applies the outcome directly.
    #[tokio::test]
    #[ignore = "requires live postgres and redis"]
    async fn the_drain_inserting_first_still_lets_the_request_path_apply_the_outcome() {
        let pg = pg_pool().await;
        let mut redis = redis_conn().await;
        ensure_provider(&pg).await;
        let nonce_hex = unique_nonce();

        insert_reservation(&mut redis, &pg, &stream_fields(&nonce_hex))
            .await
            .expect("the drain insert should succeed");
        assert_eq!(
            status_of(&pg, &nonce_hex).await,
            Some(("reserved".to_string(), None)),
            "with no outcome decided yet the row starts reserved"
        );

        let outcome = ReservationOutcome::Queued {
            upstream_status: 200,
        };
        mark_outcome(&mut redis, &nonce_hex, &outcome, None)
            .await
            .unwrap();
        let nonce = B256::from_str(&nonce_hex).unwrap();
        let rows = apply_outcome_update(&pg, nonce.as_slice(), &outcome, None)
            .await
            .expect("the update should not error");

        let observed = status_of(&pg, &nonce_hex).await;
        cleanup(&pg, &mut redis, &nonce_hex).await;

        assert_eq!(rows, 1, "the row exists, so the request path's UPDATE applies it");
        assert_eq!(observed, Some(("queued".to_string(), Some(200))));
    }

    /// `reserved -> queued -> voided` must be impossible: the transition is
    /// one-way, enforced by `WHERE status = 'reserved'`.
    #[tokio::test]
    #[ignore = "requires live postgres and redis"]
    async fn the_status_transition_is_one_way() {
        let pg = pg_pool().await;
        let mut redis = redis_conn().await;
        ensure_provider(&pg).await;
        let nonce_hex = unique_nonce();

        insert_reservation(&mut redis, &pg, &stream_fields(&nonce_hex))
            .await
            .expect("the drain insert should succeed");
        let nonce = B256::from_str(&nonce_hex).unwrap();

        apply_outcome_update(
            &pg,
            nonce.as_slice(),
            &ReservationOutcome::Queued {
                upstream_status: 200,
            },
            None,
        )
        .await
        .unwrap();

        let rows = apply_outcome_update(
            &pg,
            nonce.as_slice(),
            &ReservationOutcome::Voided {
                upstream_status: Some(500),
            },
            None,
        )
        .await
        .unwrap();

        let observed = status_of(&pg, &nonce_hex).await;
        cleanup(&pg, &mut redis, &nonce_hex).await;

        assert_eq!(rows, 0, "a second transition must match no row");
        assert_eq!(
            observed,
            Some(("queued".to_string(), Some(200))),
            "the first outcome stands"
        );
    }
}

/// A receipt is only worth anything if a third party who has never seen this gateway's
/// database can check it: recover the signer from the body and compare it against the address
/// published at `GET /v1/gateway-key`. These tests are that check, done in-process.
#[cfg(test)]
mod receipt_signature {
    use super::*;
    use alloy::primitives::U256;

    const CHAIN_ID: u64 = 84532;

    fn signer() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::from([0x11; 32]))
            .expect("a fixed non-zero scalar is a valid signing key")
    }

    fn receipt() -> Receipt {
        Receipt {
            nonce: B256::from([0xcd; 32]),
            payer: Address::from([0xa1; 20]),
            capabilityHash: B256::from([0x77; 32]),
            providerSlug: "mock-ok".to_string(),
            amount: U256::from(1000u64),
            upstreamStatus: 200,
            timestamp: 1_786_200_000,
        }
    }

    /// Recovers the address `GET /v1/gateway-key` publishes, which is what makes the receipt
    /// verifiable by someone who trusts nothing here.
    fn recovered(signed: &SignedReceipt) -> Address {
        let hash = signed
            .receipt
            .eip712_signing_hash(&crate::capability::domain(CHAIN_ID));
        alloy::primitives::Signature::from_raw(&signed.signature)
            .expect("a signature this module produced should parse")
            .recover_address_from_prehash(&hash)
            .expect("recovery should succeed")
    }

    #[test]
    fn recovering_the_signature_yields_the_gateway_signing_address() {
        let signer = signer();
        let signed = sign_receipt(&signer, CHAIN_ID, receipt()).expect("signing should succeed");

        assert_eq!(recovered(&signed), signer.address());
    }

    /// The tamper check. Changing the amount after signing must break verification — if it did
    /// not, a receipt would prove nothing about what was actually charged.
    #[test]
    fn altering_the_amount_breaks_verification() {
        let signer = signer();
        let mut signed = sign_receipt(&signer, CHAIN_ID, receipt()).expect("signing should succeed");

        signed.receipt.amount += U256::from(1u64);

        assert_ne!(
            recovered(&signed),
            signer.address(),
            "a tampered amount must not recover to the gateway's address"
        );
    }

    /// The receipt reaches Postgres inside the outcome marker whenever the drain has not
    /// inserted the row yet, so the marker's encoding has to survive a round trip intact — a
    /// truncated signature here would be a receipt the caller holds and the ledger does not.
    #[test]
    fn a_receipt_round_trips_through_the_outcome_marker() {
        let signer = signer();
        let signed = sign_receipt(&signer, CHAIN_ID, receipt()).expect("signing should succeed");
        let outcome = ReservationOutcome::Queued {
            upstream_status: 200,
        };

        let (parsed_outcome, parsed_receipt) =
            ReservationOutcome::from_marker(&outcome.marker_value(Some(signed.stored())))
                .expect("the marker should parse");

        assert_eq!(parsed_outcome, outcome);
        assert_eq!(
            parsed_receipt,
            Some((signed.receipt.timestamp, signed.signature.clone()))
        );
    }

    /// A void signs no receipt, and a marker from before Task 7.1 carries none. Both must
    /// still apply their outcome rather than failing to parse.
    #[test]
    fn a_marker_without_a_receipt_still_parses() {
        let outcome = ReservationOutcome::Voided {
            upstream_status: Some(500),
        };
        let (parsed_outcome, parsed_receipt) =
            ReservationOutcome::from_marker(&outcome.marker_value(None))
                .expect("the marker should parse");

        assert_eq!(parsed_outcome, outcome);
        assert_eq!(parsed_receipt, None);
    }
}

/// The startup replay must terminate even when an entry in the pending list can never be
/// applied. Before the cursor was introduced, `replay_pending` re-read from `"0"` on every
/// iteration and a single poison entry wedged it forever, silently stopping every ledger
/// write for the life of the process.
#[cfg(test)]
mod replay {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    async fn pg_pool() -> PgPool {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/tollgate".to_string());
        PgPool::connect(&url)
            .await
            .expect("postgres should be reachable; start it with ./scripts/dev.sh")
    }

    /// A stream of this consumer group's own, so the shared `tg:reservations` stream and the
    /// other integration tests are untouched.
    fn isolated_stream() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the unix epoch")
            .as_nanos();
        format!("tg:test:replay:{nanos}")
    }

    #[tokio::test]
    #[ignore = "requires a live redis and postgres"]
    async fn a_poison_entry_does_not_wedge_the_startup_replay() {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let client = redis::Client::open(url).expect("redis url should parse");
        let mut redis = client
            .get_connection_manager()
            .await
            .expect("redis should be reachable; start it with ./scripts/dev.sh");
        let pg = pg_pool().await;

        let stream = isolated_stream();

        // Two entries that can never be applied: `nonce` is not hex, so `insert_reservation`
        // fails to parse it and leaves them un-acked, exactly like the real poison cases.
        for i in 0..2 {
            let _: String = redis::cmd("XADD")
                .arg(&stream)
                .arg("*")
                .arg("nonce")
                .arg(format!("not-hex-{i}"))
                .arg("payer")
                .arg("0x00000000000000000000000000000000000000a1")
                .arg("provider")
                .arg("mock-ok")
                .arg("amount")
                .arg("1000")
                .arg("payload")
                .arg("{}")
                .arg("signature")
                .arg("0x1b")
                .arg("cap_hashes")
                .arg("")
                .query_async(&mut redis)
                .await
                .expect("XADD should succeed");
        }

        let _: () = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(&stream)
            .arg(CONSUMER_GROUP)
            .arg("0")
            .arg("MKSTREAM")
            .query_async(&mut redis)
            .await
            .expect("XGROUP CREATE should succeed");

        // Deliver both into this consumer's PEL, un-acked.
        let _: redis::Value = redis::cmd("XREADGROUP")
            .arg("GROUP")
            .arg(CONSUMER_GROUP)
            .arg(CONSUMER_NAME)
            .arg("COUNT")
            .arg(10)
            .arg("STREAMS")
            .arg(&stream)
            .arg(">")
            .query_async(&mut redis)
            .await
            .expect("XREADGROUP should succeed");

        let pending: i64 = redis::cmd("XLEN")
            .arg(&stream)
            .query_async(&mut redis)
            .await
            .unwrap();
        assert_eq!(pending, 2, "both poison entries are in the stream");

        // The assertion is simply that this returns. Under the old re-read-from-zero loop it
        // never did, so the timeout is the test.
        let replayed = tokio::time::timeout(
            Duration::from_secs(10),
            replay_pending(&mut redis, &pg, &stream),
        )
        .await;

        let _: () = redis::cmd("DEL")
            .arg(&stream)
            .query_async(&mut redis)
            .await
            .unwrap_or(());

        assert!(
            replayed.is_ok(),
            "the startup replay must terminate even with an unappliable entry in the PEL"
        );
    }
}
