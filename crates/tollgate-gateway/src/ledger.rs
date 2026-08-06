//! Drains `tg:reservations` into `authorisations` (architecture.md §9.3): Redis
//! is a projection, Postgres is the truth, and this stream is the crash-safe
//! bridge between them. Runs as a background task started at gateway boot.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::{Address, Bytes, B256};
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::Value;
use sqlx::PgPool;

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
}

fn outcome_marker_key(nonce_hex: &str) -> String {
    format!("tg:outcome:{nonce_hex}")
}

/// Writes the small marker `insert_reservation` consults if it inserts this
/// nonce's row after the request path has already decided the outcome — the
/// common case is the drain running first (it just inserts `reserved` and
/// this marker goes unread), but under load the request can finish first.
pub async fn mark_outcome(
    redis: &mut ConnectionManager,
    nonce_hex: &str,
    outcome: &ReservationOutcome,
) -> redis::RedisResult<()> {
    let value = match outcome.upstream_status() {
        Some(code) => format!("{}:{code}", outcome.status_str()),
        None => format!("{}:", outcome.status_str()),
    };
    redis::cmd("SET")
        .arg(outcome_marker_key(nonce_hex))
        .arg(value)
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
pub async fn apply_outcome_update(
    pg: &PgPool,
    nonce: &[u8],
    outcome: &ReservationOutcome,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE authorisations SET status = $1, upstream_status = $2
         WHERE nonce = $3 AND status = 'reserved'",
    )
    .bind(outcome.status_str())
    .bind(outcome.upstream_status())
    .bind(nonce)
    .execute(pg)
    .await?;
    Ok(result.rows_affected())
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

    // A previous run may have XREADGROUP'd entries into this consumer's PEL
    // without acking them (crash, or a failed insert). Replay those before
    // taking anything new, using "0" to read this consumer's own pending list
    // from the start rather than ">" for undelivered entries.
    loop {
        match read_group(&mut redis, "0", None).await {
            Ok(entries) if entries.is_empty() => break,
            Ok(entries) => apply_batch(&mut redis, &pg, entries).await,
            Err(err) => {
                tracing::error!(error = %err, "failed to read pending reservations at startup");
                break;
            }
        }
    }

    loop {
        match read_group(&mut redis, ">", Some(BLOCK_MS)).await {
            Ok(entries) => apply_batch(&mut redis, &pg, entries).await,
            Err(err) => {
                tracing::error!(error = %err, "XREADGROUP failed; retrying");
                tokio::time::sleep(Duration::from_millis(1000)).await;
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
        .arg(RESERVATIONS_KEY)
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
    entries: Vec<(String, HashMap<String, String>)>,
) {
    for (id, fields) in entries {
        match insert_reservation(redis, pg, &fields).await {
            Ok(()) => {
                if let Err(err) = ack(redis, &id).await {
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

async fn ack(redis: &mut ConnectionManager, id: &str) -> redis::RedisResult<()> {
    redis::cmd("XACK")
        .arg(RESERVATIONS_KEY)
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

    // The proxy request path may have already decided this nonce's outcome
    // (2xx/non-2xx/timeout) and left a marker before the drain ever inserted
    // a row for it — under load, the request can finish before the drain
    // catches up. If so, insert the row with that final status directly
    // rather than 'reserved', so it is never observably 'reserved' after
    // the outcome is already known.
    let marker: Option<String> = redis::cmd("GET")
        .arg(outcome_marker_key(nonce_hex))
        .query_async(redis)
        .await
        .map_err(|e| format!("failed to read outcome marker: {e}"))?;

    let (status, upstream_status): (&str, Option<i32>) = match marker.as_deref() {
        Some(marker) => {
            let (status, code) = marker.split_once(':').unwrap_or((marker, ""));
            (status, code.parse::<i32>().ok())
        }
        None => ("reserved", None),
    };

    // The nonce is the idempotency key end to end (architecture.md §9.4): a
    // reservation already landed from an earlier, unacked delivery is not an
    // error. This is also the other half of the outcome-marker race: if the
    // request path's own `apply_outcome_update` already updated this row
    // (the common case, drain usually wins the race to insert first), this
    // INSERT is the one that becomes the no-op instead.
    sqlx::query(
        "INSERT INTO authorisations (nonce, payer, provider_slug, amount_wei, payload, signature, status, upstream_status)
         VALUES ($1, $2, $3, $4::NUMERIC, $5::JSONB, $6, $7, $8)
         ON CONFLICT (nonce) DO NOTHING",
    )
    .bind(nonce.as_slice())
    .bind(payer.as_slice())
    .bind(provider_slug)
    .bind(amount)
    .bind(payload)
    .bind(signature.as_ref())
    .bind(status)
    .bind(upstream_status)
    .execute(pg)
    .await
    .map_err(|e| format!("insert failed: {e}"))?;

    Ok(())
}
