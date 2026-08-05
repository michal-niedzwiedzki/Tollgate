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
        match insert_reservation(pg, &fields).await {
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

async fn insert_reservation(pg: &PgPool, fields: &HashMap<String, String>) -> Result<(), String> {
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

    // The nonce is the idempotency key end to end (architecture.md §9.4): a
    // reservation already landed from an earlier, unacked delivery is not an
    // error.
    sqlx::query(
        "INSERT INTO authorisations (nonce, payer, provider_slug, amount_wei, payload, signature, status)
         VALUES ($1, $2, $3, $4::NUMERIC, $5::JSONB, $6, 'reserved')
         ON CONFLICT (nonce) DO NOTHING",
    )
    .bind(nonce.as_slice())
    .bind(payer.as_slice())
    .bind(provider_slug)
    .bind(amount)
    .bind(payload)
    .bind(signature.as_ref())
    .execute(pg)
    .await
    .map_err(|e| format!("insert failed: {e}"))?;

    Ok(())
}
