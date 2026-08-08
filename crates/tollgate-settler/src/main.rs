//! Tollgate settler: drains queued authorisations into batched on-chain settlement.
//!
//! A separate binary and a separate process from the gateway, deliberately. Nothing here is on
//! the request path — the gateway has already returned the upstream's response to the caller by
//! the time a row becomes visible to this loop (architecture.md §1, §7.2).

mod batch;
mod chain;

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tollgate_core::config::Config;
use tollgate_core::db;
use tracing::{error, info, warn};

/// Renders a `SettleFailed` reason for the log. USDC's failures are ABI-encoded `Error(string)`,
/// so the readable message is what an operator actually needs; anything else falls back to hex.
fn decode_revert(reason: &[u8]) -> String {
    const ERROR_SELECTOR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];

    if reason.len() > 4
        && reason[..4] == ERROR_SELECTOR
        && let Some(message) = decode_error_string(&reason[4..])
    {
        return message;
    }
    alloy::hex::encode_prefixed(reason)
}

/// Decodes the ABI encoding of `Error(string)`'s argument: a 32-byte offset, then a 32-byte
/// length, then the bytes. Done by hand because it is six lines and leaves nothing to infer about
/// which of the ABI codec's tuple-versus-params conventions applies.
fn decode_error_string(data: &[u8]) -> Option<String> {
    let word = |at: usize| -> Option<usize> {
        let bytes = data.get(at..at + 32)?;
        // Only the low 8 bytes can be a sane offset or length here.
        if bytes[..24].iter().any(|b| *b != 0) {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[24..32]);
        Some(u64::from_be_bytes(buf) as usize)
    };

    let offset = word(0)?;
    let length = word(offset)?;
    let start = offset.checked_add(32)?;
    let bytes = data.get(start..start.checked_add(length)?)?;

    Some(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod revert {
    use super::*;

    /// The exact bytes USDC emitted for a spent nonce, captured from a live settlement run.
    const SPENT_NONCE: &str = "08c379a0\
0000000000000000000000000000000000000000000000000000000000000020\
000000000000000000000000000000000000000000000000000000000000002e\
46696174546f6b656e56323a20617574686f72697a6174696f6e2069732075736564206f722063616e63656c6564\
000000000000000000000000000000000000";

    #[test]
    fn decodes_the_revert_string_usdc_actually_returns() {
        let reason = alloy::hex::decode(SPENT_NONCE).unwrap();
        assert_eq!(
            decode_revert(&reason),
            "FiatTokenV2: authorization is used or canceled"
        );
    }

    #[test]
    fn falls_back_to_hex_for_a_non_string_revert() {
        assert_eq!(decode_revert(&[0xde, 0xad, 0xbe, 0xef]), "0xdeadbeef");
    }

    #[test]
    fn a_truncated_error_payload_does_not_panic() {
        let mut reason = vec![0x08, 0xc3, 0x79, 0xa0];
        reason.extend_from_slice(&[0u8; 16]);
        assert!(decode_revert(&reason).starts_with("0x"));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tollgate_settler=info".into()),
        )
        .init();

    let cfg = Config::from_env().context("load configuration")?;
    let pool = db::pg_pool(&cfg).await.context("connect to postgres")?;
    let settler = chain::connect(&cfg)?;

    let batch_size = i64::from(cfg.settler_batch_size);
    let flush_interval = Duration::from_secs(cfg.settler_flush_seconds);

    info!(
        batch_size,
        flush_seconds = cfg.settler_flush_seconds,
        rpc = %cfg.rpc_url,
        batch_settler = %cfg.batch_settler_address,
        "settler started"
    );

    // Flush at `batch_size` authorisations or `flush_seconds`, whichever comes first: poll often
    // enough to notice a full batch quickly, but only submit a partial one once the flush
    // interval has actually elapsed.
    let poll_interval = Duration::from_secs(1).min(flush_interval);
    let mut last_flush = Instant::now();

    loop {
        match batch::claim_batch(&pool, batch_size).await {
            Ok(Some(claimed)) => {
                let full = claimed.items.len() as i64 >= batch_size;
                if !full && last_flush.elapsed() < flush_interval {
                    // Partial batch, and the timer has not expired. The rows keep their batch id
                    // and stay queued; the next pass picks them up again, by which point they may
                    // have company.
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }

                let count = claimed.items.len();
                info!(count, batch_id = %claimed.id, "submitting batch");

                match settler.submit(&claimed.items).await {
                    Ok(outcome) => {
                        let updated = batch::mark_settled(
                            &pool,
                            &outcome.settled,
                            outcome.tx_hash.as_slice(),
                        )
                        .await?;

                        info!(
                            batch_id = %claimed.id,
                            tx_hash = %outcome.tx_hash,
                            submitted = count,
                            settled = outcome.settled.len(),
                            failed = outcome.failed.len(),
                            rows_updated = updated,
                            "batch settled"
                        );

                        // Each refused item requeues on its own with its own counter. The others
                        // in the batch are untouched — that is what the contract's
                        // skip-and-continue behaviour buys.
                        for (nonce, reason) in &outcome.failed {
                            let hex = alloy::hex::encode_prefixed(nonce);
                            match batch::record_failure(&pool, nonce).await? {
                                Some(failure) if failure.exhausted => {
                                    // The alert, per architecture.md §4.3.
                                    error!(
                                        nonce = %hex,
                                        retry_count = failure.retry_count,
                                        reason = %decode_revert(reason),
                                        "settlement item failed permanently and will not be retried"
                                    );
                                }
                                Some(failure) => {
                                    warn!(
                                        nonce = %hex,
                                        retry_count = failure.retry_count,
                                        reason = %decode_revert(reason),
                                        "settlement item refused, requeued"
                                    );
                                }
                                None => {
                                    warn!(nonce = %hex, "refused item was no longer queued");
                                }
                            }
                        }
                    }
                    Err(chain::SubmitError::Ambiguous { tx_hash }) => {
                        // Never blind-retry. Ask the token whether the nonces were spent
                        // (architecture.md §7.2).
                        warn!(
                            batch_id = %claimed.id,
                            tx_hash = %tx_hash,
                            "no receipt within the deadline; resolving against authorizationState"
                        );

                        match chain::classify_ambiguous(&settler, &claimed.items).await {
                            Ok(verdict) => {
                                let updated = batch::mark_settled(
                                    &pool,
                                    &verdict.settled,
                                    tx_hash.as_slice(),
                                )
                                .await?;
                                info!(
                                    batch_id = %claimed.id,
                                    tx_hash = %tx_hash,
                                    already_settled = verdict.settled.len(),
                                    unresolved = verdict.unresolved.len(),
                                    rows_updated = updated,
                                    "ambiguous batch resolved on-chain"
                                );
                            }
                            Err(err) => {
                                error!(
                                    batch_id = %claimed.id,
                                    error = ?err,
                                    "could not resolve an ambiguous batch; leaving it queued"
                                );
                            }
                        }
                    }
                    Err(chain::SubmitError::NotSent(err)) => {
                        error!(batch_id = %claimed.id, error = ?err, "batch was not submitted");
                    }
                }

                last_flush = Instant::now();
            }
            Ok(None) => {
                last_flush = Instant::now();
                tokio::time::sleep(poll_interval).await;
            }
            Err(err) => {
                error!(error = ?err, "could not claim a batch");
                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}
