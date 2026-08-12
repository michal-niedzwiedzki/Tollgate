//! Batch selection out of the Postgres ledger, and the status write-back afterwards.

use alloy::primitives::{B256, keccak256};
use anyhow::{Context, Result};
use sqlx::{PgPool, Row};

/// One queued authorisation, as the settler needs it.
#[derive(Debug, Clone)]
pub struct QueuedAuth {
    pub nonce: Vec<u8>,
    /// The full EIP-3009 payload the gateway persisted, verbatim.
    pub payload: serde_json::Value,
    /// The payment signature, 65 bytes of `r || s || v`.
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Batch {
    pub id: B256,
    pub items: Vec<QueuedAuth>,
}

/// Deterministic batch id: keccak256 over the sorted nonce set.
///
/// Sorted, so the id depends on which charges are in the batch and not on the order the rows
/// happened to come back in. A resubmission of the same set therefore carries the same id and is
/// recognisable as a duplicate rather than looking like new work.
pub fn batch_id(nonces: &[Vec<u8>]) -> B256 {
    let mut sorted: Vec<&Vec<u8>> = nonces.iter().collect();
    sorted.sort();
    let mut buf = Vec::with_capacity(sorted.len() * 32);
    for nonce in sorted {
        buf.extend_from_slice(nonce);
    }
    keccak256(buf)
}

/// Claims up to `limit` queued authorisations and stamps them with their batch id.
///
/// `status = 'queued'` is the only status this reads. A `reserved` row — one whose upstream call
/// has not yet returned 2xx — is invisible to the settler by construction, which is what closes
/// the v1 race where a flush could settle a charge the request handler was about to void
/// (architecture.md §7.2).
///
/// `FOR UPDATE SKIP LOCKED` plus stamping the batch id inside the same transaction as the SELECT
/// means two settlers can never claim the same row.
pub async fn claim_batch(pool: &PgPool, limit: i64) -> Result<Option<Batch>> {
    let mut tx = pool.begin().await.context("begin batch transaction")?;

    let rows = sqlx::query(
        "SELECT nonce, payload, signature
           FROM authorisations
          WHERE status = 'queued'
          ORDER BY created_at
          LIMIT $1
            FOR UPDATE SKIP LOCKED",
    )
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .context("select queued authorisations")?;

    if rows.is_empty() {
        tx.rollback().await.ok();
        return Ok(None);
    }

    let items: Vec<QueuedAuth> = rows
        .into_iter()
        .map(|row| QueuedAuth {
            nonce: row.get("nonce"),
            payload: row.get("payload"),
            signature: row.get("signature"),
        })
        .collect();

    let nonces: Vec<Vec<u8>> = items.iter().map(|item| item.nonce.clone()).collect();
    let id = batch_id(&nonces);

    sqlx::query("UPDATE authorisations SET batch_id = $1 WHERE nonce = ANY($2)")
        .bind(id.as_slice())
        .bind(&nonces)
        .execute(&mut *tx)
        .await
        .context("stamp batch id")?;

    tx.commit().await.context("commit batch claim")?;

    Ok(Some(Batch { id, items }))
}

/// Marks the nonces the chain reported as `Settled`.
///
/// `WHERE status = 'queued'` keeps the transition one-way, the same guard the gateway's promotion
/// path uses.
///
/// `gas_used` is the whole transaction's gas, repeated across every row of its batch, which is
/// what lets `/v1/stats` divide it by the batch to get gas per charge (Task 7.3). `None` when no
/// receipt was seen — the ambiguous-timeout path confirms a charge through `authorizationState`
/// rather than through a receipt, so there is no gas figure to record and NULL says so.
pub async fn mark_settled(
    pool: &PgPool,
    nonces: &[Vec<u8>],
    tx_hash: &[u8],
    gas_used: Option<i64>,
) -> Result<u64> {
    if nonces.is_empty() {
        return Ok(0);
    }

    let result = sqlx::query(
        "UPDATE authorisations
            SET status = 'settled', settled_at = now(), tx_hash = $1, gas_used = $3
          WHERE nonce = ANY($2) AND status = 'queued'",
    )
    .bind(tx_hash)
    .bind(nonces)
    .bind(gas_used)
    .execute(pool)
    .await
    .context("mark settled")?;

    Ok(result.rows_affected())
}

/// How many times a refused item is retried before it is given up on and alerted.
pub const MAX_RETRIES: i32 = 3;

/// What happened to one refused item after its retry counter was incremented.
#[derive(Debug, Clone)]
pub struct FailureOutcome {
    pub retry_count: i32,
    /// True once the item has exhausted `MAX_RETRIES` and has been parked as `failed`.
    pub exhausted: bool,
}

/// Requeues refused items individually, one retry at a time.
///
/// Each item is counted on its own — the other items in the batch are not touched, which is the
/// whole point of the contract's skip-and-continue behaviour. On the third refusal the row moves
/// to `failed` and the caller raises the alert.
///
/// `WHERE status = 'queued'` guards the transition, so an item that settled through some other
/// path in the meantime is never dragged backwards.
pub async fn record_failure(pool: &PgPool, nonce: &[u8]) -> Result<Option<FailureOutcome>> {
    let row = sqlx::query(
        "UPDATE authorisations
            SET retry_count = retry_count + 1,
                status = CASE WHEN retry_count + 1 >= $2 THEN 'failed' ELSE 'queued' END
          WHERE nonce = $1 AND status = 'queued'
      RETURNING retry_count, status",
    )
    .bind(nonce)
    .bind(MAX_RETRIES)
    .fetch_optional(pool)
    .await
    .context("record settlement failure")?;

    Ok(row.map(|row| {
        let status: String = row.get("status");
        FailureOutcome {
            retry_count: row.get("retry_count"),
            exhausted: status == "failed",
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_id_is_independent_of_row_order() {
        let a = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
        let b = vec![vec![3u8; 32], vec![1u8; 32], vec![2u8; 32]];
        assert_eq!(batch_id(&a), batch_id(&b), "same set, same id");
    }

    #[test]
    fn batch_id_changes_with_the_nonce_set() {
        let a = vec![vec![1u8; 32], vec![2u8; 32]];
        let b = vec![vec![1u8; 32], vec![9u8; 32]];
        assert_ne!(batch_id(&a), batch_id(&b));
    }
}
