//! The expense report. Task 7.2.
//!
//! `prd.md` user story 8: "At the end of a run I get a signed expense report: what each agent and
//! sub-agent spent, on which endpoint, with the transaction hash for every settled charge." This
//! is the `sup.expense_report()` of `architecture.md` §7.3 — one call at the root of a delegation
//! tree that accounts for everything spent anywhere beneath it.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, U256};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tollgate_core::db;
use tollgate_core::error::ErrorBody;
use tollgate_core::types::numeric_to_u256;
use tollgate_core::StoredCapability;

use crate::ledger;
use crate::policy;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ExpenseQuery {
    capability: Option<String>,
    payer: Option<String>,
}

/// Base units to the decimal USDC string the report speaks (`"0.42"`, `"1.00"`, `"0.001"` — the
/// shapes `plan.md` Task 7.2 shows).
///
/// Six decimal places, trailing zeros trimmed, never fewer than two. Exact for USDC, and
/// deterministic — which matters more than it looks, because these strings are inside the bytes
/// the report signature covers.
fn format_usdc(units: U256) -> String {
    let scale = U256::from(1_000_000u64);
    let whole = units / scale;
    let fraction = units % scale;

    let mut decimals = format!("{fraction:06}");
    while decimals.len() > 2 && decimals.ends_with('0') {
        decimals.pop();
    }

    format!("{whole}.{decimals}")
}

fn bad_request(code: &str, message: impl Into<String>) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody::new(code, message.into())),
    )
        .into_response()
}

fn internal_error(message: &str) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody::new("internal_error", message)),
    )
        .into_response()
}

/// One node of the delegation tree, with its children nested beneath it.
///
/// `spent` is this capability's own drawdown, which already includes everything its descendants
/// spent — every charge decrements every level of its chain (architecture.md §5.2), so a
/// supervisor's counter is the whole subtree's total by construction rather than by summing here.
fn build_node(
    capability: &StoredCapability,
    children_by_parent: &HashMap<Vec<u8>, Vec<&StoredCapability>>,
    spend: &HashMap<Vec<u8>, String>,
) -> Result<Value, String> {
    let record = &capability.capability;
    let hash = record.hash.as_slice().to_vec();

    let spent = match spend.get(&hash) {
        Some(total) => numeric_to_u256(total).map_err(|e| e.to_string())?,
        None => U256::ZERO,
    };
    let max_total = record.max_total_wei;

    let children: Vec<Value> = children_by_parent
        .get(&hash)
        .map(|children| {
            children
                .iter()
                .map(|child| build_node(child, children_by_parent, spend))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(json!({
        "hash": record.hash.to_string(),
        "subject": record.subject.to_string(),
        "depth": record.depth,
        "spent": format_usdc(spent),
        "max_total": format_usdc(max_total),
        // Saturating: a capability whose limits were lowered after it had already spent would
        // otherwise underflow. Zero remaining is the honest answer there.
        "remaining": format_usdc(max_total.saturating_sub(spent)),
        // The three the delegation tree's cards render (Task 9.3). All already in hand here, so
        // emitting them costs no extra query — and keeps every figure on one card sourced from
        // the ledger rather than half from Redis (D16).
        //
        // `allowlist` is null when this capability inherits its parent's (`allowlistHash == 0x0`)
        // and `revoked_at` is null unless it has been revoked, so neither is a "no value" that
        // reads as an empty set.
        "allowlist": record.allowlist,
        "expiry": record.expiry,
        "revoked_at": capability.revoked_at,
        "children": children,
    }))
}

/// `GET /v1/expense-report?capability=0x…` — the delegation subtree rooted at that capability,
/// or `?payer=0x…` for a payer-level budget, which has no capabilities at all (NOTES.md D1).
pub async fn expense_report(
    State(state): State<AppState>,
    Query(query): Query<ExpenseQuery>,
) -> axum::response::Response {
    let (root_hash, nodes) = match (&query.capability, &query.payer) {
        (Some(_), Some(_)) => {
            return bad_request(
                "ambiguous_query",
                "give either capability or payer, not both",
            );
        }
        (None, None) => {
            return bad_request(
                "missing_query",
                "one of capability=0x… or payer=0x… is required",
            );
        }
        (Some(capability), None) => {
            let hash = match B256::from_str(capability) {
                Ok(hash) => hash,
                Err(err) => return bad_request("invalid_capability_hash", err.to_string()),
            };

            match db::capability_subtree(&state.pg, hash.as_slice()).await {
                Ok(subtree) if subtree.is_empty() => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(ErrorBody::new(
                            "capability_not_found",
                            "no such capability; it is recorded on first use",
                        )),
                    )
                        .into_response();
                }
                Ok(subtree) => (hash, subtree),
                Err(err) => {
                    tracing::error!(error = %err, "failed to walk the capability subtree");
                    return internal_error("failed to walk the capability subtree");
                }
            }
        }
        (None, Some(payer)) => {
            let payer = match Address::from_str(payer) {
                Ok(payer) => payer,
                Err(err) => return bad_request("invalid_payer", err.to_string()),
            };
            // A payer-level budget lives only in Redis, seeded by POST /v1/budgets — there is no
            // capability row to walk. The report is one synthetic node keyed the same way the
            // claim script keys it, so the two views agree on what was spent.
            let hash = match B256::from_str(&policy::payer_cap_hash(&payer)) {
                Ok(hash) => hash,
                Err(err) => return bad_request("invalid_payer", err.to_string()),
            };
            (hash, Vec::new())
        }
    };

    let hashes: Vec<Vec<u8>> = if nodes.is_empty() {
        vec![root_hash.as_slice().to_vec()]
    } else {
        nodes
            .iter()
            .map(|node| node.capability.hash.as_slice().to_vec())
            .collect()
    };

    let spend = match ledger::spend_by_capabilities(&state.pg, &hashes).await {
        Ok(spend) => spend,
        Err(err) => {
            tracing::error!(error = %err, "failed to aggregate capability spend");
            return internal_error("failed to aggregate capability spend");
        }
    };

    let charges = match ledger::charges_for_capabilities(&state.pg, &hashes).await {
        Ok(charges) => charges,
        Err(err) => {
            tracing::error!(error = %err, "failed to list charges");
            return internal_error("failed to list charges");
        }
    };

    // The tree. Children are grouped by parent so each node is emitted once, under the parent
    // that granted it; the root of the requested subtree is whatever was asked for, whose own
    // parent is outside this report.
    let mut children_by_parent: HashMap<Vec<u8>, Vec<&StoredCapability>> = HashMap::new();
    for node in &nodes {
        if let Some(parent) = node.capability.parent_hash
            && parent != root_hash
        {
            children_by_parent
                .entry(parent.as_slice().to_vec())
                .or_default()
                .push(node);
        } else if node.capability.hash != root_hash {
            children_by_parent
                .entry(root_hash.as_slice().to_vec())
                .or_default()
                .push(node);
        }
    }

    let node_values = if let Some(root) = nodes
        .iter()
        .find(|node| node.capability.hash == root_hash)
    {
        match build_node(root, &children_by_parent, &spend) {
            Ok(node) => vec![node],
            Err(err) => {
                tracing::error!(error = %err, "failed to build the delegation tree");
                return internal_error("failed to build the delegation tree");
            }
        }
    } else {
        // Payer-level: `max_total` has no ledger row, so it comes from the Redis meta the claim
        // script enforces against. `spent` still comes from the ledger, like every other node.
        let mut redis = state.redis.clone();
        let (max_total, _) = policy::read_level_state(&mut redis, &root_hash.to_string())
            .await
            .unwrap_or((0, 0));
        let max_total = U256::from(max_total);
        let spent = match spend.get(root_hash.as_slice()) {
            Some(total) => match numeric_to_u256(total) {
                Ok(total) => total,
                Err(err) => {
                    tracing::error!(error = %err, "failed to parse payer spend");
                    return internal_error("failed to parse payer spend");
                }
            },
            None => U256::ZERO,
        };
        let payer = query.payer.clone().unwrap_or_default();

        vec![json!({
            "hash": root_hash.to_string(),
            "subject": payer,
            "depth": 0,
            "spent": format_usdc(spent),
            "max_total": format_usdc(max_total),
            "remaining": format_usdc(max_total.saturating_sub(spent)),
            // Null rather than absent, so a payer-level node has the same shape as a capability
            // one and the tree needs no second case. A payer budget is seeded by
            // `POST /v1/budgets` and has no `capabilities` row (D1), so it genuinely has no
            // allowlist, no expiry, and nothing that could revoke it.
            "allowlist": Value::Null,
            "expiry": Value::Null,
            "revoked_at": Value::Null,
            "children": [],
        })]
    };

    let mut total_spent = U256::ZERO;
    let mut failed_count = 0u64;
    let mut charge_values = Vec::with_capacity(charges.len());
    for charge in &charges {
        let amount = match numeric_to_u256(&charge.amount_wei) {
            Ok(amount) => amount,
            Err(err) => {
                tracing::error!(error = %err, "failed to parse a charge amount");
                return internal_error("failed to parse a charge amount");
            }
        };
        total_spent += amount;
        if charge.status == "failed" {
            failed_count += 1;
        }

        charge_values.push(json!({
            "nonce": alloy::hex::encode_prefixed(&charge.nonce),
            "provider": charge.provider_slug,
            "amount": format_usdc(amount),
            "upstream_status": charge.upstream_status,
            "status": charge.status,
            "tx_hash": charge.tx_hash.as_deref().map(alloy::hex::encode_prefixed),
            "settled_at": charge.settled_at,
            "receipt_sig": charge.receipt_sig.as_deref().map(alloy::hex::encode_prefixed),
        }));
    }

    // The signed body. `generated_at` and `signature` are added afterwards, because neither can
    // be inside its own digest — see `ledger::expense_report_body_hash` for the recipe a
    // verifier follows.
    let body = json!({
        "root": root_hash.to_string(),
        "total_spent": format_usdc(total_spent),
        "failed_count": failed_count,
        "nodes": node_values,
        "charges": charge_values,
    });

    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the unix epoch")
        .as_secs();

    let body_hash = ledger::expense_report_body_hash(&body);
    let signature = match ledger::sign_expense_report(
        &state.receipt_signer,
        state.cfg.chain_id,
        body_hash,
        generated_at,
    ) {
        Ok(signature) => signature,
        Err(err) => {
            tracing::error!(error = %err, "failed to sign the expense report");
            return internal_error("failed to sign the expense report");
        }
    };

    let Value::Object(mut report) = body else {
        return internal_error("expense report body was not a json object");
    };
    report.insert("generated_at".to_string(), json!(generated_at));
    report.insert(
        "signature".to_string(),
        json!(alloy::hex::encode_prefixed(&signature)),
    );

    (StatusCode::OK, Json(Value::Object(Map::from_iter(report)))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three shapes `plan.md` Task 7.2's example response shows, which is what fixes the
    /// trim-to-at-least-two-decimals rule.
    #[test]
    fn format_usdc_matches_the_shapes_the_task_specifies() {
        assert_eq!(format_usdc(U256::from(420_000u64)), "0.42");
        assert_eq!(format_usdc(U256::from(1_000_000u64)), "1.00");
        assert_eq!(format_usdc(U256::from(1_000u64)), "0.001");
    }

    #[test]
    fn format_usdc_keeps_full_precision_and_handles_zero() {
        assert_eq!(format_usdc(U256::ZERO), "0.00");
        // One base unit is the smallest charge USDC can express; it must not round away.
        assert_eq!(format_usdc(U256::from(1u64)), "0.000001");
        assert_eq!(format_usdc(U256::from(1_234_567u64)), "1.234567");
    }

    /// The signature covers `keccak256` of the serialised body, so a verifier in another
    /// language has to reproduce these bytes exactly. Sorted keys and compact separators are
    /// what make that possible — this pins both.
    #[test]
    fn the_signed_body_serialises_canonically() {
        let body = json!({"total_spent": "0.006", "root": "0x01", "failed_count": 0});
        assert_eq!(
            body.to_string(),
            r#"{"failed_count":0,"root":"0x01","total_spent":"0.006"}"#,
            "keys must serialise sorted and compact, matching python's \
             json.dumps(sort_keys=True, separators=(',', ':'))"
        );

        // Built in a different order, the same report must hash the same.
        let reordered = json!({"root": "0x01", "failed_count": 0, "total_spent": "0.006"});
        assert_eq!(
            ledger::expense_report_body_hash(&body),
            ledger::expense_report_body_hash(&reordered)
        );
    }
}
