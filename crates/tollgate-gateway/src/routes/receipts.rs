//! Receipt lookup and the gateway's public signing address. Task 7.1.
//!
//! prd.md F6 and user story 8: "a signed expense report: what each agent and sub-agent spent, on
//! which endpoint, with the transaction hash for every settled charge". The chain shows a USDC
//! transfer and nothing else — not the endpoint, not the sub-agent, not whether the upstream
//! returned 200. These two endpoints are what make a charge checkable by someone who trusts
//! neither the payer nor this gateway's database.

use std::str::FromStr;

use alloy::primitives::B256;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use tollgate_core::error::ErrorBody;

use crate::capability::{CAPABILITY_EIP712_NAME, CAPABILITY_EIP712_VERSION};
use crate::ledger::{self, ReceiptLookup};
use crate::state::AppState;

/// `GET /v1/receipts/{nonce}` — the signed receipt for a charge, plus its settlement
/// transaction hash once the settler has landed the batch (NULL before that).
///
/// The body returned is reconstructed from the row's own columns, so it is exactly the body the
/// signature covers. Anything else would be a signature a caller cannot check.
pub async fn get_receipt(
    State(state): State<AppState>,
    Path(nonce): Path<String>,
) -> axum::response::Response {
    let nonce = match B256::from_str(&nonce) {
        Ok(nonce) => nonce,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody::new("invalid_nonce", err.to_string())),
            )
                .into_response();
        }
    };

    match ledger::fetch_receipt(&state.pg, nonce).await {
        Ok(ReceiptLookup::Issued { receipt, tx_hash }) => {
            let mut body = receipt.to_json();
            body["tx_hash"] = match tx_hash {
                Some(hash) => serde_json::json!(hash.to_string()),
                None => serde_json::Value::Null,
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        // A receipt is signed at promotion and only at promotion, so its absence is
        // information: this charge was voided on an upstream failure, or it is still in
        // flight. Saying which beats a bare 404.
        Ok(ReceiptLookup::NotIssued { status }) => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody::new(
                "receipt_not_issued",
                format!("no receipt: this charge is '{status}', not a completed 2xx charge"),
            )),
        )
            .into_response(),
        Ok(ReceiptLookup::UnknownNonce) => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody::new(
                "receipt_not_found",
                "no charge with this nonce; note the ledger write is asynchronous, so a \
                 receipt handed back in an X-Tollgate-Receipt header may land here a moment later",
            )),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to look up receipt");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new("internal_error", "failed to look up receipt")),
            )
                .into_response()
        }
    }
}

/// `GET /v1/gateway-key` — the address that signs receipts, so anyone can verify one.
///
/// The EIP-712 domain ships alongside it because an address on its own is not enough to check a
/// signature: a verifier has to rebuild the same domain separator, and `chainId` is what stops a
/// receipt for one chain being replayed as a receipt for another (architecture.md §10).
pub async fn gateway_key(State(state): State<AppState>) -> axum::response::Response {
    Json(serde_json::json!({
        "address": state.receipt_signer.address().to_string(),
        "domain": {
            "name": CAPABILITY_EIP712_NAME,
            "version": CAPABILITY_EIP712_VERSION,
            "chainId": state.cfg.chain_id,
        },
    }))
    .into_response()
}
