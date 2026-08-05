use std::str::FromStr;

use alloy::primitives::{keccak256, Address};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tollgate_core::error::ErrorBody;

use crate::policy;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct SeedBudgetRequest {
    payer: String,
    max_total: String,
    max_per_request: String,
}

#[derive(Debug, Serialize)]
pub struct SeedBudgetResponse {
    cap_hash: String,
    max_total_wei: String,
    max_per_request_wei: String,
}

/// Parses a decimal USDC string (e.g. `"1.00"`) into base units (6 decimals).
/// Mirrors `routes::providers::parse_price_wei`, kept local because this
/// endpoint is Phase 3's single-level stand-in: Phase 5 replaces its only
/// caller with real capability meta upserts (Task 5.4), and this parser goes
/// with it.
fn parse_decimal_usdc(value: &str) -> Result<u128, String> {
    let (integer_part, fractional_part) = match value.split_once('.') {
        Some((int, frac)) => (int, frac),
        None => (value, ""),
    };

    if fractional_part.len() > 6 {
        return Err("amount supports at most 6 decimal places".to_string());
    }
    if integer_part.is_empty()
        || !integer_part.chars().all(|c| c.is_ascii_digit())
        || !fractional_part.chars().all(|c| c.is_ascii_digit())
    {
        return Err("amount must be a non-negative decimal number".to_string());
    }

    let mut digits = String::with_capacity(integer_part.len() + 6);
    digits.push_str(integer_part);
    digits.push_str(fractional_part);
    for _ in fractional_part.len()..6 {
        digits.push('0');
    }

    digits
        .parse::<u128>()
        .map_err(|_| "amount is not a valid number".to_string())
}

/// `POST /v1/budgets` — a dev endpoint seeding a payer-level budget. This is
/// Phase 3's single-level stand-in for a capability chain: Phase 5 replaces the
/// source of `tg:cap:*:meta` with a verified capability (Task 5.4), keeping the
/// key shape this endpoint writes today.
pub async fn seed_budget(
    State(state): State<AppState>,
    Json(body): Json<SeedBudgetRequest>,
) -> axum::response::Response {
    let payer = match Address::from_str(&body.payer) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody::new("invalid_address", e.to_string())),
            )
                .into_response();
        }
    };

    let max_total = match parse_decimal_usdc(&body.max_total) {
        Ok(v) => v,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody::new("invalid_amount", message)),
            )
                .into_response();
        }
    };

    let max_per_request = match parse_decimal_usdc(&body.max_per_request) {
        Ok(v) => v,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody::new("invalid_amount", message)),
            )
                .into_response();
        }
    };

    let cap_hash = keccak256(payer.as_slice()).to_string();

    let mut redis = state.redis.clone();
    if let Err(e) = policy::seed_cap_meta(&mut redis, &cap_hash, max_total, max_per_request).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody::new("internal_error", e.to_string())),
        )
            .into_response();
    }

    (
        StatusCode::CREATED,
        Json(SeedBudgetResponse {
            cap_hash,
            max_total_wei: max_total.to_string(),
            max_per_request_wei: max_per_request.to_string(),
        }),
    )
        .into_response()
}
