use std::str::FromStr;

use alloy::primitives::{Address, U256};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tollgate_core::db;
use tollgate_core::error::ErrorBody;
use tollgate_core::types::{Provider, Scheme};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateProviderRequest {
    slug: String,
    upstream_url: String,
    price: String,
    payout_address: String,
    scheme: Option<String>,
    timeout_ms: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct ProviderResponse {
    slug: String,
    upstream_url: String,
    price_wei: String,
    max_price_wei: Option<String>,
    scheme: String,
    payout_address: String,
    timeout_ms: i32,
}

impl From<Provider> for ProviderResponse {
    fn from(provider: Provider) -> Self {
        ProviderResponse {
            slug: provider.slug,
            upstream_url: provider.upstream_url,
            price_wei: provider.price_wei.to_string(),
            max_price_wei: provider.max_price_wei.map(|v| v.to_string()),
            scheme: provider.scheme.as_str().to_string(),
            payout_address: provider.payout_address.to_string(),
            timeout_ms: provider.timeout_ms,
        }
    }
}

/// Parses a decimal USDC string (e.g. `"0.001"`) into base units (6 decimals).
fn parse_price_wei(price: &str) -> std::result::Result<U256, String> {
    let (integer_part, fractional_part) = match price.split_once('.') {
        Some((int, frac)) => (int, frac),
        None => (price, ""),
    };

    if fractional_part.len() > 6 {
        return Err("price supports at most 6 decimal places".to_string());
    }
    if integer_part.is_empty()
        || !integer_part.chars().all(|c| c.is_ascii_digit())
        || !fractional_part.chars().all(|c| c.is_ascii_digit())
    {
        return Err("price must be a non-negative decimal number".to_string());
    }

    let mut digits = String::with_capacity(integer_part.len() + 6);
    digits.push_str(integer_part);
    digits.push_str(fractional_part);
    for _ in fractional_part.len()..6 {
        digits.push('0');
    }

    let value =
        U256::from_str_radix(&digits, 10).map_err(|_| "price is not a valid number".to_string())?;
    if value.is_zero() {
        return Err("price must be positive".to_string());
    }
    Ok(value)
}

pub async fn create_provider(
    State(state): State<AppState>,
    Json(body): Json<CreateProviderRequest>,
) -> axum::response::Response {
    let price_wei = match parse_price_wei(&body.price) {
        Ok(v) => v,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody::new("invalid_price", message)),
            )
                .into_response();
        }
    };

    let payout_address = match Address::from_str(&body.payout_address) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody::new("invalid_address", e.to_string())),
            )
                .into_response();
        }
    };

    let scheme = match Scheme::parse(body.scheme.as_deref().unwrap_or("exact")) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody::new("invalid_scheme", e.to_string())),
            )
                .into_response();
        }
    };

    let provider = Provider {
        slug: body.slug,
        upstream_url: body.upstream_url,
        price_wei,
        max_price_wei: None,
        scheme,
        payout_address,
        timeout_ms: body.timeout_ms.unwrap_or(30_000),
    };

    match db::insert_provider(&state.pg, &provider).await {
        Ok(()) => (StatusCode::CREATED, Json(ProviderResponse::from(provider))).into_response(),
        Err(tollgate_core::Error::Database(sqlx::Error::Database(db_err)))
            if db_err.code().as_deref() == Some("23505") =>
        {
            (
                StatusCode::CONFLICT,
                Json(ErrorBody::new(
                    "duplicate_slug",
                    "a provider with this slug already exists",
                )),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody::new("internal_error", e.to_string())),
        )
            .into_response(),
    }
}

pub async fn get_provider(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> axum::response::Response {
    match db::get_provider(&state.pg, &slug).await {
        Ok(Some(provider)) => {
            (StatusCode::OK, Json(ProviderResponse::from(provider))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody::new("not_found", "provider not found")),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody::new("internal_error", e.to_string())),
        )
            .into_response(),
    }
}

pub async fn list_providers(State(state): State<AppState>) -> axum::response::Response {
    match db::list_providers(&state.pg).await {
        Ok(providers) => (
            StatusCode::OK,
            Json(
                providers
                    .into_iter()
                    .map(ProviderResponse::from)
                    .collect::<Vec<_>>(),
            ),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody::new("internal_error", e.to_string())),
        )
            .into_response(),
    }
}
