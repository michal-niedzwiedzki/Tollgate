use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use tollgate_core::db;
use tollgate_core::error::ErrorBody;

use crate::state::AppState;
use crate::x402;

/// `ANY /v1/proxy/{provider_slug}/{*path}`. Verification-only for now: an unpaid request gets a
/// spec-shaped 402; payment handling lands in later Phase 2 tasks.
pub async fn handle_proxy_request(
    State(state): State<AppState>,
    Path((provider_slug, _path)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> axum::response::Response {
    let provider = match db::get_provider(&state.pg, &provider_slug).await {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            let body = ErrorBody::new("provider_not_found", "unknown provider slug");
            return (StatusCode::NOT_FOUND, Json(body)).into_response();
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to look up provider");
            let body = ErrorBody::new("internal_error", "failed to look up provider");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response();
        }
    };

    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let resource = format!("http://{host}{}", uri.path());
    let network = x402::caip2_network(state.cfg.chain_id);
    let body = x402::payment_required_body(
        &provider,
        &state.cfg.usdc_address,
        &network,
        &resource,
        state.cfg.quote_validity_seconds,
        "payment required",
    );

    (StatusCode::PAYMENT_REQUIRED, Json(body)).into_response()
}
