use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Json};
use tollgate_core::db;
use tollgate_core::error::ErrorBody;

use tollgate_core::metrics::StageTimer;

use crate::state::AppState;
use crate::verify::recover_payer;
use crate::x402;
use crate::x402::decode::decode_payment_header;
use crate::x402::validate::validate_fields;

const X_PAYMENT: HeaderName = HeaderName::from_static("x-payment");

/// `ANY /v1/proxy/{provider_slug}/{*path}`. An unpaid request gets a spec-shaped 402. A request
/// with an `X-PAYMENT` header that fails cheap field validation or signature recovery also gets
/// a 402, naming the reason. A fully verified payment gets a debug 200 for now; the real proxy
/// lands in Phase 4.
pub async fn handle_proxy_request(
    State(state): State<AppState>,
    Path((provider_slug, _path)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> axum::response::Response {
    let _total_timer = StageTimer::start("total");

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

    let payment_required = |error: String| {
        let body = x402::payment_required_body(
            &provider,
            &state.cfg.usdc_address,
            &network,
            &resource,
            state.cfg.quote_validity_seconds,
            error,
        );
        (StatusCode::PAYMENT_REQUIRED, Json(body)).into_response()
    };

    let Some(payment_header) = headers.get(X_PAYMENT).and_then(|v| v.to_str().ok()) else {
        return payment_required("payment required".to_string());
    };

    let payload = {
        let _timer = StageTimer::start("decode");
        match decode_payment_header(payment_header) {
            Ok(payload) => payload,
            Err(err) => return payment_required(err.to_string()),
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the unix epoch")
        .as_secs();

    if let Err(reason) = validate_fields(&payload, &provider, &state.cfg, now) {
        return payment_required(reason.reason().to_string());
    }

    let payer = {
        let _timer = StageTimer::start("recover");
        match recover_payer(&payload, &state.cfg) {
            Ok(payer) => payer,
            Err(err) => return payment_required(err.to_string()),
        }
    };

    Json(serde_json::json!({
        "payer": payer.to_string(),
        "amount": payload.payload.authorization.value.to_string(),
        "provider": provider.slug,
    }))
    .into_response()
}
