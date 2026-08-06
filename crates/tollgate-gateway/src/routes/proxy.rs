use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, OriginalUri, Path, State};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode};
use axum::response::{IntoResponse, Json};
use tollgate_core::db;
use tollgate_core::error::ErrorBody;
use tollgate_core::Provider;

use tollgate_core::metrics::StageTimer;

use crate::policy::{self, CapLevel, ClaimOutcome, ClaimRequest};
use crate::proxy;
use crate::state::AppState;
use crate::verify::recover_payer;
use crate::x402;
use crate::x402::decode::decode_payment_header;
use crate::x402::validate::validate_fields;

const X_PAYMENT: HeaderName = HeaderName::from_static("x-payment");

/// `ANY /v1/proxy/{provider_slug}/{*path}`. An unpaid request gets a spec-shaped 402. A request
/// with an `X-PAYMENT` header that fails cheap field validation or signature recovery also gets
/// a 402, naming the reason. A fully verified payment proxies to the upstream and streams its
/// response back.
pub async fn handle_proxy_request(
    State(state): State<AppState>,
    Path((provider_slug, path)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Body,
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

    let auth = &payload.payload.authorization;

    // architecture.md §9.2 rule 2: never a constant TTL. validate_fields step 1
    // (above) already rejected a valid_before at or before now + clock_skew, so
    // this should always succeed; if it doesn't, something upstream broke that
    // invariant and we fail closed rather than claim with a fabricated TTL.
    let ttl_secs = match policy::nonce_ttl_secs(auth.valid_before, now, state.cfg.clock_skew_seconds)
    {
        Ok(secs) => secs,
        Err(err) => return payment_required(err.to_string()),
    };

    let amount: u128 = match u128::try_from(auth.value) {
        Ok(v) => v,
        Err(_) => return payment_required("amount exceeds the supported range".to_string()),
    };

    let nonce_hex = auth.nonce.to_string();
    let signature_hex = payload.payload.signature.to_string();
    let payer_hex = payer.to_string();
    let cap_hash = policy::payer_cap_hash(&payer);

    // Reconstructed rather than kept as raw wire bytes: every field the Phase 6
    // settler needs (from, to, value, validAfter, validBefore, nonce, signature)
    // is already decoded and verified above, so this is exactly equivalent to
    // what the client sent, just re-serialised.
    let payload_json = serde_json::json!({
        "x402Version": payload.x402_version,
        "scheme": payload.scheme,
        "network": payload.network,
        "payload": {
            "signature": signature_hex,
            "authorization": {
                "from": auth.from.to_string(),
                "to": auth.to.to_string(),
                "value": auth.value.to_string(),
                "validAfter": auth.valid_after.to_string(),
                "validBefore": auth.valid_before.to_string(),
                "nonce": nonce_hex,
            },
        },
    })
    .to_string();

    let claim_request = ClaimRequest {
        nonce: &nonce_hex,
        amount,
        levels: vec![CapLevel { cap_hash }],
        provider_slug: &provider.slug,
        payer: &payer_hex,
        ttl_secs,
        payload_json: &payload_json,
        signature_hex: &signature_hex,
    };

    let outcome = {
        let _timer = StageTimer::start("claim");
        let mut redis = state.redis.clone();
        state.claim_script.submit(&mut redis, claim_request).await
    };

    // architecture.md §10 "free shopping": nothing that can reach the upstream
    // may run outside the `Ok` arm below. The proxy call lives inside that arm,
    // never after this match returns.
    match outcome {
        Ok(ClaimOutcome::Ok { .. }) => {
            let inbound = proxy::InboundRequest {
                path: &path,
                query: uri.query(),
                method,
                headers,
                body,
                client_addr: Some(client_addr),
            };
            match proxy::proxy_request(&state.proxy_client, &provider, inbound).await {
                Ok(response) => response,
                Err(err) => proxy::proxy_error_response(err),
            }
        }
        Ok(ClaimOutcome::Replay) => (
            StatusCode::CONFLICT,
            Json(ErrorBody::new(
                "nonce_replayed",
                "this payment authorization has already been used",
            )),
        )
            .into_response(),
        Ok(ClaimOutcome::CapExceeded {
            level,
            cap_hash,
            limit,
        }) => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "reason": "cap_exceeded",
                "level": level,
                "cap_hash": cap_hash,
                "limit": limit.to_string(),
            })),
        )
            .into_response(),
        Ok(ClaimOutcome::Insufficient { .. }) => {
            insufficient_funds_response(&provider, &state, &network, &resource)
        }
        // Not in architecture.md §4.3's failure table: that table assumes a
        // capability's meta already exists (Task 5.4's upsert). In Phase 3 this
        // is what a payer who never called POST /v1/budgets gets, which is a
        // species of "no funds", so it maps the same way as Insufficient.
        Ok(ClaimOutcome::MissingMeta { .. }) => {
            insufficient_funds_response(&provider, &state, &network, &resource)
        }
        Err(err) => {
            tracing::error!(error = %err, "claim script invocation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new("internal_error", "failed to claim budget")),
            )
                .into_response()
        }
    }
}

fn insufficient_funds_response(
    provider: &Provider,
    state: &AppState,
    network: &str,
    resource: &str,
) -> axum::response::Response {
    let mut body = serde_json::to_value(x402::payment_required_body(
        provider,
        &state.cfg.usdc_address,
        network,
        resource,
        state.cfg.quote_validity_seconds,
        "insufficient budget".to_string(),
    ))
    .expect("PaymentRequiredBody always serialises to a JSON object");
    body["reason"] = serde_json::json!("insufficient_funds");
    (StatusCode::PAYMENT_REQUIRED, Json(body)).into_response()
}
