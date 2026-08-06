use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, OriginalUri, Path, State};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode};
use axum::response::{IntoResponse, Json};
use tollgate_core::db;
use tollgate_core::error::ErrorBody;
use tollgate_core::Provider;

use tollgate_core::metrics::StageTimer;

use crate::capability;
use crate::capability::decode::decode_capability_chain;
use crate::capability::verify::verify_chain;
use crate::ledger;
use crate::policy::{self, CapLevel, ClaimOutcome, ClaimRequest};
use crate::proxy;
use crate::state::AppState;
use crate::verify::recover_payer;
use crate::x402;
use crate::x402::decode::decode_payment_header;
use crate::x402::validate::validate_fields;

const X_PAYMENT: HeaderName = HeaderName::from_static("x-payment");
const X_TOLLGATE_CAPABILITY: HeaderName = HeaderName::from_static("x-tollgate-capability");

/// The capability levels a request charges against, root first, plus the subject of each so
/// the 429 body can say who owns the budget that said no.
struct Levels {
    levels: Vec<CapLevel>,
    subjects: Vec<String>,
}

impl Levels {
    fn cap_hashes(&self) -> Vec<String> {
        self.levels.iter().map(|l| l.cap_hash.clone()).collect()
    }
}

/// Resolves which capability levels this charge draws against.
///
/// `X-Tollgate-Capability` is **optional** (architecture.md §4.2). Without it the request is
/// the ordinary single-level case Phase 3 built: one level keyed by the payer, funded through
/// `POST /v1/budgets`. `prd.md` F3 — per-request cap, total cap, allowlist — is a standalone
/// requirement that does not mention delegation, so this path is not a legacy stand-in and is
/// not going away.
///
/// With the header, every link of the verified chain becomes a level, and the charge draws
/// down all of them (architecture.md §5.2: "every charge decrements every capability in the
/// chain, not just the leaf").
async fn resolve_levels(
    state: &AppState,
    headers: &HeaderMap,
    payer: alloy::primitives::Address,
    provider_slug: &str,
    now: u64,
) -> Result<Levels, axum::response::Response> {
    let Some(header) = headers.get(X_TOLLGATE_CAPABILITY).and_then(|v| v.to_str().ok()) else {
        return Ok(Levels {
            levels: vec![CapLevel {
                cap_hash: policy::payer_cap_hash(&payer),
            }],
            subjects: vec![payer.to_string()],
        });
    };

    let chain = decode_capability_chain(header).map_err(|err| {
        // A chain that will not decode is malformed, not a policy refusal.
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new("invalid_capability_chain", err.to_string())),
        )
            .into_response()
    })?;

    let hashes: Vec<String> = chain
        .iter()
        .map(|link| capability::struct_hash(&link.capability).to_string())
        .collect();

    let mut redis = state.redis.clone();
    let revoked = policy::fetch_revoked(&mut redis, &hashes)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "failed to read the revocation set");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new(
                    "internal_error",
                    "failed to read the revocation set",
                )),
            )
                .into_response()
        })?;
    let revoked: std::collections::HashSet<alloy::primitives::B256> =
        revoked.iter().filter_map(|hash| hash.parse().ok()).collect();

    let levels = verify_chain(
        &chain,
        payer,
        provider_slug,
        now,
        state.cfg.chain_id,
        &revoked,
    )
    .map_err(|err| {
        (
            err.status(),
            Json(ErrorBody::new(err.reason(), err.to_string())),
        )
            .into_response()
    })?;

    // Persisted *before* the claim, root first, and failing the request closed if it does not
    // land. Two reasons, both load-bearing:
    //
    //  - `authorisations.capability_hash` is a foreign key onto this table and the ledger
    //    drain writes that row asynchronously. A capability row missing at drain time would
    //    be a permanent FK violation — a poison stream entry that stalls the drain.
    //  - `capabilities.parent_hash` is a self-referencing foreign key, so children can only
    //    follow their parents. Root-first insertion is what satisfies it.
    for (depth, link) in chain.iter().enumerate() {
        let capability = &link.capability;
        let record = tollgate_core::CapabilityRecord {
            hash: capability::struct_hash(capability),
            issuer: capability.issuer,
            subject: capability.subject,
            // A root's `parent` is 0x0, which is not a row: it must be SQL NULL.
            parent_hash: (depth > 0).then_some(capability.parent),
            depth: depth as i32,
            max_total_wei: capability.maxTotal,
            max_per_req_wei: capability.maxPerRequest,
            allowlist: (!link.allowlist.is_empty()).then(|| link.allowlist.clone()),
            not_before: capability.notBefore,
            expiry: capability.expiry,
            signature: link.signature.to_vec(),
        };
        if let Err(err) = tollgate_core::db::insert_capability(&state.pg, &record).await {
            tracing::error!(error = %err, depth, "failed to persist capability");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new(
                    "internal_error",
                    "failed to persist capability",
                )),
            )
                .into_response());
        }
    }

    // Only now, with the chain verified, may its own limits become the limits the claim
    // script enforces. Seeding meta from an unverified chain would let a caller install
    // whatever caps it liked.
    for (link, level) in chain.iter().zip(&levels) {
        let capability = &link.capability;
        let (Ok(max_total), Ok(max_per_request)) = (
            u128::try_from(capability.maxTotal),
            u128::try_from(capability.maxPerRequest),
        ) else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorBody::new(
                    "invalid_capability",
                    "capability limits exceed the supported range",
                )),
            )
                .into_response());
        };

        if let Err(err) = policy::upsert_capability_meta(
            &mut redis,
            &level.cap_hash,
            max_total,
            max_per_request,
            capability.expiry,
        )
        .await
        {
            tracing::error!(error = %err, "failed to seed capability meta");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new(
                    "internal_error",
                    "failed to seed capability budget",
                )),
            )
                .into_response());
        }
    }

    let subjects = chain
        .iter()
        .map(|link| link.capability.subject.to_string())
        .collect();

    Ok(Levels { levels, subjects })
}

/// Per-level budget state for the 429 body. architecture.md §4.3: "The 429 body is worth
/// getting right. Make it good: include the capability hash, the parent chain, remaining
/// budget at each level, and which level said no."
async fn budget_snapshot(
    redis: &mut redis::aio::ConnectionManager,
    levels: &Levels,
) -> Vec<serde_json::Value> {
    let mut out = Vec::with_capacity(levels.levels.len());
    for (level, subject) in levels.levels.iter().zip(&levels.subjects) {
        let (max_total, spent) = policy::read_level_state(redis, &level.cap_hash)
            .await
            .unwrap_or((0, 0));
        out.push(serde_json::json!({
            "hash": level.cap_hash,
            "subject": subject,
            "max_total": max_total.to_string(),
            "spent": spent.to_string(),
            "remaining": max_total.saturating_sub(spent).to_string(),
        }));
    }
    out
}

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

    // architecture.md §4.2 step 4: the chain walk sits between signature recovery and the
    // claim, so a charge is only ever attempted against levels that have been verified.
    let levels = match resolve_levels(&state, &headers, payer, &provider.slug, now).await {
        Ok(levels) => levels,
        Err(response) => return response,
    };
    let cap_hashes = levels.cap_hashes();

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
        levels: levels.levels.clone(),
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
            let proxy_result = proxy::proxy_request(&state.proxy_client, &provider, inbound).await;

            // architecture.md §4.2 step 7 / §4.3: a 2xx promotes the reservation to
            // settleable; anything else voids it and credits the budget back. A
            // non-5xx upstream response is still forwarded to the caller as-is
            // (Task 4.3's redirect decision extended to the rest of the non-2xx
            // range); only a 5xx becomes a 502, since the upstream's own error
            // detail is not this gateway's to leak verbatim.
            let (outcome, response) = match proxy_result {
                Ok(resp) if resp.status().is_success() => {
                    let code = i32::from(resp.status().as_u16());
                    (ledger::ReservationOutcome::Queued { upstream_status: code }, resp)
                }
                Ok(resp) if resp.status().is_server_error() => {
                    let code = i32::from(resp.status().as_u16());
                    let outcome = ledger::ReservationOutcome::Voided {
                        upstream_status: Some(code),
                    };
                    let response = (
                        StatusCode::BAD_GATEWAY,
                        Json(ErrorBody::new(
                            "upstream_error",
                            format!("upstream responded {code}"),
                        )),
                    )
                        .into_response();
                    (outcome, response)
                }
                Ok(resp) => {
                    let code = i32::from(resp.status().as_u16());
                    let outcome = ledger::ReservationOutcome::Voided {
                        upstream_status: Some(code),
                    };
                    (outcome, resp)
                }
                Err(err) => {
                    let outcome = ledger::ReservationOutcome::Voided {
                        upstream_status: None,
                    };
                    let response = proxy::proxy_error_response(err);
                    (outcome, response)
                }
            };

            let mut redis = state.redis.clone();
            // Marker first, then the direct UPDATE — this order must not be
            // swapped. The drain relies on it: it reads the marker after its
            // own INSERT, so a marker written before this UPDATE is guaranteed
            // visible to the drain whenever this UPDATE finds no row yet.
            if let Err(err) = ledger::mark_outcome(&mut redis, &nonce_hex, &outcome).await {
                tracing::error!(error = %err, "failed to write outcome marker");
            }
            if let Err(err) = ledger::apply_outcome_update(&state.pg, auth.nonce.as_slice(), &outcome).await
            {
                tracing::error!(error = %err, "failed to apply reservation outcome update");
            }
            // Every level was charged, so every level is credited back — otherwise a failed
            // upstream would permanently consume an ancestor's budget for a request that
            // returned nothing.
            if matches!(outcome, ledger::ReservationOutcome::Voided { .. })
                && let Err(err) = policy::void(&mut redis, &cap_hashes, amount).await
            {
                tracing::error!(error = %err, "failed to credit budget back after void");
            }

            response
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
        }) => {
            let mut redis = state.redis.clone();
            let chain = budget_snapshot(&mut redis, &levels).await;
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "reason": "cap_exceeded",
                    "tripped_level": level,
                    "capability_hash": cap_hash,
                    "limit": limit.to_string(),
                    "chain": chain,
                })),
            )
                .into_response()
        }
        Ok(ClaimOutcome::Insufficient {
            level, cap_hash, ..
        }) => {
            let mut redis = state.redis.clone();
            let chain = budget_snapshot(&mut redis, &levels).await;
            insufficient_funds_response(
                &provider,
                &state,
                &network,
                &resource,
                Some((level, cap_hash, chain)),
            )
        }
        // Not in architecture.md §4.3's failure table: that table assumes a
        // capability's meta already exists (Task 5.4's upsert). In Phase 3 this
        // is what a payer who never called POST /v1/budgets gets, which is a
        // species of "no funds", so it maps the same way as Insufficient.
        Ok(ClaimOutcome::MissingMeta { .. }) => {
            insufficient_funds_response(&provider, &state, &network, &resource, None)
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

/// The 402 for a budget that cannot cover the charge. `tripped` names which level said no
/// and what every level had left, the same detail the 429 carries: a supervisor whose pool
/// emptied needs to know it was the root that stopped its workers, not their own caps.
fn insufficient_funds_response(
    provider: &Provider,
    state: &AppState,
    network: &str,
    resource: &str,
    tripped: Option<(usize, String, Vec<serde_json::Value>)>,
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
    if let Some((level, cap_hash, chain)) = tripped {
        body["tripped_level"] = serde_json::json!(level);
        body["capability_hash"] = serde_json::json!(cap_hash);
        body["chain"] = serde_json::json!(chain);
    }
    (StatusCode::PAYMENT_REQUIRED, Json(body)).into_response()
}
