//! The public charge feed and the live stats panel. Task 7.3.
//!
//! Data sources for `architecture.md` §7.4 view 3: "Every settled charge, streaming, plus a live
//! latency panel showing gateway p50 and p99 separated from upstream time." Polling, not SSE — a
//! live stream is Post-MVP.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;
use tollgate_core::error::ErrorBody;

use crate::state::AppState;

/// Cap on `limit`, so a public endpoint cannot be asked for the whole ledger in one request.
const MAX_LIMIT: i64 = 500;
const DEFAULT_LIMIT: i64 = 50;

#[derive(Debug, Deserialize)]
pub struct FeedQuery {
    limit: Option<i64>,
    /// An ISO-8601 timestamp — a poller passes back the newest `timestamp` it has already seen
    /// and gets only what has landed since. Strictly greater, so the row that produced the
    /// cursor is not re-delivered.
    since: Option<String>,
}

#[derive(sqlx::FromRow)]
struct FeedRow {
    payer: Vec<u8>,
    provider_slug: Option<String>,
    amount_wei: String,
    upstream_status: Option<i32>,
    tx_hash: Option<Vec<u8>>,
    status: String,
    created_at: String,
}

/// `GET /v1/feed?limit=50&since=<cursor>` — recent charges, newest first.
///
/// The payer address is shown in full and deliberately not truncated: this is testnet, and the
/// demo depends on being able to paste it straight into Basescan.
pub async fn feed(
    State(state): State<AppState>,
    Query(query): Query<FeedQuery>,
) -> axum::response::Response {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    // `voided` is excluded on the same grounds as the expense report: the caller received
    // nothing and the budget was credited back, so it is not a charge. Everything else appears,
    // with `status` alongside, so a reader can tell a settled charge from one still queued
    // without having to infer it from `tx_hash` being null.
    let rows: Result<Vec<FeedRow>, sqlx::Error> = sqlx::query_as(
        "SELECT payer, provider_slug, amount_wei::TEXT AS amount_wei, upstream_status, tx_hash,
                status, created_at::TEXT AS created_at
           FROM authorisations
          WHERE status <> 'voided'
            AND ($1::TIMESTAMPTZ IS NULL OR created_at > $1::TIMESTAMPTZ)
          ORDER BY created_at DESC
          LIMIT $2",
    )
    .bind(query.since.as_deref())
    .bind(limit)
    .fetch_all(&state.pg)
    .await;

    let rows = match rows {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(error = %err, "failed to read the charge feed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new("internal_error", "failed to read the feed")),
            )
                .into_response();
        }
    };

    let entries: Vec<_> = rows
        .into_iter()
        .map(|row| {
            json!({
                "payer": alloy::hex::encode_prefixed(&row.payer),
                "provider": row.provider_slug,
                "amount_wei": row.amount_wei,
                "upstream_status": row.upstream_status,
                "tx_hash": row.tx_hash.as_deref().map(alloy::hex::encode_prefixed),
                "status": row.status,
                "timestamp": row.created_at,
            })
        })
        .collect();

    (StatusCode::OK, Json(entries)).into_response()
}

/// Reads one quantile out of the Prometheus text the gateway already exports.
///
/// `PrometheusHandle` exposes no structured snapshot — `render()` is the whole public API — so
/// the percentiles come from parsing our own exported histogram buckets. That is deliberate
/// rather than merely expedient: `/v1/stats` and `/metrics` are then the same numbers by
/// construction, and no second copy of the latency data has to be kept in step with the first.
///
/// Standard `histogram_quantile` semantics: find the bucket the quantile falls in and
/// interpolate linearly within it. Returns `None` when nothing has been observed yet, which the
/// caller renders as JSON null rather than as a fabricated zero.
fn quantile_from_render(render: &str, stage: &str, quantile: f64) -> Option<f64> {
    let needle = format!("stage=\"{stage}\"");
    let mut buckets: Vec<(f64, f64)> = Vec::new();

    for line in render.lines() {
        if !line.starts_with("tollgate_stage_seconds_bucket") || !line.contains(&needle) {
            continue;
        }
        let (labels, count) = line.rsplit_once(' ')?;
        let le = labels.split("le=\"").nth(1)?.split('"').next()?;
        let bound = if le == "+Inf" { f64::INFINITY } else { le.parse().ok()? };
        buckets.push((bound, count.trim().parse().ok()?));
    }

    buckets.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    // Buckets are cumulative, so the last one is the total observation count.
    let total = buckets.last()?.1;
    if total <= 0.0 {
        return None;
    }

    let target = quantile * total;
    let mut previous_bound = 0.0;
    let mut previous_count = 0.0;
    for (bound, count) in &buckets {
        if *count >= target {
            if bound.is_infinite() {
                // Everything above the largest finite bucket: the most that can honestly be
                // said is "at least that bound".
                return Some(previous_bound);
            }
            let span = count - previous_count;
            let position = if span > 0.0 {
                (target - previous_count) / span
            } else {
                0.0
            };
            return Some(previous_bound + (bound - previous_bound) * position);
        }
        previous_bound = *bound;
        previous_count = *count;
    }

    Some(previous_bound)
}

/// `GET /v1/stats` — the live panel behind `architecture.md` §11.
///
/// Gateway and upstream latency are separate fields and are never summed. `gateway_*` is the
/// added latency `prd.md` §8 budgets at 15 ms p50, measured as the request minus its upstream
/// hop; `upstream_p50` is the hop itself, which the caller was paying for anyway.
pub async fn stats(State(state): State<AppState>) -> axum::response::Response {
    let render = state.prometheus_handle.render();

    let queue_depth: Result<(i64,), sqlx::Error> =
        sqlx::query_as("SELECT count(*) FROM authorisations WHERE status = 'queued'")
            .fetch_one(&state.pg)
            .await;

    // The most recent batch: its size, the gas its transaction burned, and the two divided.
    // Phase 9's settlement panel wants "last batch", not a lifetime average, and a recent
    // figure is also the one worth comparing against `.gas-snapshot`.
    let last_batch: Result<Option<(i64, Option<i64>)>, sqlx::Error> = sqlx::query_as(
        "SELECT count(*), max(gas_used)
           FROM authorisations
          WHERE batch_id = (
              SELECT batch_id FROM authorisations
               WHERE status = 'settled' AND batch_id IS NOT NULL
               ORDER BY settled_at DESC LIMIT 1)
            AND status = 'settled'",
    )
    .fetch_optional(&state.pg)
    .await;

    // `created_at` is when the reservation was written, which is the same request that promoted
    // it to `queued` — there is no separate `queued_at`, so this is queue latency to within the
    // upstream round trip.
    let mean_queue_seconds: Result<Option<(Option<f64>,)>, sqlx::Error> = sqlx::query_as(
        "SELECT EXTRACT(EPOCH FROM avg(settled_at - created_at))::DOUBLE PRECISION
           FROM authorisations WHERE status = 'settled' AND settled_at IS NOT NULL",
    )
    .fetch_optional(&state.pg)
    .await;

    let (queue_depth, last_batch, mean_queue_seconds) =
        match (queue_depth, last_batch, mean_queue_seconds) {
            (Ok(depth), Ok(batch), Ok(mean)) => (depth.0, batch, mean),
            _ => {
                tracing::error!("failed to read settlement stats");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorBody::new("internal_error", "failed to read stats")),
                )
                    .into_response();
            }
        };

    let (batch_size, gas_per_batch) = match last_batch {
        Some((size, gas)) if size > 0 => (Some(size), gas),
        _ => (None, None),
    };
    let gas_per_charge = match (gas_per_batch, batch_size) {
        // The transaction's whole gas over the charges that settled in it. Items the contract
        // refused consumed gas too and are not counted here, so this reads slightly high — the
        // conservative direction for a cost claim.
        (Some(gas), Some(size)) if size > 0 => Some(gas / size),
        _ => None,
    };

    (
        StatusCode::OK,
        Json(json!({
            "gateway_p50": quantile_from_render(&render, "gateway", 0.50),
            "gateway_p99": quantile_from_render(&render, "gateway", 0.99),
            "upstream_p50": quantile_from_render(&render, "upstream", 0.50),
            "batch_size": batch_size,
            "gas_per_batch": gas_per_batch,
            "gas_per_charge": gas_per_charge,
            "queue_depth": queue_depth,
            "mean_queued_to_settled_seconds": mean_queue_seconds.and_then(|row| row.0),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two stages, so the label filter is doing real work rather than reading whichever
    /// histogram happens to come first.
    const RENDER: &str = "\
# TYPE tollgate_stage_seconds histogram
tollgate_stage_seconds_bucket{stage=\"gateway\",le=\"0.001\"} 0
tollgate_stage_seconds_bucket{stage=\"gateway\",le=\"0.005\"} 5
tollgate_stage_seconds_bucket{stage=\"gateway\",le=\"0.01\"} 10
tollgate_stage_seconds_bucket{stage=\"gateway\",le=\"+Inf\"} 10
tollgate_stage_seconds_bucket{stage=\"upstream\",le=\"0.001\"} 0
tollgate_stage_seconds_bucket{stage=\"upstream\",le=\"0.5\"} 4
tollgate_stage_seconds_bucket{stage=\"upstream\",le=\"+Inf\"} 4
";

    #[test]
    fn the_median_interpolates_inside_its_bucket() {
        // 10 observations, so p50 targets the 5th, which is the top of the 0.001..0.005 bucket.
        let p50 = quantile_from_render(RENDER, "gateway", 0.50).expect("gateway p50");
        assert!(
            (p50 - 0.005).abs() < 1e-9,
            "p50 should land at the 0.005 bound, got {p50}"
        );
    }

    #[test]
    fn a_higher_quantile_lands_in_a_higher_bucket() {
        let p50 = quantile_from_render(RENDER, "gateway", 0.50).expect("p50");
        let p99 = quantile_from_render(RENDER, "gateway", 0.99).expect("p99");
        assert!(p99 > p50, "p99 {p99} should exceed p50 {p50}");
        assert!(p99 <= 0.01, "p99 cannot exceed the largest populated bound");
    }

    /// The whole point of the endpoint: these are different numbers from different histograms,
    /// and one must never be read in place of the other (prd.md §8).
    #[test]
    fn stages_are_read_independently() {
        let gateway = quantile_from_render(RENDER, "gateway", 0.50).expect("gateway");
        let upstream = quantile_from_render(RENDER, "upstream", 0.50).expect("upstream");
        assert!(
            upstream > gateway,
            "the sample upstream is slower than the sample gateway; got {upstream} vs {gateway}"
        );
    }

    #[test]
    fn an_unobserved_stage_is_none_rather_than_zero() {
        assert_eq!(quantile_from_render(RENDER, "claim", 0.50), None);
        assert_eq!(quantile_from_render("", "gateway", 0.50), None);
    }
}
