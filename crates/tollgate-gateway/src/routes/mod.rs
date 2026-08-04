use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use crate::state::AppState;

pub mod providers;
pub mod proxy;

pub async fn health(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let postgres_ok = sqlx::query("SELECT 1").execute(&state.pg).await.is_ok();

    let mut redis_conn = state.redis.clone();
    let redis_ping: redis::RedisResult<String> =
        redis::cmd("PING").query_async(&mut redis_conn).await;
    let redis_ok = redis_ping.is_ok();

    let status_code = if postgres_ok && redis_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = json!({
        "status": if postgres_ok && redis_ok { "ok" } else { "degraded" },
        "postgres": postgres_ok,
        "redis": redis_ok,
    });

    (status_code, Json(body))
}

pub async fn metrics(State(state): State<AppState>) -> String {
    state.prometheus_handle.render()
}
