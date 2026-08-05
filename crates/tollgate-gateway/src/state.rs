use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusHandle;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tollgate_core::Config;

use crate::policy::ClaimScript;

#[derive(Clone)]
pub struct AppState {
    #[allow(dead_code)]
    pub cfg: Arc<Config>,
    pub pg: PgPool,
    pub redis: ConnectionManager,
    /// Loaded at startup. Task 3.3 calls it from the request path.
    #[allow(dead_code)]
    pub claim_script: Arc<ClaimScript>,
    pub prometheus_handle: PrometheusHandle,
}
