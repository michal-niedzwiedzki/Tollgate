use std::sync::Arc;

use alloy::signers::local::PrivateKeySigner;
use metrics_exporter_prometheus::PrometheusHandle;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tollgate_core::Config;

use crate::policy::ClaimScript;
use crate::proxy::ProxyClient;

#[derive(Clone)]
pub struct AppState {
    #[allow(dead_code)]
    pub cfg: Arc<Config>,
    pub pg: PgPool,
    pub redis: ConnectionManager,
    /// Loaded at startup. Task 3.3 calls it from the request path.
    #[allow(dead_code)]
    pub claim_script: Arc<ClaimScript>,
    /// One connection-pooled client per gateway process (`architecture.md` §10 step 3's
    /// pinned connector, built once so pooling matters for the latency budget).
    pub proxy_client: ProxyClient,
    pub prometheus_handle: PrometheusHandle,
    /// Signs per-charge receipts (Task 7.1). Parsed once at startup, so a malformed
    /// `GATEWAY_SIGNING_KEY` is a boot failure rather than a receipt that silently never gets
    /// signed. Its address is published at `GET /v1/gateway-key`.
    pub receipt_signer: Arc<PrivateKeySigner>,
}
