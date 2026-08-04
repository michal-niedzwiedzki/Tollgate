use std::sync::Arc;

use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tollgate_core::Config;

#[derive(Clone)]
pub struct AppState {
    #[allow(dead_code)]
    pub cfg: Arc<Config>,
    pub pg: PgPool,
    pub redis: ConnectionManager,
}
