use std::sync::Arc;

use axum::routing::{any, get};
use axum::Router;
use tokio::signal;
use tollgate_core::{db, Config};

mod routes;
mod state;
mod x402;

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env()?;
    let bind_addr = cfg.bind_addr;

    let pg = db::pg_pool(&cfg).await?;
    sqlx::migrate!("../../migrations").run(&pg).await?;
    let redis = db::redis_conn(&cfg).await?;

    let state = AppState {
        cfg: Arc::new(cfg),
        pg,
        redis,
    };

    let app = Router::new()
        .route("/health", get(routes::health))
        .route(
            "/v1/providers",
            get(routes::providers::list_providers).post(routes::providers::create_provider),
        )
        .route("/v1/providers/{slug}", get(routes::providers::get_provider))
        .route(
            "/v1/proxy/{provider_slug}/{*path}",
            any(routes::proxy::handle_proxy_request),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "starting tollgate-gateway");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
