use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use tokio::signal;
use tollgate_core::{db, Config};

mod routes;
mod state;

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Config::from_env()?;
    let bind_addr = cfg.bind_addr;

    let pg = db::pg_pool(&cfg).await?;
    let redis = db::redis_conn(&cfg).await?;

    let state = AppState {
        cfg: Arc::new(cfg),
        pg,
        redis,
    };

    let app = Router::new()
        .route("/health", get(routes::health))
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
