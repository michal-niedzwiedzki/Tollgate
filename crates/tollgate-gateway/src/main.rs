use std::sync::Arc;

use axum::routing::{any, get, post};
use axum::Router;
use metrics_exporter_prometheus::PrometheusBuilder;
use tokio::signal;
use tollgate_core::{db, Config};
use tower_http::cors::CorsLayer;

// Task 5.1 builds the capability type, its hash and issuer recovery; Task 5.2 decodes the
// chain from the request header and Task 5.3 walks it. Nothing calls into it until then.
#[allow(dead_code)]
mod capability;
mod ledger;
mod policy;
mod proxy;
mod routes;
mod ssrf;
mod state;
mod verify;
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
    let mut redis = db::redis_conn(&cfg).await?;

    // SCRIPT LOAD once at startup so the first paid request pays for an EVALSHA
    // and not for a NOSCRIPT round trip.
    let claim_script = policy::ClaimScript::new();
    let claim_sha = claim_script.load(&mut redis).await?;
    tracing::info!(%claim_sha, "loaded the atomic claim script");

    let prometheus_handle = PrometheusBuilder::new()
        .set_buckets(&[
            0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0,
        ])?
        .install_recorder()?;

    // architecture.md §9.3: rebuild at boot, not lazily, and before the listener binds — a
    // cold-start miss that lets an agent overspend is exactly the bug that surfaces later.
    // Awaited, not spawned: serving a request against empty counters is the failure this
    // exists to prevent.
    ledger::rebuild_counters(&mut redis, &pg).await?;

    tokio::spawn(ledger::run(cfg.redis_url.clone(), pg.clone()));

    let proxy_client = proxy::build_client();

    // Parsed here, not on the request path: a bad key must stop the gateway starting rather
    // than surface later as a charge that returned 200 with no receipt attached.
    let receipt_signer: alloy::signers::local::PrivateKeySigner = cfg
        .gateway_signing_key
        .parse()
        .map_err(|e| anyhow::anyhow!("GATEWAY_SIGNING_KEY is not a valid private key: {e}"))?;
    tracing::info!(
        address = %receipt_signer.address(),
        "loaded the gateway receipt signing key"
    );

    let state = AppState {
        cfg: Arc::new(cfg),
        pg,
        redis,
        claim_script: Arc::new(claim_script),
        proxy_client,
        prometheus_handle,
        receipt_signer: Arc::new(receipt_signer),
    };

    // CORS for the dashboard (Task 9.1). One explicit origin, not `Any`: the gateway has write
    // endpoints — provider registration, budget seeding, revocation — and a wildcard would let
    // any page a browser happens to load call them. An unparseable origin is a startup failure
    // rather than a silently CORS-less gateway the dashboard then fails against at runtime.
    let cors = CorsLayer::new()
        .allow_origin(state.cfg.dashboard_origin.parse::<http::HeaderValue>().map_err(
            |e| anyhow::anyhow!("DASHBOARD_ORIGIN is not a valid origin header value: {e}"),
        )?)
        .allow_methods([http::Method::GET, http::Method::POST])
        .allow_headers([http::header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/metrics", get(routes::metrics))
        .route(
            "/v1/providers",
            get(routes::providers::list_providers).post(routes::providers::create_provider),
        )
        .route("/v1/providers/{slug}", get(routes::providers::get_provider))
        .route("/v1/budgets", post(routes::budgets::seed_budget))
        .route(
            "/v1/capabilities/{hash}",
            get(routes::capabilities::get_capability),
        )
        .route(
            "/v1/capabilities/{hash}/revoke",
            post(routes::capabilities::revoke_capability),
        )
        .route("/v1/receipts/{nonce}", get(routes::receipts::get_receipt))
        .route(
            "/v1/expense-report",
            get(routes::expense::expense_report),
        )
        .route("/v1/gateway-key", get(routes::receipts::gateway_key))
        .route("/v1/feed", get(routes::feed::feed))
        .route("/v1/stats", get(routes::feed::stats))
        .route(
            "/v1/proxy/{provider_slug}/{*path}",
            any(routes::proxy::handle_proxy_request),
        )
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "starting tollgate-gateway");

    // `into_make_service_with_connect_info` so the proxy route can read the real peer address
    // for the X-Forwarded-For header it adds on the way upstream.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
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
