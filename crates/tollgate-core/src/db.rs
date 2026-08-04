use std::time::Duration;

use redis::aio::ConnectionManager;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::config::Config;
use crate::error::Result;

pub async fn pg_pool(cfg: &Config) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&cfg.database_url)
        .await?;
    Ok(pool)
}

pub async fn redis_conn(cfg: &Config) -> Result<ConnectionManager> {
    let client = redis::Client::open(cfg.redis_url.as_str())?;
    let manager = client.get_connection_manager().await?;
    Ok(manager)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            database_url: "postgres://postgres:postgres@localhost:5432/tollgate".to_string(),
            redis_url: "redis://localhost:6379".to_string(),
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            chain_id: 84532,
            rpc_url: "http://localhost:8545".to_string(),
            usdc_address: "0x0000000000000000000000000000000000000000".to_string(),
            batch_settler_address: "0x0000000000000000000000000000000000000000".to_string(),
            settler_private_key: "0x0".to_string(),
            gateway_signing_key: "0x0".to_string(),
            quote_validity_seconds: 300,
            clock_skew_seconds: 60,
            settler_batch_size: 50,
            settler_flush_seconds: 10,
        }
    }

    #[tokio::test]
    #[ignore]
    async fn connection() {
        let cfg = test_config();

        let pool = pg_pool(&cfg).await.expect("postgres pool should connect");
        let row: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("select 1 should succeed");
        assert_eq!(row.0, 1);

        let mut conn = redis_conn(&cfg)
            .await
            .expect("redis connection manager should connect");
        let pong: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .expect("ping should succeed");
        assert_eq!(pong, "PONG");
    }
}
