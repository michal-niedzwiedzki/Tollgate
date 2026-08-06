use std::time::Duration;

use redis::aio::ConnectionManager;
use sqlx::postgres::PgPoolOptions;
use alloy::primitives::Address;
use sqlx::PgPool;

use crate::config::Config;
use crate::error::Result;
use crate::types::{
    address_to_bytea, bytea_to_address, bytea_to_b256, numeric_to_u256, u256_to_numeric,
    CapabilityRecord, Provider, Scheme, StoredCapability,
};

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

#[derive(sqlx::FromRow)]
struct ProviderRow {
    slug: String,
    upstream_url: String,
    price_wei: String,
    max_price_wei: Option<String>,
    scheme: String,
    payout_address: Vec<u8>,
    timeout_ms: i32,
}

impl TryFrom<ProviderRow> for Provider {
    type Error = crate::error::Error;

    fn try_from(row: ProviderRow) -> Result<Self> {
        Ok(Provider {
            slug: row.slug,
            upstream_url: row.upstream_url,
            price_wei: numeric_to_u256(&row.price_wei)?,
            max_price_wei: row.max_price_wei.as_deref().map(numeric_to_u256).transpose()?,
            scheme: Scheme::parse(&row.scheme)?,
            payout_address: bytea_to_address(&row.payout_address)?,
            timeout_ms: row.timeout_ms,
        })
    }
}

const PROVIDER_COLUMNS: &str = "slug, upstream_url, price_wei::TEXT AS price_wei, \
    max_price_wei::TEXT AS max_price_wei, scheme, payout_address, timeout_ms";

pub async fn insert_provider(pool: &PgPool, provider: &Provider) -> Result<()> {
    sqlx::query(
        "INSERT INTO providers (slug, upstream_url, price_wei, max_price_wei, scheme, payout_address, timeout_ms)
         VALUES ($1, $2, $3::NUMERIC, $4::NUMERIC, $5, $6, $7)",
    )
    .bind(&provider.slug)
    .bind(&provider.upstream_url)
    .bind(u256_to_numeric(provider.price_wei))
    .bind(provider.max_price_wei.map(u256_to_numeric))
    .bind(provider.scheme.as_str())
    .bind(address_to_bytea(&provider.payout_address))
    .bind(provider.timeout_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_provider(pool: &PgPool, slug: &str) -> Result<Option<Provider>> {
    let row: Option<ProviderRow> = sqlx::query_as(&format!(
        "SELECT {PROVIDER_COLUMNS} FROM providers WHERE slug = $1"
    ))
    .bind(slug)
    .fetch_optional(pool)
    .await?;

    row.map(Provider::try_from).transpose()
}

pub async fn list_providers(pool: &PgPool) -> Result<Vec<Provider>> {
    let rows: Vec<ProviderRow> = sqlx::query_as(&format!(
        "SELECT {PROVIDER_COLUMNS} FROM providers ORDER BY slug"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(Provider::try_from).collect()
}

/// Records a capability on its first use (Task 5.4). Idempotent: a capability presented on
/// every request of a run inserts once and is a no-op thereafter.
///
/// Callers must insert **root first**. `parent_hash` is a self-referencing foreign key, so a
/// child whose parent has not landed yet is rejected by the constraint.
pub async fn insert_capability(pool: &PgPool, capability: &CapabilityRecord) -> Result<()> {
    sqlx::query(
        "INSERT INTO capabilities
           (hash, issuer, subject, parent_hash, depth, max_total_wei, max_per_req_wei,
            allowlist, not_before, expiry, signature)
         VALUES ($1, $2, $3, $4, $5, $6::NUMERIC, $7::NUMERIC, $8,
                 TO_TIMESTAMP($9), TO_TIMESTAMP($10), $11)
         ON CONFLICT (hash) DO NOTHING",
    )
    .bind(capability.hash.as_slice())
    .bind(capability.issuer.as_slice())
    .bind(capability.subject.as_slice())
    .bind(capability.parent_hash.as_ref().map(|h| h.as_slice()))
    .bind(capability.depth)
    .bind(u256_to_numeric(capability.max_total_wei))
    .bind(u256_to_numeric(capability.max_per_req_wei))
    .bind(capability.allowlist.as_ref())
    .bind(capability.not_before as f64)
    .bind(capability.expiry as f64)
    .bind(&capability.signature)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct CapabilityRow {
    hash: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    parent_hash: Option<Vec<u8>>,
    depth: i32,
    max_total_wei: String,
    max_per_req_wei: String,
    allowlist: Option<Vec<String>>,
    not_before: i64,
    expiry: i64,
    signature: Vec<u8>,
    revoked_at: Option<String>,
}

impl TryFrom<CapabilityRow> for StoredCapability {
    type Error = crate::error::Error;

    fn try_from(row: CapabilityRow) -> Result<Self> {
        Ok(StoredCapability {
            capability: CapabilityRecord {
                hash: bytea_to_b256(&row.hash)?,
                issuer: bytea_to_address(&row.issuer)?,
                subject: bytea_to_address(&row.subject)?,
                parent_hash: row.parent_hash.as_deref().map(bytea_to_b256).transpose()?,
                depth: row.depth,
                max_total_wei: numeric_to_u256(&row.max_total_wei)?,
                max_per_req_wei: numeric_to_u256(&row.max_per_req_wei)?,
                allowlist: row.allowlist,
                not_before: row.not_before as u64,
                expiry: row.expiry as u64,
                signature: row.signature,
            },
            revoked_at: row.revoked_at,
        })
    }
}

/// `TIMESTAMPTZ` back to unix seconds, and `NUMERIC`/`TIMESTAMPTZ` to text, so reading a
/// capability needs no date-time dependency in this crate.
const CAPABILITY_COLUMNS: &str = "hash, issuer, subject, parent_hash, depth, \
    max_total_wei::TEXT AS max_total_wei, max_per_req_wei::TEXT AS max_per_req_wei, \
    allowlist, EXTRACT(EPOCH FROM not_before)::BIGINT AS not_before, \
    EXTRACT(EPOCH FROM expiry)::BIGINT AS expiry, signature, \
    revoked_at::TEXT AS revoked_at";

pub async fn get_capability(pool: &PgPool, hash: &[u8]) -> Result<Option<StoredCapability>> {
    let row: Option<CapabilityRow> = sqlx::query_as(&format!(
        "SELECT {CAPABILITY_COLUMNS} FROM capabilities WHERE hash = $1"
    ))
    .bind(hash)
    .fetch_optional(pool)
    .await?;

    row.map(StoredCapability::try_from).transpose()
}

/// Every address entitled to revoke `hash`: its own issuer, plus the issuer of every
/// ancestor. architecture.md §5.2 makes a child's authority borrowed from its parent, so an
/// ancestor that granted the authority can withdraw it.
///
/// One recursive walk up `parent_hash` rather than a query per level: the chain is at most
/// four links, but a round trip each would put the database on a revocation's critical path
/// for no reason.
pub async fn capability_issuers(pool: &PgPool, hash: &[u8]) -> Result<Vec<Address>> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
        "WITH RECURSIVE ancestry AS (
             SELECT hash, issuer, parent_hash FROM capabilities WHERE hash = $1
           UNION ALL
             SELECT c.hash, c.issuer, c.parent_hash
             FROM capabilities c JOIN ancestry a ON c.hash = a.parent_hash
         )
         SELECT issuer FROM ancestry",
    )
    .bind(hash)
    .fetch_all(pool)
    .await?;

    rows.iter().map(|(issuer,)| bytea_to_address(issuer)).collect()
}

/// Stamps `revoked_at`. Idempotent: `WHERE revoked_at IS NULL` keeps the first revocation's
/// timestamp rather than letting a replay move it forward.
pub async fn mark_capability_revoked(pool: &PgPool, hash: &[u8]) -> Result<()> {
    sqlx::query("UPDATE capabilities SET revoked_at = now() WHERE hash = $1 AND revoked_at IS NULL")
        .bind(hash)
        .execute(pool)
        .await?;
    Ok(())
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

    #[tokio::test]
    #[ignore]
    async fn provider_repo_round_trips_address_and_price() {
        use alloy::primitives::{Address, U256};

        let cfg = test_config();
        let pool = pg_pool(&cfg).await.expect("postgres pool should connect");

        let slug = "test-provider-repo";
        sqlx::query("DELETE FROM providers WHERE slug = $1")
            .bind(slug)
            .execute(&pool)
            .await
            .expect("cleanup before insert should succeed");

        let provider = Provider {
            slug: slug.to_string(),
            upstream_url: "http://127.0.0.1:9000".to_string(),
            price_wei: U256::from(123_456_789_012_345_678u128),
            max_price_wei: Some(U256::from(5_000u64)),
            scheme: Scheme::Exact,
            payout_address: Address::from_slice(&[0xab; 20]),
            timeout_ms: 5_000,
        };

        insert_provider(&pool, &provider)
            .await
            .expect("insert should succeed");

        let fetched = get_provider(&pool, slug)
            .await
            .expect("get should succeed")
            .expect("provider should exist");

        assert_eq!(fetched.payout_address, provider.payout_address);
        assert_eq!(fetched.price_wei, provider.price_wei);
        assert_eq!(fetched.max_price_wei, provider.max_price_wei);
        assert_eq!(fetched.scheme, Scheme::Exact);
        assert_eq!(fetched.timeout_ms, provider.timeout_ms);

        let listed = list_providers(&pool).await.expect("list should succeed");
        assert!(listed.iter().any(|p| p.slug == slug));

        sqlx::query("DELETE FROM providers WHERE slug = $1")
            .bind(slug)
            .execute(&pool)
            .await
            .expect("cleanup after test should succeed");
    }

    #[test]
    #[ignore]
    fn provider_repo_rejects_unknown_scheme() {
        let err = Scheme::parse("upto").expect_err("scheme \"upto\" should fail to parse");
        assert!(matches!(err, crate::error::Error::UnsupportedScheme(ref s) if s == "upto"));
    }
}
