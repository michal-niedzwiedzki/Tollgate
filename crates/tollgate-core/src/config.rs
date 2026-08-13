use std::env;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub bind_addr: SocketAddr,
    pub chain_id: u64,
    pub rpc_url: String,
    pub usdc_address: String,
    pub batch_settler_address: String,
    pub settler_private_key: String,
    pub gateway_signing_key: String,
    pub quote_validity_seconds: u64,
    pub clock_skew_seconds: u64,
    pub settler_batch_size: u32,
    pub settler_flush_seconds: u64,
    /// Origin the dashboard is served from, allowed through CORS (Task 9.1). A single explicit
    /// origin rather than a wildcard: the gateway has write endpoints, and `*` would let any
    /// page a browser loads register a provider or revoke a capability.
    pub dashboard_origin: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Config {
            database_url: required("DATABASE_URL")?,
            redis_url: required("REDIS_URL")?,
            bind_addr: required_parsed("BIND_ADDR")?,
            chain_id: default_parsed("CHAIN_ID", 84532)?,
            rpc_url: required("RPC_URL")?,
            usdc_address: required("USDC_ADDRESS")?,
            batch_settler_address: required("BATCH_SETTLER_ADDRESS")?,
            settler_private_key: required("SETTLER_PRIVATE_KEY")?,
            gateway_signing_key: required("GATEWAY_SIGNING_KEY")?,
            quote_validity_seconds: default_parsed("QUOTE_VALIDITY_SECONDS", 300)?,
            clock_skew_seconds: default_parsed("CLOCK_SKEW_SECONDS", 60)?,
            settler_batch_size: default_parsed("SETTLER_BATCH_SIZE", 50)?,
            settler_flush_seconds: default_parsed("SETTLER_FLUSH_SECONDS", 10)?,
            dashboard_origin: default_string("DASHBOARD_ORIGIN", "http://localhost:3000"),
        })
    }
}

fn required(name: &str) -> Result<String> {
    env::var(name).map_err(|_| Error::MissingEnvVar(name.to_string()))
}

fn default_string(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn required_parsed<T>(name: &str) -> Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    parse(name, required(name)?)
}

fn default_parsed<T>(name: &str, default: T) -> Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(value) => parse(name, value),
        Err(_) => Ok(default),
    }
}

fn parse<T>(name: &str, value: String) -> Result<T>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    value.parse::<T>().map_err(|e| Error::InvalidEnvVar {
        var: name.to_string(),
        message: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn full_env() -> Vec<(&'static str, &'static str)> {
        vec![
            ("DATABASE_URL", "postgres://postgres:postgres@localhost/tollgate"),
            ("REDIS_URL", "redis://localhost:6379"),
            ("BIND_ADDR", "0.0.0.0:8080"),
            ("RPC_URL", "http://localhost:8545"),
            ("USDC_ADDRESS", "0x0000000000000000000000000000000000000002"),
            ("BATCH_SETTLER_ADDRESS", "0x0000000000000000000000000000000000000001"),
            ("SETTLER_PRIVATE_KEY", "0xabc123"),
            ("GATEWAY_SIGNING_KEY", "0xdef456"),
        ]
    }

    fn clear_all() {
        for (key, _) in full_env() {
            unsafe { env::remove_var(key) };
        }
        for key in [
            "CHAIN_ID",
            "QUOTE_VALIDITY_SECONDS",
            "CLOCK_SKEW_SECONDS",
            "SETTLER_BATCH_SIZE",
            "SETTLER_FLUSH_SECONDS",
            "DASHBOARD_ORIGIN",
        ] {
            unsafe { env::remove_var(key) };
        }
    }

    #[test]
    fn from_env_parses_a_full_env_map() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        for (key, value) in full_env() {
            unsafe { env::set_var(key, value) };
        }

        let cfg = Config::from_env().expect("full env should parse");

        assert_eq!(cfg.database_url, "postgres://postgres:postgres@localhost/tollgate");
        assert_eq!(cfg.redis_url, "redis://localhost:6379");
        assert_eq!(cfg.bind_addr, "0.0.0.0:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.chain_id, 84532);
        assert_eq!(cfg.quote_validity_seconds, 300);
        assert_eq!(cfg.clock_skew_seconds, 60);
        assert_eq!(cfg.settler_batch_size, 50);
        assert_eq!(cfg.settler_flush_seconds, 10);
        assert_eq!(cfg.dashboard_origin, "http://localhost:3000");

        clear_all();
    }

    #[test]
    fn from_env_missing_database_url_returns_named_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        for (key, value) in full_env() {
            if key != "DATABASE_URL" {
                unsafe { env::set_var(key, value) };
            }
        }

        let err = Config::from_env().expect_err("missing DATABASE_URL should error");
        assert!(matches!(err, Error::MissingEnvVar(ref var) if var == "DATABASE_URL"));

        clear_all();
    }
}
