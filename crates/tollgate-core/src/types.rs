use alloy::primitives::{Address, B256, U256};
use serde::{Deserialize, Deserializer};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Exact,
}

impl Scheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scheme::Exact => "exact",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "exact" => Ok(Scheme::Exact),
            other => Err(Error::UnsupportedScheme(other.to_string())),
        }
    }
}

impl<'de> Deserialize<'de> for Scheme {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Scheme::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub slug: String,
    pub upstream_url: String,
    pub price_wei: U256,
    pub max_price_wei: Option<U256>,
    pub scheme: Scheme,
    pub payout_address: Address,
    pub timeout_ms: i32,
}

/// One row of `capabilities`, written on a capability's first use (Task 5.4). The
/// capability is self-describing and signed, so there is no registration step: presenting it
/// is what records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRecord {
    pub hash: B256,
    pub issuer: Address,
    pub subject: Address,
    /// `None` for a root. The column is a self-referencing foreign key, so a root must store
    /// SQL NULL — the capability's own `parent` field is `0x0`, which is not a row and would
    /// fail the constraint.
    pub parent_hash: Option<B256>,
    pub depth: i32,
    pub max_total_wei: U256,
    pub max_per_req_wei: U256,
    /// `None` when the capability inherits its parent's allowlist (`allowlistHash == 0x0`).
    pub allowlist: Option<Vec<String>>,
    /// Unix seconds; stored as `TIMESTAMPTZ`.
    pub not_before: u64,
    pub expiry: u64,
    pub signature: Vec<u8>,
}

/// Parses a Postgres `NUMERIC` value (read back via a `::TEXT` cast) into a `U256`.
pub fn numeric_to_u256(s: &str) -> Result<U256> {
    U256::from_str_radix(s, 10).map_err(|e| Error::InvalidNumeric(e.to_string()))
}

/// Formats a `U256` for binding into a Postgres `NUMERIC` column (via a `::NUMERIC` cast).
pub fn u256_to_numeric(v: U256) -> String {
    v.to_string()
}

/// Decodes a Postgres `BYTEA` value into an `Address`. Fails unless it is exactly 20 bytes.
pub fn bytea_to_address(bytes: &[u8]) -> Result<Address> {
    if bytes.len() != 20 {
        return Err(Error::InvalidAddress(format!(
            "expected 20 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(Address::from_slice(bytes))
}

/// Formats an `Address` for binding into a Postgres `BYTEA` column.
pub fn address_to_bytea(address: &Address) -> &[u8] {
    address.as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_parses_exact_only() {
        assert_eq!(Scheme::parse("exact").unwrap(), Scheme::Exact);
        let err = Scheme::parse("upto").unwrap_err();
        assert!(matches!(err, Error::UnsupportedScheme(ref s) if s == "upto"));
    }

    #[test]
    fn u256_numeric_round_trip() {
        let value = U256::from(123_456_789_012_345_678u128);
        let text = u256_to_numeric(value);
        assert_eq!(numeric_to_u256(&text).unwrap(), value);
    }

    #[test]
    fn address_bytea_round_trip() {
        let address = Address::from_slice(&[0xab; 20]);
        let bytes = address_to_bytea(&address);
        assert_eq!(bytea_to_address(bytes).unwrap(), address);
    }
}
