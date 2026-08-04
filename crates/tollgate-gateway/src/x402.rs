use serde::Serialize;
use serde_json::{json, Value};
use tollgate_core::Provider;

/// EIP-712 domain fields USDC's `TransferWithAuthorization` is signed under. Native USDC on
/// Base Sepolia is the only asset in scope for this MVP (`plan.md` locked decision #3), so this
/// is a constant rather than sourced from provider config.
pub const USDC_EIP712_NAME: &str = "USDC";
pub const USDC_EIP712_VERSION: &str = "2";

#[derive(Debug, Serialize)]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    #[serde(rename = "maxAmountRequired")]
    pub max_amount_required: String,
    pub asset: String,
    #[serde(rename = "payTo")]
    pub pay_to: String,
    pub resource: String,
    pub description: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    #[serde(rename = "maxTimeoutSeconds")]
    pub max_timeout_seconds: u64,
    pub extra: Value,
}

#[derive(Debug, Serialize)]
pub struct PaymentRequiredBody {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub accepts: Vec<PaymentRequirements>,
    pub error: String,
}

/// Builds the 402 body for a request against `provider`, priced in the provider's configured
/// asset. `network` is the CAIP-2 identifier for the configured chain (e.g. `eip155:84532`).
pub fn payment_required_body(
    provider: &Provider,
    usdc_address: &str,
    network: &str,
    resource: &str,
    max_timeout_seconds: u64,
    error: impl Into<String>,
) -> PaymentRequiredBody {
    let requirements = PaymentRequirements {
        scheme: provider.scheme.as_str().to_string(),
        network: network.to_string(),
        max_amount_required: provider.price_wei.to_string(),
        asset: usdc_address.to_string(),
        pay_to: provider.payout_address.to_string(),
        resource: resource.to_string(),
        description: String::new(),
        mime_type: String::new(),
        max_timeout_seconds,
        extra: json!({
            "name": USDC_EIP712_NAME,
            "version": USDC_EIP712_VERSION,
        }),
    };

    PaymentRequiredBody {
        x402_version: 1,
        accepts: vec![requirements],
        error: error.into(),
    }
}

/// The CAIP-2 network identifier for an EVM chain id.
pub fn caip2_network(chain_id: u64) -> String {
    format!("eip155:{chain_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256};
    use tollgate_core::Scheme;

    fn test_provider() -> Provider {
        Provider {
            slug: "mock-ok".to_string(),
            upstream_url: "http://127.0.0.1:9000".to_string(),
            price_wei: U256::from(1000u64),
            max_price_wei: None,
            scheme: Scheme::Exact,
            payout_address: Address::from_slice(&[0x01; 20]),
            timeout_ms: 5000,
        }
    }

    #[test]
    fn caip2_network_formats_chain_id() {
        assert_eq!(caip2_network(84532), "eip155:84532");
    }

    #[test]
    fn requirements_serialisation() {
        let provider = test_provider();
        let body = payment_required_body(
            &provider,
            "0x0000000000000000000000000000000000000002",
            &caip2_network(84532),
            "http://localhost:8080/v1/proxy/mock-ok/ok",
            300,
            "payment required",
        );

        let value = serde_json::to_value(&body).unwrap();
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/x402_402_response.json"
        ))
        .unwrap();

        assert_eq!(value, fixture);
    }
}
