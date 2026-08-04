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

/// Decoding the `X-PAYMENT` header into a typed payload. Decode only, no crypto.
/// Wired into the proxy route in Task 2.3, so its public items are unused until then.
#[allow(dead_code)]
pub mod decode {
    use alloy::primitives::{Address, Bytes, B256, U256};
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde::Deserialize;

    /// The only network this MVP accepts payments on (locked decision: Base Sepolia, one chain).
    const SUPPORTED_NETWORK: &str = "eip155:84532";
    const SUPPORTED_SCHEME: &str = "exact";

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum X402Error {
        #[error("invalid base64 in X-PAYMENT header: {0}")]
        InvalidBase64(String),
        #[error("invalid JSON in X-PAYMENT payload: {0}")]
        InvalidJson(String),
        #[error("unsupported payment scheme: {0}")]
        UnknownScheme(String),
        #[error("unsupported network: {0}")]
        UnknownNetwork(String),
        #[error("malformed field {field}: {message}")]
        MalformedField { field: String, message: String },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PaymentPayload {
        pub x402_version: u32,
        pub scheme: String,
        pub network: String,
        pub payload: ExactEvmPayload,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ExactEvmPayload {
        pub signature: Bytes,
        pub authorization: Authorization,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Authorization {
        pub from: Address,
        pub to: Address,
        pub value: U256,
        pub valid_after: u64,
        pub valid_before: u64,
        pub nonce: B256,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawPaymentPayload {
        x402_version: u32,
        scheme: String,
        network: String,
        payload: RawExactEvmPayload,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawExactEvmPayload {
        signature: String,
        authorization: RawAuthorization,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawAuthorization {
        from: String,
        to: String,
        value: String,
        valid_after: u64,
        valid_before: u64,
        nonce: String,
    }

    fn parse_field<T>(field: &str, value: &str) -> Result<T, X402Error>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        value.parse::<T>().map_err(|e| X402Error::MalformedField {
            field: field.to_string(),
            message: e.to_string(),
        })
    }

    /// Base64-decodes and JSON-parses the `X-PAYMENT` header value into a typed payload. No
    /// signature verification happens here; that is Task 2.4.
    pub fn decode_payment_header(header: &str) -> Result<PaymentPayload, X402Error> {
        let decoded = BASE64
            .decode(header)
            .map_err(|e| X402Error::InvalidBase64(e.to_string()))?;

        let raw: RawPaymentPayload = serde_json::from_slice(&decoded)
            .map_err(|e| X402Error::InvalidJson(e.to_string()))?;

        if raw.scheme != SUPPORTED_SCHEME {
            return Err(X402Error::UnknownScheme(raw.scheme));
        }
        if raw.network != SUPPORTED_NETWORK {
            return Err(X402Error::UnknownNetwork(raw.network));
        }

        let signature = parse_field::<Bytes>("payload.signature", &raw.payload.signature)?;
        let from = parse_field::<Address>(
            "payload.authorization.from",
            &raw.payload.authorization.from,
        )?;
        let to = parse_field::<Address>("payload.authorization.to", &raw.payload.authorization.to)?;
        let value = parse_field::<U256>(
            "payload.authorization.value",
            &raw.payload.authorization.value,
        )?;
        let nonce = parse_field::<B256>(
            "payload.authorization.nonce",
            &raw.payload.authorization.nonce,
        )?;

        Ok(PaymentPayload {
            x402_version: raw.x402_version,
            scheme: raw.scheme,
            network: raw.network,
            payload: ExactEvmPayload {
                signature,
                authorization: Authorization {
                    from,
                    to,
                    value,
                    valid_after: raw.payload.authorization.valid_after,
                    valid_before: raw.payload.authorization.valid_before,
                    nonce,
                },
            },
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::str::FromStr;

        fn valid_json() -> serde_json::Value {
            serde_json::json!({
                "x402Version": 1,
                "scheme": "exact",
                "network": "eip155:84532",
                "payload": {
                    "signature": format!("0x{}", "ab".repeat(65)),
                    "authorization": {
                        "from": "0x0101010101010101010101010101010101010101",
                        "to": "0x0202020202020202020202020202020202020202",
                        "value": "1000",
                        "validAfter": 0,
                        "validBefore": 9_999_999_999u64,
                        "nonce": format!("0x{}", "cd".repeat(32)),
                    }
                }
            })
        }

        fn encode(value: &serde_json::Value) -> String {
            BASE64.encode(serde_json::to_vec(value).unwrap())
        }

        #[test]
        fn valid_payload_decodes_with_every_field() {
            let header = encode(&valid_json());
            let payload = decode_payment_header(&header).expect("valid payload should decode");

            assert_eq!(payload.x402_version, 1);
            assert_eq!(payload.scheme, "exact");
            assert_eq!(payload.network, "eip155:84532");
            assert_eq!(
                payload.payload.signature,
                Bytes::from_str(&format!("0x{}", "ab".repeat(65))).unwrap()
            );
            assert_eq!(
                payload.payload.authorization.from,
                Address::from_str("0x0101010101010101010101010101010101010101").unwrap()
            );
            assert_eq!(
                payload.payload.authorization.to,
                Address::from_str("0x0202020202020202020202020202020202020202").unwrap()
            );
            assert_eq!(payload.payload.authorization.value, U256::from(1000u64));
            assert_eq!(payload.payload.authorization.valid_after, 0);
            assert_eq!(payload.payload.authorization.valid_before, 9_999_999_999u64);
            assert_eq!(
                payload.payload.authorization.nonce,
                B256::from_str(&format!("0x{}", "cd".repeat(32))).unwrap()
            );
        }

        #[test]
        fn truncated_base64_is_rejected() {
            let err = decode_payment_header("not-valid-base64!!!").unwrap_err();
            assert!(matches!(err, X402Error::InvalidBase64(_)));
        }

        #[test]
        fn non_json_body_is_rejected() {
            let header = BASE64.encode(b"this is not json");
            let err = decode_payment_header(&header).unwrap_err();
            assert!(matches!(err, X402Error::InvalidJson(_)));
        }

        #[test]
        fn unknown_scheme_is_rejected() {
            let mut json = valid_json();
            json["scheme"] = serde_json::Value::String("upto".to_string());
            let err = decode_payment_header(&encode(&json)).unwrap_err();
            assert_eq!(err, X402Error::UnknownScheme("upto".to_string()));
        }

        #[test]
        fn unknown_network_is_rejected() {
            let mut json = valid_json();
            json["network"] = serde_json::Value::String("eip155:1".to_string());
            let err = decode_payment_header(&encode(&json)).unwrap_err();
            assert_eq!(err, X402Error::UnknownNetwork("eip155:1".to_string()));
        }

        #[test]
        fn thirty_one_byte_nonce_is_rejected() {
            let mut json = valid_json();
            json["payload"]["authorization"]["nonce"] =
                serde_json::Value::String(format!("0x{}", "cd".repeat(31)));
            let err = decode_payment_header(&encode(&json)).unwrap_err();
            assert!(matches!(err, X402Error::MalformedField { field, .. } if field == "payload.authorization.nonce"));
        }
    }
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
