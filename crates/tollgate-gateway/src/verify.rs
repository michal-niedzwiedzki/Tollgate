use alloy::primitives::{Address, Signature, U256};
use alloy::sol;
use alloy::sol_types::{eip712_domain, SolStruct};
use tollgate_core::Config;

use crate::x402::decode::PaymentPayload;
use crate::x402::{USDC_EIP712_NAME, USDC_EIP712_VERSION};

sol! {
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid signature encoding: {0}")]
    InvalidSignature(String),
    #[error("signature has a non-normalized (high-s) value")]
    HighS,
    #[error("signature recovery failed: {0}")]
    RecoveryFailed(String),
    #[error("recovered signer does not match authorization.from")]
    SignerMismatch,
}

/// Recovers the payer address from the `TransferWithAuthorization` EIP-712 typed data and
/// confirms it equals `authorization.from`. No side effects; a debug 200 body is built by the
/// caller.
pub fn recover_payer(payload: &PaymentPayload, cfg: &Config) -> Result<Address, VerifyError> {
    let usdc_address = cfg
        .usdc_address
        .parse::<Address>()
        .map_err(|e| VerifyError::InvalidConfig(e.to_string()))?;

    let domain = eip712_domain! {
        name: USDC_EIP712_NAME,
        version: USDC_EIP712_VERSION,
        chain_id: cfg.chain_id,
        verifying_contract: usdc_address,
    };

    let auth = &payload.payload.authorization;
    let typed = TransferWithAuthorization {
        from: auth.from,
        to: auth.to,
        value: auth.value,
        validAfter: U256::from(auth.valid_after),
        validBefore: U256::from(auth.valid_before),
        nonce: auth.nonce,
    };

    let signing_hash = typed.eip712_signing_hash(&domain);

    let signature = Signature::from_raw(&payload.payload.signature)
        .map_err(|e| VerifyError::InvalidSignature(e.to_string()))?;

    // Malleability guard (architecture.md §10): reject before spending a recovery on it.
    if signature.normalize_s().is_some() {
        return Err(VerifyError::HighS);
    }

    let recovered = signature
        .recover_address_from_prehash(&signing_hash)
        .map_err(|e| VerifyError::RecoveryFailed(e.to_string()))?;

    if recovered != auth.from {
        return Err(VerifyError::SignerMismatch);
    }

    Ok(recovered)
}

#[cfg(test)]
mod recover {
    use super::*;
    use alloy::primitives::B256;
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use std::str::FromStr;

    use crate::x402::decode::{Authorization, ExactEvmPayload};

    fn test_config() -> Config {
        Config {
            database_url: "postgres://postgres:postgres@localhost:5432/tollgate".to_string(),
            redis_url: "redis://localhost:6379".to_string(),
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            chain_id: 84532,
            rpc_url: "http://localhost:8545".to_string(),
            usdc_address: "0x0000000000000000000000000000000000000002".to_string(),
            batch_settler_address: "0x0000000000000000000000000000000000000001".to_string(),
            settler_private_key: "0xabc".to_string(),
            gateway_signing_key: "0xdef".to_string(),
            quote_validity_seconds: 300,
            clock_skew_seconds: 60,
            settler_batch_size: 50,
            settler_flush_seconds: 10,
            dashboard_origin: "http://localhost:3000".to_string(),
        }
    }

    fn signer_address(signing_key: &SigningKey) -> Address {
        Address::from_public_key(signing_key.verifying_key())
    }

    fn signed_payload(signing_key: &SigningKey, cfg: &Config, from: Address) -> PaymentPayload {
        let usdc_address = cfg.usdc_address.parse::<Address>().unwrap();
        let domain = eip712_domain! {
            name: USDC_EIP712_NAME,
            version: USDC_EIP712_VERSION,
            chain_id: cfg.chain_id,
            verifying_contract: usdc_address,
        };

        let typed = TransferWithAuthorization {
            from,
            to: Address::from_str("0x0101010101010101010101010101010101010101").unwrap(),
            value: U256::from(1000u64),
            validAfter: U256::from(0u64),
            validBefore: U256::from(9_999_999_999u64),
            nonce: B256::from_str(&format!("0x{}", "cd".repeat(32))).unwrap(),
        };

        let hash = typed.eip712_signing_hash(&domain);
        let (raw_sig, recid) = signing_key.sign_prehash_recoverable(hash.as_slice()).unwrap();
        let signature = Signature::from_signature_and_parity(raw_sig, recid.is_y_odd());

        PaymentPayload {
            x402_version: 1,
            scheme: "exact".to_string(),
            network: "eip155:84532".to_string(),
            payload: ExactEvmPayload {
                signature: signature.as_bytes().to_vec().into(),
                authorization: Authorization {
                    from: typed.from,
                    to: typed.to,
                    value: typed.value,
                    valid_after: 0,
                    valid_before: 9_999_999_999,
                    nonce: typed.nonce,
                },
            },
        }
    }

    #[test]
    fn recovers_the_expected_address() {
        let cfg = test_config();
        let signing_key = SigningKey::random(&mut OsRng);
        let from = signer_address(&signing_key);
        let payload = signed_payload(&signing_key, &cfg, from);

        let recovered = recover_payer(&payload, &cfg).expect("recovery should succeed");
        assert_eq!(recovered, from);
    }

    #[test]
    fn flipping_value_changes_recovered_address_and_fails_the_from_check() {
        let cfg = test_config();
        let signing_key = SigningKey::random(&mut OsRng);
        let from = signer_address(&signing_key);
        let mut payload = signed_payload(&signing_key, &cfg, from);

        // Tamper with `value` after signing without re-signing: the signature was made over the
        // original value, so this changes the effective signing hash and thus the recovered
        // address, which no longer equals `authorization.from`.
        payload.payload.authorization.value += U256::from(1u64);

        let err = recover_payer(&payload, &cfg).unwrap_err();
        assert_eq!(err, VerifyError::SignerMismatch);
    }

    /// The order of the secp256k1 curve, used to construct the high-s (malleable) counterpart
    /// of a signature for the rejection test below. Public knowledge, not a secret.
    const SECP256K1N_ORDER: &str =
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    #[test]
    fn high_s_signature_is_rejected_before_recovery() {
        let cfg = test_config();
        let signing_key = SigningKey::random(&mut OsRng);
        let from = signer_address(&signing_key);
        let mut payload = signed_payload(&signing_key, &cfg, from);

        let low_s_sig = Signature::from_raw(&payload.payload.signature).unwrap();
        assert!(
            low_s_sig.normalize_s().is_none(),
            "freshly generated ecdsa signatures should already be low-s"
        );

        let order = U256::from_str(SECP256K1N_ORDER).unwrap();
        let high_s = order - low_s_sig.s();
        let high_s_sig = Signature::new(low_s_sig.r(), high_s, !low_s_sig.v());

        payload.payload.signature = high_s_sig.as_bytes().to_vec().into();

        let err = recover_payer(&payload, &cfg).unwrap_err();
        assert_eq!(err, VerifyError::HighS);
    }
}

/// The cross-language check: a payment header produced by the Python client, verified here.
///
/// `mod recover` above signs with `alloy` and recovers with `alloy`, so it proves this file
/// is self-consistent and nothing more. An EIP-712 signature is over an encoding, and the
/// only way to know Python's encoding matches is to verify Python's bytes — which is what
/// this does.
///
/// The fixture is written by `client/tests/test_signing.py` and committed, and it is pulled
/// in with `include_str!` so a missing or unreadable one is a compile error rather than a
/// test that quietly passes by skipping.
#[cfg(test)]
mod python_vector {
    use super::*;
    use crate::x402::decode::decode_payment_header;

    const VECTOR: &str = include_str!("../tests/fixtures/payment_vector.json");

    /// Everything `recover_payer` reads is `chain_id` and `usdc_address`; both come from the
    /// fixture so the vector, not this file, decides what it was signed against.
    fn config_for(chain_id: u64, usdc_address: &str) -> Config {
        Config {
            database_url: "postgres://postgres:postgres@localhost:5432/tollgate".to_string(),
            redis_url: "redis://localhost:6379".to_string(),
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            chain_id,
            rpc_url: "http://localhost:8545".to_string(),
            usdc_address: usdc_address.to_string(),
            batch_settler_address: "0x0000000000000000000000000000000000000001".to_string(),
            settler_private_key: "0xabc".to_string(),
            gateway_signing_key: "0xdef".to_string(),
            quote_validity_seconds: 300,
            clock_skew_seconds: 60,
            settler_batch_size: 50,
            settler_flush_seconds: 10,
            dashboard_origin: "http://localhost:3000".to_string(),
        }
    }

    fn vector() -> serde_json::Value {
        serde_json::from_str(VECTOR).expect("payment vector should be valid JSON")
    }

    #[test]
    fn a_python_signed_header_decodes_and_recovers_the_expected_payer() {
        let vector = vector();
        let cfg = config_for(
            vector["chainId"].as_u64().expect("chainId"),
            vector["usdcAddress"].as_str().expect("usdcAddress"),
        );
        let expected: Address = vector["expectedPayer"]
            .as_str()
            .expect("expectedPayer")
            .parse()
            .expect("expectedPayer should be an address");

        let payload = decode_payment_header(vector["header"].as_str().expect("header"))
            .expect("the python header should decode");

        let recovered = recover_payer(&payload, &cfg).expect("the python signature should verify");
        assert_eq!(
            recovered, expected,
            "python and rust disagree on the TransferWithAuthorization encoding"
        );
    }

    #[test]
    fn the_decoded_header_carries_the_fields_python_signed() {
        let vector = vector();
        let payload = decode_payment_header(vector["header"].as_str().expect("header"))
            .expect("the python header should decode");
        let signed = &vector["payload"]["payload"]["authorization"];
        let auth = &payload.payload.authorization;

        assert_eq!(payload.scheme, "exact");
        assert_eq!(payload.network, "eip155:84532");
        assert_eq!(auth.value.to_string(), signed["value"].as_str().unwrap());
        assert_eq!(
            auth.valid_before.to_string(),
            signed["validBefore"].as_str().unwrap()
        );
        assert_eq!(
            format!("{:#x}", auth.nonce),
            signed["nonce"].as_str().unwrap()
        );
    }

    /// The negative half. Recovery that succeeds against the wrong domain would mean the
    /// domain is not actually binding, and a payment signed for one token or one chain would
    /// be replayable against another (`architecture.md` §10, cross-chain replay).
    #[test]
    fn the_same_header_fails_against_a_different_verifying_contract() {
        let vector = vector();
        let cfg = config_for(
            vector["chainId"].as_u64().expect("chainId"),
            "0x0000000000000000000000000000000000000002",
        );

        let payload = decode_payment_header(vector["header"].as_str().expect("header"))
            .expect("the python header should decode");

        assert_eq!(
            recover_payer(&payload, &cfg).unwrap_err(),
            VerifyError::SignerMismatch
        );
    }
}
