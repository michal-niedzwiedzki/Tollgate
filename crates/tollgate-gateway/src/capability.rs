//! The EIP-712 capability: the struct from architecture.md §5.1, its hash, and issuer
//! recovery. Task 5.1.
//!
//! Two different hashes come out of this module and they are not interchangeable:
//!
//! - the **struct hash** (`struct_hash`) is a capability's *identity*. It is what
//!   `capabilities.hash` stores, what `tg:cap:{hash}:*` is keyed by, and what a child's
//!   `parent` field points at (architecture.md §5.2 rule 3). It carries no domain, so it
//!   is stable regardless of chain.
//! - the **signing hash** (private, used only by `recover_issuer`) is the EIP-712 digest
//!   the issuer actually signed, domain included.
//!
//! Mixing them up would make `parent` chain-dependent and break every delegation across a
//! chain-id change, so only the first is public.

use alloy::primitives::{keccak256, Address, Signature, B256};
use alloy::sol;
use alloy::sol_types::{eip712_domain, Eip712Domain, SolStruct};

sol! {
    /// architecture.md §5.1, verbatim. **Field order is part of the EIP-712 type hash**, so
    /// reordering these lines silently changes every capability's identity and invalidates
    /// every signature ever issued. The golden tests below pin both the encoded type string
    /// and a known struct hash precisely so that a reorder cannot pass unnoticed.
    #[derive(Debug)]
    struct Capability {
        address issuer;          // who is granting
        address subject;         // who may spend
        bytes32 parent;          // struct hash of the parent capability, 0x0 for a root
        uint256 maxTotal;        // cumulative ceiling, in token base units
        uint256 maxPerRequest;
        bytes32 allowlistHash;   // keccak of the sorted provider-slug list, 0x0 = inherit
        uint64  notBefore;
        uint64  expiry;
        uint32  maxDepth;        // how many further links may be issued below this one
        bytes32 salt;
    }
}

/// The EIP-712 domain a capability is signed under. Distinct from the USDC domain in
/// `verify.rs`: that one is Circle's and is fixed by the token contract, this one is
/// Tollgate's own.
pub const CAPABILITY_EIP712_NAME: &str = "Tollgate";
pub const CAPABILITY_EIP712_VERSION: &str = "1";

/// `chainId` is the cross-chain replay guard (architecture.md §10): the same capability
/// signed for Base Sepolia cannot be presented to a gateway on another chain.
///
/// There is deliberately **no `verifyingContract`**. A capability is never verified
/// on-chain by any contract — the gateway is the sole enforcement point (architecture.md
/// §5.2) — so naming a contract that will never see it would be a lie in the domain
/// separator.
pub fn domain(chain_id: u64) -> Eip712Domain {
    eip712_domain! {
        name: CAPABILITY_EIP712_NAME,
        version: CAPABILITY_EIP712_VERSION,
        chain_id: chain_id,
    }
}

/// `keccak256` of the provider slugs sorted lexicographically and joined with `\n`
/// (plan.md assumption A9: a plain sorted-list hash, not a merkle root, for a first build).
///
/// Sorting here is what makes the hash order-independent, so an issuer and a presenter who
/// list the same slugs in different orders still agree.
///
/// This never returns `0x0` for any input, including the empty slice — `keccak256("")` is
/// an ordinary value. That matters: `allowlistHash == 0x0` means *inherit the parent's
/// allowlist*, which is a different thing from an empty allowlist that permits nothing.
/// Callers wanting "inherit" write `B256::ZERO` themselves rather than hashing nothing.
pub fn allowlist_hash(slugs: &[String]) -> B256 {
    let mut sorted: Vec<&str> = slugs.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    keccak256(sorted.join("\n").as_bytes())
}

/// A capability's identity: its EIP-712 `hashStruct`, with no domain mixed in. See the
/// module comment for why this and the signing hash are kept apart.
pub fn struct_hash(capability: &Capability) -> B256 {
    capability.eip712_hash_struct()
}

/// The digest the issuer signs. Private: nothing outside this module has a use for it that
/// `recover_issuer` does not already serve, and exposing it invites it being stored as an
/// identity by mistake.
fn signing_hash(capability: &Capability, chain_id: u64) -> B256 {
    capability.eip712_signing_hash(&domain(chain_id))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("invalid signature encoding: {0}")]
    InvalidSignature(String),
    #[error("signature recovery failed: {0}")]
    RecoveryFailed(String),
}

/// Recovers the address that signed `capability`. Deliberately does **not** compare the
/// result against `capability.issuer`: that comparison is architecture.md §5.2 rule 2 and
/// belongs to the chain walk in Task 5.3, which needs to report it as its own named
/// failure. This function stays a pure "who signed this".
pub fn recover_issuer(
    capability: &Capability,
    signature: &[u8],
    chain_id: u64,
) -> Result<Address, CapabilityError> {
    let signature =
        Signature::from_raw(signature).map_err(|e| CapabilityError::InvalidSignature(e.to_string()))?;

    signature
        .recover_address_from_prehash(&signing_hash(capability, chain_id))
        .map_err(|e| CapabilityError::RecoveryFailed(e.to_string()))
}

#[cfg(test)]
mod hash {
    use super::*;
    use alloy::primitives::U256;
    use k256::ecdsa::SigningKey;
    use serde_json::{json, Value};
    use std::str::FromStr;

    const CHAIN_ID: u64 = 84532;

    /// Fixed, not random. The fixture below is a cross-language test vector for the Python
    /// reimplementation in Phase 8 (Task 5.1: "both implementations test against the same
    /// vectors"), so it has to be byte-identical on every run — a random key would make it
    /// churn on every `cargo test` and prove nothing.
    ///
    /// Test keys, published on purpose. They control no funds anywhere.
    const SUPERVISOR_KEY: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const LEAD_KEY: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
    const WORKER_KEY: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
    const TOOL_KEY: &str = "0x4444444444444444444444444444444444444444444444444444444444444444";

    fn key(hex: &str) -> SigningKey {
        let bytes = B256::from_str(hex).expect("test key should be 32 bytes of hex");
        SigningKey::from_slice(bytes.as_slice()).expect("test key should be a valid scalar")
    }

    fn address_of(signing_key: &SigningKey) -> Address {
        Address::from_public_key(signing_key.verifying_key())
    }

    fn sign(capability: &Capability, signing_key: &SigningKey) -> Vec<u8> {
        let hash = signing_hash(capability, CHAIN_ID);
        let (raw, recid) = signing_key
            .sign_prehash_recoverable(hash.as_slice())
            .expect("signing a 32-byte prehash should succeed");
        Signature::from_signature_and_parity(raw, recid.is_y_odd())
            .as_bytes()
            .to_vec()
    }

    fn salt(byte: u8) -> B256 {
        B256::from([byte; 32])
    }

    /// The known capability the golden test pins. Every field is non-zero and distinct so
    /// that a field-order change moves the hash rather than coincidentally preserving it.
    fn known_capability() -> Capability {
        Capability {
            issuer: address_of(&key(SUPERVISOR_KEY)),
            subject: address_of(&key(LEAD_KEY)),
            parent: B256::ZERO,
            maxTotal: U256::from(1_000_000u64),
            maxPerRequest: U256::from(50_000u64),
            allowlistHash: allowlist_hash(&["geocode".to_string(), "weather".to_string()]),
            notBefore: 1_700_000_000,
            expiry: 1_800_000_000,
            maxDepth: 3,
            salt: salt(0x01),
        }
    }

    /// The EIP-712 encoded type string, spelled out. This is the independent half of the
    /// golden test: the pinned hash below proves the value has not moved, and this proves
    /// the value was right to begin with, which a self-generated hash alone cannot.
    const ENCODED_TYPE: &str = "Capability(address issuer,address subject,bytes32 parent,\
uint256 maxTotal,uint256 maxPerRequest,bytes32 allowlistHash,uint64 notBefore,uint64 expiry,\
uint32 maxDepth,bytes32 salt)";

    #[test]
    fn the_encoded_type_matches_the_architecture_field_order() {
        let capability = known_capability();
        assert_eq!(
            Capability::eip712_encode_type(),
            ENCODED_TYPE,
            "field order is part of the type hash; architecture.md §5.1 fixes it"
        );
        assert_eq!(
            capability.eip712_type_hash(),
            keccak256(ENCODED_TYPE.as_bytes()),
            "the type hash must be keccak of exactly that string"
        );
    }

    /// Golden. A change to field order, field types, or the struct name breaks this.
    #[test]
    fn a_known_capability_hashes_to_a_fixed_value() {
        let expected =
            B256::from_str("0x225b90797b53a7b6623b4563dd7689e37c602835aa676d8ca39fb893f3a39634")
                .expect("expected hash should parse");
        assert_eq!(struct_hash(&known_capability()), expected);
    }

    #[test]
    fn changing_max_total_by_one_changes_the_hash() {
        let base = known_capability();
        let mut bumped = known_capability();
        bumped.maxTotal += U256::from(1u64);

        assert_ne!(
            struct_hash(&base),
            struct_hash(&bumped),
            "identity must be sensitive to every field, or a capability could be inflated \
             after signing without changing what it is"
        );
    }

    #[test]
    fn allowlist_hash_is_order_independent() {
        let ab = allowlist_hash(&["a".to_string(), "b".to_string()]);
        let ba = allowlist_hash(&["b".to_string(), "a".to_string()]);
        assert_eq!(ab, ba, "sorting is what makes issuer and presenter agree");

        assert_ne!(
            ab,
            allowlist_hash(&["a".to_string()]),
            "a different slug set must be a different hash"
        );
        assert_ne!(
            allowlist_hash(&[]),
            B256::ZERO,
            "an empty allowlist must not collide with 0x0, which means inherit"
        );
    }

    #[test]
    fn recover_issuer_returns_the_signer() {
        let signing_key = key(SUPERVISOR_KEY);
        let capability = known_capability();
        let signature = sign(&capability, &signing_key);

        let recovered = recover_issuer(&capability, &signature, CHAIN_ID)
            .expect("a well-formed signature should recover");
        assert_eq!(recovered, address_of(&signing_key));
    }

    #[test]
    fn recovery_is_bound_to_the_chain_id() {
        let signing_key = key(SUPERVISOR_KEY);
        let capability = known_capability();
        let signature = sign(&capability, &signing_key);

        // architecture.md §10, cross-chain replay: the same bytes presented to a gateway on
        // another chain recover to somebody else, so the issuer check in Task 5.3 fails.
        let elsewhere = recover_issuer(&capability, &signature, 1)
            .expect("recovery itself still succeeds; it just yields a different address");
        assert_ne!(elsewhere, address_of(&signing_key));
    }

    #[test]
    fn a_malformed_signature_is_a_named_error() {
        let err = recover_issuer(&known_capability(), &[0u8; 10], CHAIN_ID)
            .expect_err("a 10-byte signature is not recoverable");
        assert!(matches!(err, CapabilityError::InvalidSignature(_)));
    }

    /// Writes `tests/fixtures/capability_vectors.json`: three signed capabilities forming a
    /// valid attenuating 3-link chain, with their hashes. Task 5.1 requires the file so the
    /// Phase 8 Python reimplementation of this domain and hashing can be tested against the
    /// same vectors rather than against itself.
    ///
    /// The chain attenuates on every axis at every link (maxTotal, maxPerRequest, expiry,
    /// maxDepth, allowlist), so Task 5.3 can also use it directly as its "fully valid
    /// 3-link chain that passes" case.
    #[test]
    fn the_fixture_file_is_written_and_readable() {
        let supervisor = key(SUPERVISOR_KEY);
        let lead = key(LEAD_KEY);
        let worker = key(WORKER_KEY);
        let tool = key(TOOL_KEY);

        let wide = vec!["geocode".to_string(), "weather".to_string()];
        let narrow = vec!["geocode".to_string()];

        let root = known_capability();

        let middle = Capability {
            issuer: address_of(&lead),
            subject: address_of(&worker),
            parent: struct_hash(&root),
            maxTotal: U256::from(500_000u64),
            maxPerRequest: U256::from(50_000u64),
            allowlistHash: allowlist_hash(&wide),
            notBefore: 1_700_000_000,
            expiry: 1_800_000_000,
            maxDepth: 2,
            salt: salt(0x02),
        };

        let leaf = Capability {
            issuer: address_of(&worker),
            subject: address_of(&tool),
            parent: struct_hash(&middle),
            maxTotal: U256::from(250_000u64),
            maxPerRequest: U256::from(25_000u64),
            allowlistHash: allowlist_hash(&narrow),
            notBefore: 1_700_000_000,
            expiry: 1_750_000_000,
            maxDepth: 1,
            salt: salt(0x03),
        };

        let links = [
            ("root: supervisor delegates to team lead", &root, &supervisor, &wide),
            ("middle: team lead delegates to worker", &middle, &lead, &wide),
            ("leaf: worker delegates to tool", &leaf, &worker, &narrow),
        ];

        let capabilities: Vec<Value> = links
            .iter()
            .map(|(label, capability, signer, allowlist)| {
                json!({
                    "label": label,
                    "signerPrivateKey": format!("0x{}", hex_of(&signer.to_bytes())),
                    "capability": {
                        "issuer": capability.issuer.to_string(),
                        "subject": capability.subject.to_string(),
                        "parent": capability.parent.to_string(),
                        "maxTotal": capability.maxTotal.to_string(),
                        "maxPerRequest": capability.maxPerRequest.to_string(),
                        "allowlistHash": capability.allowlistHash.to_string(),
                        "notBefore": capability.notBefore,
                        "expiry": capability.expiry,
                        "maxDepth": capability.maxDepth,
                        "salt": capability.salt.to_string(),
                    },
                    "allowlist": allowlist,
                    "structHash": struct_hash(capability).to_string(),
                    "signingHash": signing_hash(capability, CHAIN_ID).to_string(),
                    "signature": format!("0x{}", hex_of(&sign(capability, signer))),
                })
            })
            .collect();

        let fixture = json!({
            "_comment": "Generated by tollgate-gateway's capability::hash::the_fixture_file_is_written_and_readable. \
Cross-language test vectors: the Phase 8 Python client reimplements this domain and hashing and must \
reproduce every structHash, signingHash and signature here. The private keys are test-only and control \
no funds. Root first; the chain attenuates on every axis at every link.",
            "domain": {
                "name": CAPABILITY_EIP712_NAME,
                "version": CAPABILITY_EIP712_VERSION,
                "chainId": CHAIN_ID,
            },
            "encodedType": ENCODED_TYPE,
            "capabilities": capabilities,
        });

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/capability_vectors.json");
        let serialised = format!(
            "{}\n",
            serde_json::to_string_pretty(&fixture).expect("fixture should serialise")
        );
        std::fs::write(&path, &serialised).expect("fixture should be writable");

        // Readable, and round-trips to the same value it was written from.
        let read_back: Value = serde_json::from_str(
            &std::fs::read_to_string(&path).expect("fixture should be readable"),
        )
        .expect("fixture should be valid json");
        assert_eq!(read_back, fixture);

        // The vectors have to be self-consistent or they are worse than no vectors: a
        // Python port matching a broken fixture would look correct and be wrong.
        assert_eq!(read_back["capabilities"].as_array().unwrap().len(), 3);
        for (link, (_, capability, signer, _)) in links.iter().enumerate() {
            let recorded = &read_back["capabilities"][link];
            let signature = B256::from_str(recorded["structHash"].as_str().unwrap())
                .expect("recorded struct hash should parse");
            assert_eq!(signature, struct_hash(capability), "link {link} struct hash");

            let bytes = hex_bytes(recorded["signature"].as_str().unwrap());
            assert_eq!(
                recover_issuer(capability, &bytes, CHAIN_ID).unwrap(),
                address_of(signer),
                "link {link} signature must recover to its declared issuer"
            );
        }
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }
}
