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

/// Decoding the `X-Tollgate-Capability` header into an ordered chain. Task 5.2.
///
/// Decode only: nothing here recovers a signature, checks an expiry, or compares a link
/// against its parent. That is the chain walk in Task 5.3. The one security-relevant thing
/// this module does is the depth guard, which is a denial-of-service control and therefore
/// has to run before any per-link work at all — see `decode_capability_chain`.
pub mod decode {
    use super::{allowlist_hash, Capability};
    use alloy::primitives::{Address, Bytes, B256, U256};
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde::Deserialize;
    use serde_json::Value;

    /// architecture.md §5.2 rule 1. Four links total, not four plus a funding root: under
    /// Resolution A (§5.3) the parent funds the child wallet on-chain up front, so the chain
    /// is pure policy and link 0's issuer *is* the funding wallet. There is no separate
    /// root level to count.
    pub const MAX_CHAIN_DEPTH: usize = 4;

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum ChainDecodeError {
        #[error("invalid base64 in X-Tollgate-Capability header: {0}")]
        InvalidBase64(String),
        #[error("invalid JSON in capability chain: {0}")]
        InvalidJson(String),
        #[error("capability chain is empty")]
        EmptyChain,
        #[error("capability chain depth {depth} exceeds the maximum of {max}", max = MAX_CHAIN_DEPTH)]
        DepthExceeded { depth: usize },
        #[error("malformed link {index}: field {field}: {message}")]
        MalformedLink {
            index: usize,
            field: String,
            message: String,
        },
        #[error("link {index} declares an allowlist that does not hash to its allowlistHash")]
        AllowlistMismatch { index: usize },
        #[error("link {index} sets allowlistHash but presents no plaintext allowlist")]
        AllowlistMissing { index: usize },
    }

    /// One decoded link. The plaintext `allowlist` rides along because `allowlistHash` is a
    /// one-way hash: Task 5.3's subset check (§5.2 rule 4) needs the slugs themselves, and
    /// the presenter is the only party that has them.
    #[derive(Debug, Clone)]
    pub struct ChainLink {
        pub capability: Capability,
        pub signature: Bytes,
        /// Empty exactly when `allowlistHash` is `0x0`, meaning inherit from the parent.
        pub allowlist: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct RawChainLink {
        capability: RawCapability,
        signature: String,
        #[serde(default)]
        allowlist: Vec<String>,
    }

    /// Numeric limits arrive as decimal strings because `maxTotal` and `maxPerRequest` are
    /// `uint256` and do not survive a JSON number. The small unsigned fields are ordinary
    /// JSON numbers. Unknown fields are ignored, so the Task 5.1 vector file's extra keys
    /// (`label`, `structHash`, …) can be presented verbatim as a chain.
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RawCapability {
        issuer: String,
        subject: String,
        parent: String,
        max_total: String,
        max_per_request: String,
        allowlist_hash: String,
        not_before: u64,
        expiry: u64,
        max_depth: u32,
        salt: String,
    }

    /// Base64-decodes and JSON-parses the `X-Tollgate-Capability` header into an ordered
    /// chain, root first.
    ///
    /// **The depth guard runs before any per-link parsing.** architecture.md §5.2 rule 1
    /// calls for rejecting deeper chains "before doing any signature work", and the cheapest
    /// way to guarantee that is to not look inside the links at all: the payload is parsed
    /// only as far as a JSON array, counted, and rejected. An attacker cannot make this
    /// gateway do per-link work by sending a hundred links.
    pub fn decode_capability_chain(header: &str) -> Result<Vec<ChainLink>, ChainDecodeError> {
        let decoded = BASE64
            .decode(header)
            .map_err(|e| ChainDecodeError::InvalidBase64(e.to_string()))?;

        let raw: Vec<Value> = serde_json::from_slice(&decoded)
            .map_err(|e| ChainDecodeError::InvalidJson(e.to_string()))?;

        if raw.is_empty() {
            return Err(ChainDecodeError::EmptyChain);
        }
        if raw.len() > MAX_CHAIN_DEPTH {
            return Err(ChainDecodeError::DepthExceeded { depth: raw.len() });
        }

        raw.into_iter()
            .enumerate()
            .map(|(index, value)| parse_link(index, value))
            .collect()
    }

    fn parse_link(index: usize, value: Value) -> Result<ChainLink, ChainDecodeError> {
        let raw: RawChainLink =
            serde_json::from_value(value).map_err(|e| ChainDecodeError::MalformedLink {
                index,
                field: "link".to_string(),
                message: e.to_string(),
            })?;

        let field = |name: &str, message: String| ChainDecodeError::MalformedLink {
            index,
            field: name.to_string(),
            message,
        };

        let parse_address = |name: &str, raw: &str| {
            raw.parse::<Address>()
                .map_err(|e| field(name, e.to_string()))
        };
        let parse_b256 = |name: &str, raw: &str| {
            raw.parse::<B256>().map_err(|e| field(name, e.to_string()))
        };
        let parse_u256 = |name: &str, raw: &str| {
            U256::from_str_radix(raw, 10).map_err(|e| field(name, e.to_string()))
        };

        let capability = Capability {
            issuer: parse_address("issuer", &raw.capability.issuer)?,
            subject: parse_address("subject", &raw.capability.subject)?,
            parent: parse_b256("parent", &raw.capability.parent)?,
            maxTotal: parse_u256("maxTotal", &raw.capability.max_total)?,
            maxPerRequest: parse_u256("maxPerRequest", &raw.capability.max_per_request)?,
            allowlistHash: parse_b256("allowlistHash", &raw.capability.allowlist_hash)?,
            notBefore: raw.capability.not_before,
            expiry: raw.capability.expiry,
            maxDepth: raw.capability.max_depth,
            salt: parse_b256("salt", &raw.capability.salt)?,
        };

        let signature: Bytes = raw
            .signature
            .parse()
            .map_err(|e: alloy::hex::FromHexError| field("signature", e.to_string()))?;

        // The declared allowlist must actually be the one that was signed. Without this the
        // plaintext list would be attacker-controlled free text and the hash inside the
        // signed capability would constrain nothing.
        if capability.allowlistHash == B256::ZERO {
            // 0x0 means inherit from the parent, so there is nothing to present. A link
            // that ships slugs anyway is contradicting its own signed field.
            if !raw.allowlist.is_empty() {
                return Err(ChainDecodeError::AllowlistMismatch { index });
            }
        } else {
            if raw.allowlist.is_empty() {
                return Err(ChainDecodeError::AllowlistMissing { index });
            }
            if allowlist_hash(&raw.allowlist) != capability.allowlistHash {
                return Err(ChainDecodeError::AllowlistMismatch { index });
            }
        }

        Ok(ChainLink {
            capability,
            signature,
            allowlist: raw.allowlist,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;

        const VECTORS: &str = include_str!("../tests/fixtures/capability_vectors.json");

        /// The Task 5.1 vector file's links, used verbatim as wire links. That the fixture
        /// needs no reshaping to be presented as a header is the point: the shape a
        /// supervisor signs is the shape a worker sends.
        fn fixture_links() -> Vec<Value> {
            let vectors: Value = serde_json::from_str(VECTORS).expect("fixture should parse");
            vectors["capabilities"]
                .as_array()
                .expect("fixture should hold a capabilities array")
                .clone()
        }

        fn encode(links: &Value) -> String {
            BASE64.encode(serde_json::to_vec(links).expect("links should serialise"))
        }

        #[test]
        fn a_valid_three_link_chain_decodes_root_first() {
            let links = fixture_links();
            let chain = decode_capability_chain(&encode(&json!(links)))
                .expect("the fixture chain should decode");

            assert_eq!(chain.len(), 3);

            // Root first, and provably so: each link's parent is the previous link's struct
            // hash, which only holds in this order.
            assert_eq!(chain[0].capability.parent, B256::ZERO, "link 0 is the root");
            assert_eq!(
                chain[1].capability.parent,
                super::super::struct_hash(&chain[0].capability),
                "link 1 must point at link 0"
            );
            assert_eq!(
                chain[2].capability.parent,
                super::super::struct_hash(&chain[1].capability),
                "link 2 must point at link 1"
            );

            // Delegation runs issuer -> subject -> issuer down the chain.
            assert_eq!(chain[1].capability.issuer, chain[0].capability.subject);
            assert_eq!(chain[2].capability.issuer, chain[1].capability.subject);

            assert_eq!(chain[0].allowlist, vec!["geocode", "weather"]);
            assert_eq!(chain[2].allowlist, vec!["geocode"]);
            assert_eq!(chain[0].signature.len(), 65, "a 65-byte ecdsa signature");
        }

        #[test]
        fn a_five_link_chain_is_rejected_for_depth() {
            let mut links = fixture_links();
            let extra = links.clone();
            links.extend(extra.into_iter().take(2));
            assert_eq!(links.len(), 5);

            let err = decode_capability_chain(&encode(&json!(links)))
                .expect_err("five links exceeds the maximum of four");
            assert_eq!(err, ChainDecodeError::DepthExceeded { depth: 5 });
        }

        /// architecture.md §5.2 rule 1 requires the depth guard to run before *any*
        /// signature work. Rather than counting recoveries — a counter would read zero
        /// trivially, since this module never recovers at all — this asserts something
        /// stronger and non-circular: a five-link chain whose links are not even objects
        /// still fails on depth. If a single link were parsed, let alone recovered, the
        /// error would be `MalformedLink` instead.
        #[test]
        fn depth_is_rejected_before_any_per_link_work() {
            let garbage = json!([1, "two", null, {"nonsense": true}, []]);
            let err = decode_capability_chain(&encode(&garbage))
                .expect_err("five links exceeds the maximum of four");
            assert_eq!(
                err,
                ChainDecodeError::DepthExceeded { depth: 5 },
                "depth must be decided from the array length alone"
            );

            // The control: the same garbage within the depth limit *does* reach per-link
            // parsing, which proves the test above is not passing for some unrelated reason.
            let short = json!([1, "two"]);
            assert!(matches!(
                decode_capability_chain(&encode(&short)).unwrap_err(),
                ChainDecodeError::MalformedLink { index: 0, .. }
            ));
        }

        #[test]
        fn an_allowlist_that_does_not_hash_to_its_declared_hash_is_rejected() {
            let mut links = fixture_links();
            links[1]["allowlist"] = json!(["geocode", "weather", "smuggled"]);

            let err = decode_capability_chain(&encode(&json!(links)))
                .expect_err("a tampered allowlist must not decode");
            assert_eq!(err, ChainDecodeError::AllowlistMismatch { index: 1 });
        }

        #[test]
        fn a_missing_allowlist_is_rejected_when_the_hash_is_set() {
            let mut links = fixture_links();
            links[0]["allowlist"] = json!([]);

            let err = decode_capability_chain(&encode(&json!(links)))
                .expect_err("allowlistHash != 0 requires the plaintext list");
            assert_eq!(err, ChainDecodeError::AllowlistMissing { index: 0 });
        }

        /// `0x0` means inherit, so presenting slugs alongside it contradicts the signed
        /// field and must not be silently ignored.
        #[test]
        fn an_inheriting_link_may_not_present_an_allowlist() {
            let mut links = fixture_links();
            links[2]["capability"]["allowlistHash"] = json!(B256::ZERO.to_string());

            let err = decode_capability_chain(&encode(&json!(links)))
                .expect_err("0x0 plus slugs is contradictory");
            assert_eq!(err, ChainDecodeError::AllowlistMismatch { index: 2 });

            // With the slugs removed it is a well-formed inheriting link.
            links[2]["allowlist"] = json!([]);
            let chain = decode_capability_chain(&encode(&json!(links)))
                .expect("inheriting with no slugs is valid");
            assert!(chain[2].allowlist.is_empty());
            assert_eq!(chain[2].capability.allowlistHash, B256::ZERO);
        }

        #[test]
        fn an_empty_chain_is_rejected() {
            let err = decode_capability_chain(&encode(&json!([])))
                .expect_err("an empty chain grants nothing and must not decode");
            assert_eq!(err, ChainDecodeError::EmptyChain);
        }

        #[test]
        fn bad_base64_and_bad_json_are_distinct_errors() {
            assert!(matches!(
                decode_capability_chain("not!valid!base64").unwrap_err(),
                ChainDecodeError::InvalidBase64(_)
            ));
            assert!(matches!(
                decode_capability_chain(&BASE64.encode("{not json")).unwrap_err(),
                ChainDecodeError::InvalidJson(_)
            ));
            // A JSON object rather than an array is a shape error, not a link error.
            assert!(matches!(
                decode_capability_chain(&BASE64.encode("{}")).unwrap_err(),
                ChainDecodeError::InvalidJson(_)
            ));
        }

        #[test]
        fn each_malformed_field_names_itself() {
            for (field, mutate) in [
                ("issuer", json!("0xnothex")),
                ("salt", json!("0x01")),
                ("maxTotal", json!("not a number")),
            ] {
                let mut links = fixture_links();
                links[0]["capability"][field] = mutate;

                let err = decode_capability_chain(&encode(&json!(links)))
                    .expect_err("a malformed field must not decode");
                match err {
                    ChainDecodeError::MalformedLink { index, field: got, .. } => {
                        assert_eq!(index, 0);
                        assert_eq!(got, field, "the error must name the offending field");
                    }
                    other => panic!("expected MalformedLink for {field}, got {other:?}"),
                }
            }

            // A malformed signature is a link error too, not a recovery failure: this
            // module does no crypto.
            let mut links = fixture_links();
            links[0]["signature"] = json!("0xzz");
            assert!(matches!(
                decode_capability_chain(&encode(&json!(links))).unwrap_err(),
                ChainDecodeError::MalformedLink { index: 0, .. }
            ));
        }
    }
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
