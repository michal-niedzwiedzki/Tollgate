//! Capability revocation and lookup. Task 5.5.
//!
//! architecture.md §5.2: "Revocation is off-chain and that is fine. The gateway is the
//! enforcement point, so a signed revocation posted to the gateway and stored in a Redis set
//! is sufficient. Nothing needs to reach a chain for a revocation to take effect."

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::B256;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tollgate_core::db;
use tollgate_core::error::ErrorBody;

use crate::capability::{recover_revoker, Revocation};
use crate::policy;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    /// Signed over, so it must be present and must agree with the path.
    capability_hash: String,
    issued_at: u64,
    signature: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    hash: String,
    revoked_at: Option<String>,
}

fn bad_request(code: &str, message: impl Into<String>) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody::new(code, message.into())),
    )
        .into_response()
}

/// Returns the parse message rather than a built response: a `Response` is a large error
/// variant to carry through a `Result`, and every call site wants the same error code anyway.
fn parse_hash(raw: &str) -> Result<B256, String> {
    B256::from_str(raw).map_err(|e| e.to_string())
}

/// `POST /v1/capabilities/{hash}/revoke`.
///
/// The signer must be the capability's own issuer or the issuer of any ancestor: authority
/// flows down the chain, so whoever granted it may withdraw it. Revoking a parent therefore
/// blocks every descendant, because a descendant's chain still contains the revoked link and
/// `verify_chain` checks every link (architecture.md §5.2 rule 6).
pub async fn revoke_capability(
    State(state): State<AppState>,
    Path(hash): Path<String>,
    Json(body): Json<RevokeRequest>,
) -> axum::response::Response {
    let hash = match parse_hash(&hash) {
        Ok(hash) => hash,
        Err(message) => return bad_request("invalid_capability_hash", message),
    };
    let signed_over = match parse_hash(&body.capability_hash) {
        Ok(hash) => hash,
        Err(message) => return bad_request("invalid_capability_hash", message),
    };

    // The signature covers `capabilityHash`, so a mismatch means the caller is presenting a
    // revocation for one capability at another's endpoint.
    if signed_over != hash {
        return bad_request(
            "capability_hash_mismatch",
            "the signed capabilityHash does not match the path",
        );
    }

    let signature = match alloy::hex::decode(body.signature.trim_start_matches("0x")) {
        Ok(bytes) => bytes,
        Err(e) => return bad_request("invalid_signature", e.to_string()),
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the unix epoch")
        .as_secs();

    // A future-dated revocation is meaningless, and refusing it is free. There is
    // deliberately no lower bound: revocation is idempotent and monotonic, so replaying an
    // old one can only re-revoke something already revoked.
    if body.issued_at > now + state.cfg.clock_skew_seconds {
        return bad_request("revocation_not_yet_valid", "issuedAt is in the future");
    }

    let revocation = Revocation {
        capabilityHash: hash,
        issuedAt: body.issued_at,
    };
    let signer = match recover_revoker(&revocation, &signature, state.cfg.chain_id) {
        Ok(signer) => signer,
        Err(e) => return bad_request("invalid_signature", e.to_string()),
    };

    let stored = match db::get_capability(&state.pg, hash.as_slice()).await {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorBody::new(
                    "capability_not_found",
                    "no such capability; it is recorded on first use",
                )),
            )
                .into_response();
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to look up capability");
            return internal_error("failed to look up capability");
        }
    };

    let issuers = match db::capability_issuers(&state.pg, hash.as_slice()).await {
        Ok(issuers) => issuers,
        Err(err) => {
            tracing::error!(error = %err, "failed to walk capability ancestry");
            return internal_error("failed to walk capability ancestry");
        }
    };

    if !issuers.contains(&signer) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody::new(
                "not_authorised_to_revoke",
                "the signer is neither this capability's issuer nor an ancestor's",
            )),
        )
            .into_response();
    }

    // Redis first, Postgres second. Redis is what `verify_chain` consults on the request
    // path, so this ordering makes the revocation take effect at the earliest possible
    // moment; if the Postgres write then fails, the capability is already refused and the
    // audit row is what is missing, which is the safe way round.
    let mut redis = state.redis.clone();
    if let Err(err) = policy::add_revoked(&mut redis, &hash.to_string()).await {
        tracing::error!(error = %err, "failed to add capability to the revocation set");
        return internal_error("failed to record revocation");
    }
    if let Err(err) = db::mark_capability_revoked(&state.pg, hash.as_slice()).await {
        tracing::error!(error = %err, "failed to stamp revoked_at");
        return internal_error("failed to record revocation");
    }

    let revoked_at = match db::get_capability(&state.pg, hash.as_slice()).await {
        Ok(Some(stored)) => stored.revoked_at,
        _ => stored.revoked_at,
    };

    (
        StatusCode::OK,
        Json(RevokeResponse {
            hash: hash.to_string(),
            revoked_at,
        }),
    )
        .into_response()
}

#[derive(Debug, Serialize)]
pub struct CapabilityResponse {
    hash: String,
    issuer: String,
    subject: String,
    parent_hash: Option<String>,
    depth: i32,
    max_total_wei: String,
    max_per_req_wei: String,
    allowlist: Option<Vec<String>>,
    not_before: u64,
    expiry: u64,
    revoked_at: Option<String>,
    /// Live from Redis, not Postgres: the spend counter is the thing the claim script
    /// actually enforces against.
    spent_wei: String,
    remaining_wei: String,
}

/// `GET /v1/capabilities/{hash}` — the stored capability with `revoked_at` and current spend.
pub async fn get_capability(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> axum::response::Response {
    let hash = match parse_hash(&hash) {
        Ok(hash) => hash,
        Err(message) => return bad_request("invalid_capability_hash", message),
    };

    let stored = match db::get_capability(&state.pg, hash.as_slice()).await {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorBody::new(
                    "capability_not_found",
                    "no such capability; it is recorded on first use",
                )),
            )
                .into_response();
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to look up capability");
            return internal_error("failed to look up capability");
        }
    };

    let mut redis = state.redis.clone();
    let (_, spent) = policy::read_level_state(&mut redis, &hash.to_string())
        .await
        .unwrap_or((0, 0));

    let capability = &stored.capability;
    let max_total = capability.max_total_wei;
    let remaining = max_total.saturating_sub(alloy::primitives::U256::from(spent));

    (
        StatusCode::OK,
        Json(CapabilityResponse {
            hash: capability.hash.to_string(),
            issuer: capability.issuer.to_string(),
            subject: capability.subject.to_string(),
            parent_hash: capability.parent_hash.map(|h| h.to_string()),
            depth: capability.depth,
            max_total_wei: max_total.to_string(),
            max_per_req_wei: capability.max_per_req_wei.to_string(),
            allowlist: capability.allowlist.clone(),
            not_before: capability.not_before,
            expiry: capability.expiry,
            revoked_at: stored.revoked_at,
            spent_wei: spent.to_string(),
            remaining_wei: remaining.to_string(),
        }),
    )
        .into_response()
}

fn internal_error(message: &str) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody::new("internal_error", message)),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::domain;
    use alloy::primitives::Address;
    use alloy::sol_types::SolStruct;

    /// The revocation must be bound to the capability it names, or a signature obtained for
    /// one capability could be presented against another.
    #[test]
    fn a_revocation_signing_hash_is_bound_to_its_capability_hash() {
        let a = Revocation {
            capabilityHash: B256::from([0xaa; 32]),
            issuedAt: 1_700_000_000,
        };
        let b = Revocation {
            capabilityHash: B256::from([0xbb; 32]),
            issuedAt: 1_700_000_000,
        };
        assert_ne!(
            a.eip712_signing_hash(&domain(84532)),
            b.eip712_signing_hash(&domain(84532))
        );
    }

    /// architecture.md §10, cross-chain replay: the domain carries the chain id.
    #[test]
    fn a_revocation_signing_hash_is_bound_to_the_chain_id() {
        let revocation = Revocation {
            capabilityHash: B256::from([0xaa; 32]),
            issuedAt: 1_700_000_000,
        };
        assert_ne!(
            revocation.eip712_signing_hash(&domain(84532)),
            revocation.eip712_signing_hash(&domain(1))
        );
    }

    #[test]
    fn the_encoded_type_matches_the_task_specification() {
        assert_eq!(
            Revocation::eip712_encode_type(),
            "Revocation(bytes32 capabilityHash,uint64 issuedAt)"
        );
    }

    /// An unrelated signer is not in the issuer set, which is what produces the 403.
    #[test]
    fn authorisation_is_membership_of_the_issuer_set() {
        let issuers = [Address::from([0x11; 20]), Address::from([0x22; 20])];
        assert!(issuers.contains(&Address::from([0x22; 20])), "an ancestor issuer may revoke");
        assert!(
            !issuers.contains(&Address::from([0x33; 20])),
            "an unrelated key may not"
        );
    }
}
