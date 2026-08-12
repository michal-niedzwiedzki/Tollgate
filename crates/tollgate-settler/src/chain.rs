//! Turning queued rows into one `BatchSettler.settle` transaction.

use std::str::FromStr;
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::{Context, Result, anyhow, bail};
use tollgate_core::config::Config;

use crate::batch::QueuedAuth;

sol! {
    #[sol(rpc)]
    contract BatchSettler {
        struct Auth {
            address token;
            address from;
            address to;
            uint256 value;
            uint256 validAfter;
            uint256 validBefore;
            bytes32 nonce;
            uint8 v;
            bytes32 r;
            bytes32 s;
        }

        event Settled(bytes32 indexed nonce);
        event SettleFailed(bytes32 indexed nonce, bytes reason);

        function settle(Auth[] calldata auths) external;
    }
}

sol! {
    #[sol(rpc)]
    contract IERC3009 {
        function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);
    }
}

/// How long to wait for a receipt before declaring the result ambiguous.
const RECEIPT_DEADLINE: Duration = Duration::from_secs(60);

/// Fixed EIP-1559 parameters. `architecture.md` §7.2: "EIP-1559 with a fixed multiplier. Do not
/// build a gas oracle." The base fee is read from the latest block and multiplied; the priority
/// fee is a constant. Base's base fee is a fraction of a gwei, so this is generous without being
/// expensive, and it avoids an oracle dependency in the settlement path.
const BASE_FEE_MULTIPLIER: u128 = 2;
const PRIORITY_FEE_WEI: u128 = 1_000_000; // 0.001 gwei

/// What the chain reported back about one batch.
pub struct SettlementOutcome {
    pub tx_hash: B256,
    /// Gas the settlement transaction actually burned, for `/v1/stats` (Task 7.3) — measured,
    /// not estimated, which is the whole point of `prd.md` §8's "under $0.001" claim.
    pub gas_used: u64,
    pub settled: Vec<Vec<u8>>,
    /// Nonces the contract emitted `SettleFailed` for. Task 6.5 owns requeueing these with a
    /// retry count; this task only reports them.
    pub failed: Vec<(Vec<u8>, Bytes)>,
}

/// Why a submission produced no receipt we can act on.
#[derive(Debug)]
pub enum SubmitError {
    /// The transaction was sent, but no receipt arrived before the deadline. Whether the batch
    /// executed is genuinely unknown, so it must never be blind-resubmitted — that is the double
    /// submission architecture.md §7.2 forbids. The caller resolves it against
    /// `authorizationState` instead.
    Ambiguous { tx_hash: B256 },
    /// Nothing reached the chain. Safe to leave the rows queued and try again later.
    NotSent(anyhow::Error),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ambiguous { tx_hash } => {
                write!(f, "no receipt for {tx_hash} within {RECEIPT_DEADLINE:?}")
            }
            Self::NotSent(err) => write!(f, "{err:#}"),
        }
    }
}

/// The result of resolving an ambiguous submission against the token's own replay guard.
#[derive(Debug, Default)]
pub struct AmbiguityVerdict {
    /// Nonces USDC reports as already used: the charge settled after all.
    pub settled: Vec<Vec<u8>>,
    /// Nonces still unused on-chain, so the batch really did not execute for them.
    pub unresolved: Vec<Vec<u8>>,
}

/// Reads USDC's `authorizationState` for one authorisation.
///
/// A trait so the ambiguous-timeout path can be tested against a stub rather than a live chain,
/// which is what the task's verification asks for.
pub trait AuthorizationLookup {
    fn is_used(
        &self,
        from: Address,
        nonce: B256,
    ) -> impl std::future::Future<Output = Result<bool>>;
}

/// Decides, for each item of an ambiguous batch, whether it already settled on-chain.
///
/// This performs no submission of any kind. That is the point: after an ambiguous result the only
/// safe next action is a read.
pub async fn classify_ambiguous<L: AuthorizationLookup>(
    lookup: &L,
    items: &[QueuedAuth],
) -> Result<AmbiguityVerdict> {
    let mut verdict = AmbiguityVerdict::default();

    for item in items {
        let (from, nonce) = authorization_key(item)?;
        if lookup.is_used(from, nonce).await? {
            verdict.settled.push(item.nonce.clone());
        } else {
            verdict.unresolved.push(item.nonce.clone());
        }
    }

    Ok(verdict)
}

/// The `(authorizer, nonce)` pair USDC keys its replay guard by.
fn authorization_key(item: &QueuedAuth) -> Result<(Address, B256)> {
    let auth = item
        .payload
        .get("payload")
        .and_then(|p| p.get("authorization"))
        .ok_or_else(|| anyhow!("payload has no payload.authorization object"))?;

    let from = auth
        .get("from")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("authorization.from is missing"))?
        .parse()
        .context("authorization.from")?;
    let nonce = B256::from_slice(&item.nonce);

    Ok((from, nonce))
}

pub struct Settler<P> {
    provider: P,
    batch_settler: Address,
    usdc: Address,
}

impl<P: Provider> AuthorizationLookup for Settler<P> {
    async fn is_used(&self, from: Address, nonce: B256) -> Result<bool> {
        let usdc = IERC3009::new(self.usdc, &self.provider);
        usdc.authorizationState(from, nonce)
            .call()
            .await
            .context("read authorizationState")
    }
}

/// Builds a settler bound to the configured RPC, signing key and contract addresses.
pub fn connect(cfg: &Config) -> Result<Settler<impl Provider>> {
    let signer = PrivateKeySigner::from_str(&cfg.settler_private_key)
        .context("SETTLER_PRIVATE_KEY is not a valid private key")?;
    let url = cfg.rpc_url.parse().context("RPC_URL is not a valid url")?;

    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(url);

    Ok(Settler {
        provider,
        batch_settler: cfg
            .batch_settler_address
            .parse()
            .context("BATCH_SETTLER_ADDRESS is not a valid address")?,
        usdc: cfg
            .usdc_address
            .parse()
            .context("USDC_ADDRESS is not a valid address")?,
    })
}

impl<P: Provider> Settler<P> {
    /// Submits one batch and waits for its receipt.
    ///
    /// One in-flight transaction at a time, awaited to completion before the caller loops, so the
    /// settler EOA's nonces stay sequential. That caps throughput at roughly one batch per block
    /// — ~25 settlements/sec at 50 per batch and Base's 2-second blocks. The production fix is
    /// several settler EOAs behind a nonce allocator; the ceiling is stated in the README rather
    /// than hidden (architecture.md §7.2).
    pub async fn submit(&self, items: &[QueuedAuth]) -> Result<SettlementOutcome, SubmitError> {
        let auths = items
            .iter()
            .map(|item| self.to_auth(item))
            .collect::<Result<Vec<_>>>()
            .map_err(SubmitError::NotSent)?;

        let contract = BatchSettler::new(self.batch_settler, &self.provider);

        let base_fee = self
            .base_fee()
            .await
            .map_err(SubmitError::NotSent)?;

        let pending = contract
            .settle(auths)
            .max_fee_per_gas(base_fee * BASE_FEE_MULTIPLIER + PRIORITY_FEE_WEI)
            .max_priority_fee_per_gas(PRIORITY_FEE_WEI)
            .send()
            .await
            .context("submit settle transaction")
            .map_err(SubmitError::NotSent)?;

        // From here the transaction is on the wire and its outcome is the chain's to decide.
        // A missing receipt is not a failure, it is an unknown.
        let tx_hash = *pending.tx_hash();

        let receipt = pending
            .with_timeout(Some(RECEIPT_DEADLINE))
            .get_receipt()
            .await
            .map_err(|_| SubmitError::Ambiguous { tx_hash })?;

        if !receipt.status() {
            // A reverted batch is unambiguous: nothing in it settled. `settle` only reverts on
            // something structural, since per-item failures are caught inside the contract.
            return Ok(SettlementOutcome {
                tx_hash: receipt.transaction_hash,
                gas_used: receipt.gas_used,
                settled: Vec::new(),
                failed: items
                    .iter()
                    .map(|item| (item.nonce.clone(), Bytes::new()))
                    .collect(),
            });
        }

        let mut settled = Vec::new();
        let mut failed = Vec::new();
        for log in receipt.inner.logs() {
            if log.address() != self.batch_settler {
                continue;
            }
            if let Ok(event) = log.log_decode::<BatchSettler::Settled>() {
                settled.push(event.inner.nonce.to_vec());
            } else if let Ok(event) = log.log_decode::<BatchSettler::SettleFailed>() {
                failed.push((event.inner.nonce.to_vec(), event.inner.reason.clone()));
            }
        }

        Ok(SettlementOutcome {
            tx_hash: receipt.transaction_hash,
            gas_used: receipt.gas_used,
            settled,
            failed,
        })
    }

    async fn base_fee(&self) -> Result<u128> {
        Ok(self
            .provider
            .get_block(alloy::eips::BlockId::latest())
            .await
            .context("fetch latest block")?
            .and_then(|block| block.header.base_fee_per_gas)
            .ok_or_else(|| anyhow!("chain did not report a base fee; EIP-1559 is required"))?
            as u128)
    }

    /// Rebuilds the signed `Auth` from what the gateway persisted.
    ///
    /// Nothing here is re-derived or re-signed: every field was inside the payer's signature and
    /// is carried through verbatim. The token is the configured USDC, because the payload does
    /// not name it — this deployment settles one token on one chain (prd.md decision #3).
    fn to_auth(&self, item: &QueuedAuth) -> Result<BatchSettler::Auth> {
        let auth = item
            .payload
            .get("payload")
            .and_then(|p| p.get("authorization"))
            .ok_or_else(|| anyhow!("payload has no payload.authorization object"))?;

        let field = |name: &str| -> Result<&str> {
            auth.get(name)
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("payload.authorization.{name} is missing or not a string"))
        };

        let (v, r, s) = split_signature(&item.signature)?;

        Ok(BatchSettler::Auth {
            token: self.usdc,
            from: field("from")?.parse().context("authorization.from")?,
            to: field("to")?.parse().context("authorization.to")?,
            value: U256::from_str(field("value")?).context("authorization.value")?,
            validAfter: U256::from_str(field("validAfter")?).context("authorization.validAfter")?,
            validBefore: U256::from_str(field("validBefore")?)
                .context("authorization.validBefore")?,
            nonce: B256::from_str(field("nonce")?).context("authorization.nonce")?,
            v,
            r,
            s,
        })
    }
}

/// Splits the stored 65-byte signature into the `v, r, s` that USDC's `ecrecover` wants.
///
/// The layout is `r || s || v`, which is what `eth_account` and `alloy` both produce. `v` is
/// normalised to 27/28: a raw parity bit of 0/1 would make `ecrecover` return the zero address
/// and every item in the batch would fail signature verification for a reason the revert message
/// does not explain.
fn split_signature(signature: &[u8]) -> Result<(u8, B256, B256)> {
    if signature.len() != 65 {
        bail!("signature is {} bytes, expected 65", signature.len());
    }

    let r = B256::from_slice(&signature[0..32]);
    let s = B256::from_slice(&signature[32..64]);
    let v = match signature[64] {
        raw @ (0 | 1) => raw + 27,
        raw @ (27 | 28) => raw,
        other => bail!("signature v byte is {other}, expected 0, 1, 27 or 28"),
    };

    Ok((v, r, s))
}

#[cfg(test)]
mod ambiguous {
    use std::cell::RefCell;

    use super::*;

    /// A stubbed `authorizationState` lookup. It records what it was asked so a test can assert
    /// that resolution is a read and nothing more — no second submission is even reachable from
    /// here, which is the property the ambiguous path exists to guarantee.
    struct StubLookup {
        used: bool,
        calls: RefCell<Vec<(Address, B256)>>,
    }

    impl AuthorizationLookup for StubLookup {
        async fn is_used(&self, from: Address, nonce: B256) -> Result<bool> {
            self.calls.borrow_mut().push((from, nonce));
            Ok(self.used)
        }
    }

    fn item(nonce: u8) -> QueuedAuth {
        QueuedAuth {
            nonce: vec![nonce; 32],
            payload: serde_json::json!({
                "payload": {
                    "authorization": {
                        "from": "0x00000000000000000000000000000000000000a1",
                        "to": "0x0000000000000000000000000000000000000001",
                        "value": "1000",
                        "validAfter": "0",
                        "validBefore": "99999999999",
                        "nonce": "0x00",
                    }
                }
            }),
            signature: vec![0u8; 65],
        }
    }

    #[tokio::test]
    async fn a_timed_out_batch_whose_nonces_are_spent_is_marked_settled_not_resubmitted() {
        let lookup = StubLookup {
            used: true,
            calls: RefCell::new(Vec::new()),
        };
        let items = vec![item(1), item(2)];

        let verdict = classify_ambiguous(&lookup, &items).await.unwrap();

        assert_eq!(verdict.settled.len(), 2, "both already settled on-chain");
        assert!(verdict.unresolved.is_empty(), "nothing left to resubmit");
        assert_eq!(
            lookup.calls.borrow().len(),
            2,
            "resolution is one authorizationState read per item"
        );
    }

    #[tokio::test]
    async fn a_timed_out_batch_whose_nonces_are_unspent_stays_queued() {
        let lookup = StubLookup {
            used: false,
            calls: RefCell::new(Vec::new()),
        };
        let items = vec![item(1), item(2)];

        let verdict = classify_ambiguous(&lookup, &items).await.unwrap();

        assert!(verdict.settled.is_empty(), "nothing settled");
        assert_eq!(verdict.unresolved.len(), 2, "both genuinely need retrying");
    }

    #[tokio::test]
    async fn the_nonce_checked_is_the_authorisation_nonce() {
        let lookup = StubLookup {
            used: true,
            calls: RefCell::new(Vec::new()),
        };

        classify_ambiguous(&lookup, &[item(7)]).await.unwrap();

        let calls = lookup.calls.borrow();
        assert_eq!(calls[0].1, B256::from([7u8; 32]));
        assert_eq!(
            calls[0].0,
            "0x00000000000000000000000000000000000000a1"
                .parse::<Address>()
                .unwrap()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature_with_v(v: u8) -> Vec<u8> {
        let mut sig = vec![0u8; 65];
        sig[0..32].copy_from_slice(&[0xaa; 32]);
        sig[32..64].copy_from_slice(&[0xbb; 32]);
        sig[64] = v;
        sig
    }

    #[test]
    fn splits_r_s_and_v_in_the_stored_order() {
        let (v, r, s) = split_signature(&signature_with_v(27)).unwrap();
        assert_eq!(v, 27);
        assert_eq!(r, B256::from([0xaa; 32]));
        assert_eq!(s, B256::from([0xbb; 32]));
    }

    #[test]
    fn a_raw_parity_bit_is_normalised_to_the_ecrecover_range() {
        assert_eq!(split_signature(&signature_with_v(0)).unwrap().0, 27);
        assert_eq!(split_signature(&signature_with_v(1)).unwrap().0, 28);
        assert_eq!(split_signature(&signature_with_v(28)).unwrap().0, 28);
    }

    #[test]
    fn a_wrong_length_signature_is_an_error() {
        assert!(split_signature(&[0u8; 64]).is_err());
    }

    #[test]
    fn an_unrecognised_v_byte_is_an_error() {
        assert!(split_signature(&signature_with_v(7)).is_err());
    }
}
