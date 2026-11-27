use crate::asset_id::AssetId;
use crate::error::ZyozaError;
use blake2b_simd::Params;
use serde::{Deserialize, Serialize};

const PERSONAL_COL_ID: &[u8; 16] = b"ZYOZA-COL-ID1___";
const PERSONAL_MINT_AID: &[u8; 16] = b"ZYOZA-MINT-AID1_";
const PERSONAL_MINT_IDX: &[u8; 16] = b"ZYOZA-MINT-IDX1_";
const PERSONAL_MINT_MED: &[u8; 16] = b"ZYOZA-MINT-MED1_";

/// Declarative issuance guarantees for a Zyoza collection.
///
/// Unifies 1/1 unique mints (`max_supply: Some(1)`), capped editions (`Some(N)`),
/// timed open editions (`mint_window`), and duplicate-media prevention (`unique_media`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionSpec {
    pub issuer_vk: [u8; 32],
    pub slug: String,
    pub max_supply: Option<u64>,
    pub unique_media: bool,
    pub mint_window: Option<(u64, u64)>,
}

/// Per-mint claim validated against a `CollectionSpec`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintClaim {
    pub asset_id: AssetId,
    pub token_index: u64,
    pub media_sha256: [u8; 32],
    pub timestamp_unix: u64,
}

impl CollectionSpec {
    /// Derives the deterministic 32-byte `collection_id` committing to the issuer and all rules.
    pub fn collection_id(&self) -> [u8; 32] {
        let mut h = Params::new()
            .hash_length(32)
            .personal(PERSONAL_COL_ID)
            .to_state();
        h.update(&self.issuer_vk);
        h.update(self.slug.as_bytes());
        match self.max_supply {
            Some(cap) => {
                h.update(&[1]);
                h.update(&cap.to_be_bytes());
            }
            None => {
                h.update(&[0]);
            }
        }
        h.update(&[u8::from(self.unique_media)]);
        match self.mint_window {
            Some((start, end)) => {
                h.update(&[1]);
                h.update(&start.to_be_bytes());
                h.update(&end.to_be_bytes());
            }
            None => {
                h.update(&[0]);
            }
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }

    /// Validates `claim` against all collection rules and returns the deterministic
    /// set of mint nullifiers that must be unclaimed on the settlement layer.
    pub fn validate_and_nullifiers(&self, claim: &MintClaim) -> Result<Vec<[u8; 32]>, ZyozaError> {
        if let Some(cap) = self.max_supply {
            if claim.token_index == 0 || claim.token_index > cap {
                return Err(ZyozaError::InvalidTransition(format!(
                    "token_index {} out of collection bounds 1..={cap}",
                    claim.token_index
                )));
            }
        }

        if let Some((start, end)) = self.mint_window {
            if claim.timestamp_unix < start || claim.timestamp_unix > end {
                return Err(ZyozaError::InvalidTransition(format!(
                    "mint timestamp {} outside window {start}..={end}",
                    claim.timestamp_unix
                )));
            }
        }

        let col_id = self.collection_id();
        let mut nullifiers = Vec::with_capacity(3);

        // 1. Always prevent minting the exact same AssetId twice (even with a fresh nonce).
        nullifiers.push(hash_nf(PERSONAL_MINT_AID, &col_id, &claim.asset_id.0));

        // 2. If supply is capped, prevent two different AssetIds from claiming the same slot index.
        if self.max_supply.is_some() {
            nullifiers.push(hash_nf(
                PERSONAL_MINT_IDX,
                &col_id,
                &claim.token_index.to_be_bytes(),
            ));
        }

        // 3. If unique_media is enabled, prevent copy-minting the same media hash in this collection.
        if self.unique_media {
            nullifiers.push(hash_nf(PERSONAL_MINT_MED, &col_id, &claim.media_sha256));
        }

        Ok(nullifiers)
    }
}

fn hash_nf(personal: &[u8; 16], col_id: &[u8; 32], item: &[u8]) -> [u8; 32] {
    let mut h = Params::new().hash_length(32).personal(personal).to_state();
    h.update(col_id);
    h.update(item);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}
