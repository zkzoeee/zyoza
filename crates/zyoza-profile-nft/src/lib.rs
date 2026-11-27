//! NFT vertical profile (`NFT1`) for Zyoza (Phase 2).

use zyoza_core::{
    AssetId, AssetProfile, ZyozaError, ObjectViewingKey, ProfileId, ProfilePreview,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// 4-byte profile identifier for Zyoza NFTs.
pub const NFT_PROFILE_ID: ProfileId = *b"NFT1";

/// Encrypted media manifest carried out-of-band.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaManifest {
    pub mime: String,
    pub sha256_hex: String,
    pub encrypted_blob_uri: String,
}

/// Optional collection-level rules enforced on state transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionPolicy {
    pub royalty_bps: u16,
    pub lockup_until_unix: Option<u64>,
}

/// Append-only provenance record for an NFT lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEvent {
    pub step: u64,
    pub kind: String,
    pub commitment_hex: String,
    pub timestamp_unix: u64,
}

/// Full off-chain state of a `NFT1` Zyoza object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftState {
    pub asset_id: AssetId,
    pub title: String,
    pub description: String,
    pub creator: String,
    pub media: MediaManifest,
    pub traits: BTreeMap<String, String>,
    pub policy: CollectionPolicy,
    pub provenance: Vec<ProvenanceEvent>,
}

impl NftState {
    /// Computes the deterministic 32-byte `state_root` for anchoring in `ZyozaEnvelope`.
    pub fn state_root(&self) -> Result<[u8; 32], ZyozaError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| ZyozaError::InvalidEncoding(format!("nft state json: {e}")))?;
        let digest = Sha256::digest(&bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    /// Serializes the state to canonical JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZyozaError> {
        serde_json::to_vec(self)
            .map_err(|e| ZyozaError::InvalidEncoding(format!("nft state serialize: {e}")))
    }

    /// Parses an `NftState` from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZyozaError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ZyozaError::InvalidEncoding(format!("nft state parse: {e}")))
    }
}

/// Witness supplied when validating an `NFT1` state transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftTransitionWitness {
    pub current_unix: u64,
    pub royalty_paid: bool,
}

/// `AssetProfile` implementation for `NFT1`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NftProfile;

impl AssetProfile for NftProfile {
    fn profile_id(&self) -> ProfileId {
        NFT_PROFILE_ID
    }

    fn validate_transition(
        &self,
        prev_state: Option<&[u8]>,
        next_state: &[u8],
        witness: &[u8],
    ) -> Result<(), ZyozaError> {
        let next = NftState::from_bytes(next_state)?;
        let wit: NftTransitionWitness = serde_json::from_slice(witness)
            .map_err(|e| ZyozaError::InvalidTransition(format!("bad witness: {e}")))?;

        if next.title.trim().is_empty() {
            return Err(ZyozaError::InvalidTransition("title cannot be empty".into()));
        }
        if next.media.sha256_hex.len() != 64 {
            return Err(ZyozaError::InvalidTransition(
                "media sha256_hex must be 64 hex chars".into(),
            ));
        }
        if next.policy.royalty_bps > 10_000 {
            return Err(ZyozaError::InvalidTransition(
                "royalty_bps cannot exceed 10000".into(),
            ));
        }

        match prev_state {
            None => {
                if next.provenance.len() != 1 || next.provenance[0].kind != "mint" {
                    return Err(ZyozaError::InvalidTransition(
                        "mint state must have exactly 1 'mint' provenance event".into(),
                    ));
                }
                Ok(())
            }
            Some(prev_bytes) => {
                let prev = NftState::from_bytes(prev_bytes)?;
                if prev.asset_id != next.asset_id
                    || prev.creator != next.creator
                    || prev.media != next.media
                    || prev.policy != next.policy
                {
                    return Err(ZyozaError::InvalidTransition(
                        "immutable NFT fields modified during transfer".into(),
                    ));
                }
                if next.provenance.len() != prev.provenance.len() + 1 {
                    return Err(ZyozaError::InvalidTransition(
                        "transfer must append exactly 1 provenance event".into(),
                    ));
                }
                if let Some(lockup) = prev.policy.lockup_until_unix {
                    if wit.current_unix < lockup {
                        return Err(ZyozaError::InvalidTransition(format!(
                            "transfer locked until {lockup}"
                        )));
                    }
                }
                if prev.policy.royalty_bps > 0 && !wit.royalty_paid {
                    return Err(ZyozaError::InvalidTransition(
                        "collection royalty must be satisfied".into(),
                    ));
                }
                Ok(())
            }
        }
    }

    fn public_preview(
        &self,
        state: &[u8],
        viewing_key: Option<&ObjectViewingKey>,
    ) -> Result<ProfilePreview, ZyozaError> {
        let nft = NftState::from_bytes(state)?;
        let authorized = viewing_key.is_some_and(|ovk| ovk.asset_id == nft.asset_id);

        if authorized {
            let attributes_json = serde_json::to_string(&nft.traits)
                .map_err(|e| ZyozaError::InvalidEncoding(e.to_string()))?;
            Ok(ProfilePreview {
                profile_id: NFT_PROFILE_ID,
                title: nft.title,
                summary: format!("{} (by {})", nft.description, nft.creator),
                attributes_json,
            })
        } else {
            Ok(ProfilePreview {
                profile_id: NFT_PROFILE_ID,
                title: "Shielded Zyoza NFT".to_string(),
                summary: "shielded (ObjectViewingKey required)".to_string(),
                attributes_json: "{}".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_nft(asset_id: AssetId) -> NftState {
        let mut traits = BTreeMap::new();
        traits.insert("filling".to_string(), "truffle".to_string());
        traits.insert("rarity".to_string(), "genesis".to_string());

        NftState {
            asset_id,
            title: "Genesis Zyoza #1".to_string(),
            description: "First shielded dumpling".to_string(),
            creator: "alice".to_string(),
            media: MediaManifest {
                mime: "image/png".to_string(),
                sha256_hex: "a".repeat(64),
                encrypted_blob_uri: "ipfs://bafy123".to_string(),
            },
            traits,
            policy: CollectionPolicy {
                royalty_bps: 500,
                lockup_until_unix: Some(1_700_000_000),
            },
            provenance: vec![ProvenanceEvent {
                step: 0,
                kind: "mint".to_string(),
                commitment_hex: "00".repeat(32),
                timestamp_unix: 1_699_000_000,
            }],
        }
    }

    #[test]
    fn nft_mint_transfer_policy_and_preview() {
        let profile = NftProfile;
        let asset_id = AssetId::derive(&[0xAA; 32], b"zyoza:nft:1");
        let mint = sample_nft(asset_id);
        let mint_bytes = mint.to_bytes().unwrap();

        let wit_ok = serde_json::to_vec(&NftTransitionWitness {
            current_unix: 1_700_000_100,
            royalty_paid: true,
        })
        .unwrap();

        profile.validate_transition(None, &mint_bytes, &wit_ok).unwrap();

        let mut xfer = mint.clone();
        xfer.provenance.push(ProvenanceEvent {
            step: 1,
            kind: "transfer".to_string(),
            commitment_hex: "11".repeat(32),
            timestamp_unix: 1_700_000_100,
        });
        let xfer_bytes = xfer.to_bytes().unwrap();

        // Valid transfer
        profile
            .validate_transition(Some(&mint_bytes), &xfer_bytes, &wit_ok)
            .unwrap();

        // Lockup violation
        let wit_early = serde_json::to_vec(&NftTransitionWitness {
            current_unix: 1_699_500_000,
            royalty_paid: true,
        })
        .unwrap();
        assert!(profile
            .validate_transition(Some(&mint_bytes), &xfer_bytes, &wit_early)
            .is_err());

        // Royalty violation
        let wit_unpaid = serde_json::to_vec(&NftTransitionWitness {
            current_unix: 1_700_000_100,
            royalty_paid: false,
        })
        .unwrap();
        assert!(profile
            .validate_transition(Some(&mint_bytes), &xfer_bytes, &wit_unpaid)
            .is_err());

        // Preview: shielded vs OVK
        let shielded = profile.public_preview(&xfer_bytes, None).unwrap();
        assert_eq!(shielded.title, "Shielded Zyoza NFT");

        let ovk = ObjectViewingKey::derive(asset_id, &[0x42; 32]);
        let unlocked = profile.public_preview(&xfer_bytes, Some(&ovk)).unwrap();
        assert_eq!(unlocked.title, "Genesis Zyoza #1");
        assert!(unlocked.attributes_json.contains("truffle"));
    }
}
