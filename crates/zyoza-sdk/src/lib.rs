//! High-level Zyoza client SDK unifying profiles, OOB encryption, settlement, and ZK proofs.

pub mod portable;

use zyoza_core::{
    AssetDesc, AssetId, AssetProfile, ZyozaEnvelope, ZyozaError, ObjectViewingKey, OrchardMemoSeal,
    OwnershipProofRequest, OwnershipVerifyRequest, ProfilePreview, ProofBytes, ProofEngine,
    SettlementAdapter, SettlementReceipt, PROTOCOL_VERSION,
};
use zyoza_oob::{OobEnvelope, OobKeypair, OobStorage};
use zyoza_profile_nft::{
    CollectionPolicy, MediaManifest, NftProfile, NftState, NftTransitionWitness, ProvenanceEvent,
    NFT_PROFILE_ID,
};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub use zyoza_core;
pub use zyoza_oob;
pub use zyoza_profile_nft;
pub use zyoza_proofs;
pub use zyoza_settlement;

/// Output of minting a Zyoza NFT.
#[derive(Debug, Clone)]
pub struct MintNftOutput {
    pub asset_id: AssetId,
    pub state: NftState,
    pub envelope: ZyozaEnvelope,
    pub commitment: [u8; 32],
    pub oob_uri: String,
    pub oob_envelope: OobEnvelope,
    pub receipt: SettlementReceipt,
    pub viewing_key: ObjectViewingKey,
}

/// Output of transferring a Zyoza NFT.
#[derive(Debug, Clone)]
pub struct TransferNftOutput {
    pub state: NftState,
    pub envelope: ZyozaEnvelope,
    pub commitment: [u8; 32],
    pub oob_uri: String,
    pub oob_envelope: OobEnvelope,
    pub receipt: SettlementReceipt,
}

/// High-level Zyoza NFT client parameterized by storage, settlement, and proof engines.
pub struct ZyozaNftClient<S, A, P> {
    pub profile: NftProfile,
    pub storage: S,
    pub settlement: A,
    pub prover: P,
}

impl<S: OobStorage, A: SettlementAdapter, P: ProofEngine> ZyozaNftClient<S, A, P> {
    /// Creates a new `ZyozaNftClient`.
    pub fn new(storage: S, settlement: A, prover: P) -> Self {
        Self {
            profile: NftProfile,
            storage,
            settlement,
            prover,
        }
    }

    /// Mints a new `NFT1` Zyoza object, encrypts its OOB state, and anchors an Orchard seal.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_nft<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        issuer_vk: &[u8],
        desc: &AssetDesc,
        title: String,
        description: String,
        creator: String,
        media_uri: String,
        traits: BTreeMap<String, String>,
        policy: CollectionPolicy,
        owner_keys: &OobKeypair,
        owner_ovk_secret: &[u8; 32],
        now_unix: u64,
    ) -> Result<MintNftOutput, ZyozaError> {
        let asset_id = AssetId::derive(issuer_vk, &desc.to_canonical_bytes());
        let media_hash = hex::encode(Sha256::digest(media_uri.as_bytes()));

        let state = NftState {
            asset_id,
            title,
            description,
            creator,
            media: MediaManifest {
                mime: "application/octet-stream".to_string(),
                sha256_hex: media_hash,
                encrypted_blob_uri: media_uri,
            },
            traits,
            policy,
            provenance: vec![ProvenanceEvent {
                step: 0,
                kind: "mint".to_string(),
                commitment_hex: "00".repeat(32),
                timestamp_unix: now_unix,
            }],
        };

        let state_bytes = state.to_bytes()?;
        let witness = serde_json::to_vec(&NftTransitionWitness {
            current_unix: now_unix,
            royalty_paid: true,
        })
        .map_err(|e| ZyozaError::InvalidEncoding(e.to_string()))?;
        self.profile
            .validate_transition(None, &state_bytes, &witness)?;

        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let state_root = state.state_root()?;
        let envelope = ZyozaEnvelope {
            version: PROTOCOL_VERSION,
            profile_id: NFT_PROFILE_ID,
            asset_id,
            state_root,
            prev_commitment: None,
            nonce,
        };
        let commitment = envelope.state_commitment();

        let oob_envelope = OobEnvelope::seal(rng, &envelope, &owner_keys.public, &state_bytes)
            .map_err(|e| ZyozaError::Settlement(format!("oob seal: {e}")))?;
        let oob_uri = self
            .storage
            .put(&oob_envelope)
            .map_err(|e| ZyozaError::Settlement(format!("oob put: {e}")))?;
        let oob_pointer_hash = oob_envelope
            .pointer_hash()
            .map_err(|e| ZyozaError::Settlement(format!("oob hash: {e}")))?;

        let memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: NFT_PROFILE_ID,
            asset_id,
            state_root,
            nonce,
            oob_pointer_hash,
            oob_uri: oob_uri.clone(),
        }
        .to_bytes()?;

        let receipt = self.settlement.anchor_mint(&asset_id, commitment, &memo)?;
        let viewing_key = ObjectViewingKey::derive(asset_id, owner_ovk_secret);

        Ok(MintNftOutput {
            asset_id,
            state,
            envelope,
            commitment,
            oob_uri,
            oob_envelope,
            receipt,
            viewing_key,
        })
    }

    /// Transfers an existing `NFT1` Zyoza object, re-wrapping OOB state and anchoring the seal.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_nft<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        prev_state: &NftState,
        prev_commitment: [u8; 32],
        prev_oob: &OobEnvelope,
        from_keys: &OobKeypair,
        to_keys: &OobKeypair,
        royalty_paid: bool,
        now_unix: u64,
    ) -> Result<TransferNftOutput, ZyozaError> {
        let prev_bytes = prev_state.to_bytes()?;
        let mut next_state = prev_state.clone();
        next_state.provenance.push(ProvenanceEvent {
            step: prev_state.provenance.len() as u64,
            kind: "transfer".to_string(),
            commitment_hex: hex::encode(prev_commitment),
            timestamp_unix: now_unix,
        });
        let next_bytes = next_state.to_bytes()?;
        let witness = serde_json::to_vec(&NftTransitionWitness {
            current_unix: now_unix,
            royalty_paid,
        })
        .map_err(|e| ZyozaError::InvalidEncoding(e.to_string()))?;

        self.profile
            .validate_transition(Some(&prev_bytes), &next_bytes, &witness)?;

        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let state_root = next_state.state_root()?;
        let envelope = ZyozaEnvelope {
            version: PROTOCOL_VERSION,
            profile_id: NFT_PROFILE_ID,
            asset_id: next_state.asset_id,
            state_root,
            prev_commitment: Some(prev_commitment),
            nonce,
        };
        let commitment = envelope.state_commitment();

        // Re-wrap existing OOB blob or seal updated state for recipient.
        let _ = prev_oob
            .open(&from_keys.secret)
            .map_err(|e| ZyozaError::Settlement(format!("oob open: {e}")))?;
        let oob_envelope = OobEnvelope::seal(rng, &envelope, &to_keys.public, &next_bytes)
            .map_err(|e| ZyozaError::Settlement(format!("oob seal: {e}")))?;
        let oob_uri = self
            .storage
            .put(&oob_envelope)
            .map_err(|e| ZyozaError::Settlement(format!("oob put: {e}")))?;
        let oob_pointer_hash = oob_envelope
            .pointer_hash()
            .map_err(|e| ZyozaError::Settlement(format!("oob hash: {e}")))?;

        let memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: NFT_PROFILE_ID,
            asset_id: next_state.asset_id,
            state_root,
            nonce,
            oob_pointer_hash,
            oob_uri: oob_uri.clone(),
        }
        .to_bytes()?;

        let receipt = self.settlement.anchor_transfer(
            &next_state.asset_id,
            prev_commitment,
            commitment,
            &memo,
        )?;

        Ok(TransferNftOutput {
            state: next_state,
            envelope,
            commitment,
            oob_uri,
            oob_envelope,
            receipt,
        })
    }

    /// Inspects an NFT's OOB state using an optional `ObjectViewingKey`.
    pub fn inspect_nft(
        &self,
        oob_uri: &str,
        owner_keys: &OobKeypair,
        viewing_key: Option<&ObjectViewingKey>,
    ) -> Result<ProfilePreview, ZyozaError> {
        let oob = self
            .storage
            .get(oob_uri)
            .map_err(|e| ZyozaError::Settlement(format!("oob get: {e}")))?;
        let state_bytes = oob
            .open(&owner_keys.secret)
            .map_err(|e| ZyozaError::Settlement(format!("oob open: {e}")))?;
        self.profile.public_preview(&state_bytes, viewing_key)
    }

    /// Generates a zero-knowledge ownership proof for an NFT.
    pub fn prove_ownership(
        &self,
        req: &OwnershipProofRequest,
    ) -> Result<ProofBytes, ZyozaError> {
        self.prover.prove_ownership(req)
    }

    /// Verifies a zero-knowledge ownership proof.
    pub fn verify_ownership(
        &self,
        req: &OwnershipVerifyRequest,
        proof: &[u8],
    ) -> Result<bool, ZyozaError> {
        self.prover.verify_ownership(req, proof)
    }
}
