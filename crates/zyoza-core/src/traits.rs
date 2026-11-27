use crate::asset_id::AssetId;
use crate::disclosure::ObjectViewingKey;
use crate::error::ZyozaError;
use crate::types::{
    OwnershipProofRequest, OwnershipVerifyRequest, ProfileId, ProfilePreview, ProofBytes,
    SettlementReceipt, ORCHARD_MEMO_LEN,
};

/// Vertical-specific schema and state-transition rules (e.g., NFT, Ticket, Credential).
pub trait AssetProfile: Send + Sync {
    /// 4-byte identifier for this vertical profile (e.g., `b"NFT1"`).
    fn profile_id(&self) -> ProfileId;

    /// Validates a mint (`prev_state == None`) or state transition (`prev_state == Some(...)`).
    fn validate_transition(
        &self,
        prev_state: Option<&[u8]>,
        next_state: &[u8],
        witness: &[u8],
    ) -> Result<(), ZyozaError>;

    /// Renders a human-readable preview of the state, optionally using an `ObjectViewingKey`.
    fn public_preview(
        &self,
        state: &[u8],
        viewing_key: Option<&ObjectViewingKey>,
    ) -> Result<ProfilePreview, ZyozaError>;
}

/// Swappable L1 settlement backend (Orchard seal today, OrchardZSA / Tachyon later).
pub trait SettlementAdapter: Send + Sync {
    /// Anchors an initial mint commitment on the underlying ledger.
    fn anchor_mint(
        &self,
        asset_id: &AssetId,
        state_commitment: [u8; 32],
        memo: &[u8; ORCHARD_MEMO_LEN],
    ) -> Result<SettlementReceipt, ZyozaError>;

    /// Anchors a state transfer commitment, spending `prev_commitment`.
    fn anchor_transfer(
        &self,
        asset_id: &AssetId,
        prev_commitment: [u8; 32],
        next_commitment: [u8; 32],
        memo: &[u8; ORCHARD_MEMO_LEN],
    ) -> Result<SettlementReceipt, ZyozaError>;

    /// Verifies that a settlement receipt is anchored and unspent/valid.
    fn verify_seal(&self, receipt: &SettlementReceipt) -> Result<bool, ZyozaError>;
}

/// Zero-knowledge proof backend (implemented by `RaguPcdEngine` over Pasta).
pub trait ProofEngine: Send + Sync {
    /// Generates a zero-knowledge proof of unspent object ownership.
    fn prove_ownership(&self, req: &OwnershipProofRequest) -> Result<ProofBytes, ZyozaError>;

    /// Verifies an ownership proof against public inputs.
    fn verify_ownership(
        &self,
        req: &OwnershipVerifyRequest,
        proof: &[u8],
    ) -> Result<bool, ZyozaError>;

    /// Generates (or recursively folds) a state-transition proof.
    fn prove_transition(
        &self,
        prev_proof: Option<&[u8]>,
        step_witness: &[u8],
    ) -> Result<ProofBytes, ZyozaError>;

    /// Verifies a state-transition proof against public inputs.
    fn verify_transition(
        &self,
        proof: &[u8],
        public_inputs: &[u8],
    ) -> Result<bool, ZyozaError>;
}
