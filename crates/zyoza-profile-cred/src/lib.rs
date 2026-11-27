//! Soulbound / Credential vertical profile (`CRD1`) for Zyoza (Phase 3).

use blake2b_simd::Params;
use zyoza_core::{
    AssetId, AssetProfile, ZyozaError, ObjectViewingKey, ProfileId, ProfilePreview,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Mutex;

/// 4-byte profile identifier for Zyoza Soulbound Credentials.
pub const CRED_PROFILE_ID: ProfileId = *b"CRD1";

/// Off-chain state of a `CRD1` Zyoza soulbound credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialState {
    pub asset_id: AssetId,
    pub issuer_id: String,
    pub claim_type: String,
    pub claim_summary: String,
    pub claim_commitment: [u8; 32],
    pub soulbound: bool,
    pub revoked: bool,
}

impl CredentialState {
    /// Serializes the credential state to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZyozaError> {
        serde_json::to_vec(self)
            .map_err(|e| ZyozaError::InvalidEncoding(format!("cred state serialize: {e}")))
    }

    /// Parses a `CredentialState` from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZyozaError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ZyozaError::InvalidEncoding(format!("cred state parse: {e}")))
    }

    /// Computes a deterministic revocation tag for accumulator checks.
    pub fn revocation_tag(&self) -> [u8; 32] {
        let mut h = Params::new()
            .hash_length(32)
            .personal(b"ZYOZA-CRD-REV1__")
            .to_state();
        h.update(&self.asset_id.0);
        h.update(&self.claim_commitment);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}

/// Witness for `CRD1` transitions (only issuer revocation is permitted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialWitness {
    pub is_revocation: bool,
}

/// `AssetProfile` implementation for `CRD1` (non-transferable / soulbound).
#[derive(Debug, Default, Clone, Copy)]
pub struct CredentialProfile;

impl AssetProfile for CredentialProfile {
    fn profile_id(&self) -> ProfileId {
        CRED_PROFILE_ID
    }

    fn validate_transition(
        &self,
        prev_state: Option<&[u8]>,
        next_state: &[u8],
        witness: &[u8],
    ) -> Result<(), ZyozaError> {
        let next = CredentialState::from_bytes(next_state)?;
        let wit: CredentialWitness = serde_json::from_slice(witness)
            .map_err(|e| ZyozaError::InvalidTransition(format!("bad cred witness: {e}")))?;

        if next.issuer_id.trim().is_empty() || next.claim_type.trim().is_empty() {
            return Err(ZyozaError::InvalidTransition(
                "issuer_id and claim_type must be non-empty".into(),
            ));
        }

        match prev_state {
            None => {
                if !next.soulbound {
                    return Err(ZyozaError::InvalidTransition(
                        "CRD1 credentials must be soulbound".into(),
                    ));
                }
                Ok(())
            }
            Some(prev_bytes) => {
                let prev = CredentialState::from_bytes(prev_bytes)?;
                if !wit.is_revocation {
                    return Err(ZyozaError::InvalidTransition(
                        "soulbound credential cannot be transferred".into(),
                    ));
                }
                if prev.asset_id != next.asset_id || !next.revoked {
                    return Err(ZyozaError::InvalidTransition(
                        "revocation must preserve asset_id and set revoked = true".into(),
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
        let cred = CredentialState::from_bytes(state)?;
        let authorized = viewing_key.is_some_and(|ovk| ovk.asset_id == cred.asset_id);
        if authorized {
            Ok(ProfilePreview {
                profile_id: CRED_PROFILE_ID,
                title: format!("{} ({})", cred.claim_type, cred.issuer_id),
                summary: if cred.revoked {
                    "REVOKED".to_string()
                } else {
                    cred.claim_summary
                },
                attributes_json: serde_json::json!({
                    "issuer": cred.issuer_id,
                    "claim_type": cred.claim_type,
                    "revoked": cred.revoked,
                })
                .to_string(),
            })
        } else {
            Ok(ProfilePreview {
                profile_id: CRED_PROFILE_ID,
                title: "Shielded Zyoza Credential".to_string(),
                summary: "shielded (ObjectViewingKey required)".to_string(),
                attributes_json: "{}".to_string(),
            })
        }
    }
}

/// Issuer revocation registry tracking revoked credential tags.
#[derive(Default)]
pub struct RevocationRegistry {
    revoked_tags: Mutex<HashSet<[u8; 32]>>,
}

impl RevocationRegistry {
    /// Marks a credential revocation tag as revoked.
    pub fn revoke(&self, tag: [u8; 32]) {
        self.revoked_tags.lock().unwrap().insert(tag);
    }

    /// Returns `true` if the credential is still active (not revoked).
    pub fn is_active(&self, cred: &CredentialState) -> bool {
        !cred.revoked && !self.revoked_tags.lock().unwrap().contains(&cred.revocation_tag())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soulbound_transfer_rejected_and_revocation_enforced() {
        let profile = CredentialProfile;
        let asset_id = AssetId::derive(&[0x01; 32], b"zyoza:cred:kyc:42");

        let cred = CredentialState {
            asset_id,
            issuer_id: "zcash-dao".into(),
            claim_type: "CoreContributor".into(),
            claim_summary: "2026 Cohort".into(),
            claim_commitment: [0x77; 32],
            soulbound: true,
            revoked: false,
        };
        let cred_bytes = cred.to_bytes().unwrap();

        let wit_mint = serde_json::to_vec(&CredentialWitness { is_revocation: false }).unwrap();
        profile.validate_transition(None, &cred_bytes, &wit_mint).unwrap();

        // Transfer attempt MUST FAIL (soulbound)
        assert!(profile
            .validate_transition(Some(&cred_bytes), &cred_bytes, &wit_mint)
            .is_err());

        let registry = RevocationRegistry::default();
        assert!(registry.is_active(&cred));

        // Revoke credential
        let mut revoked = cred.clone();
        revoked.revoked = true;
        let revoked_bytes = revoked.to_bytes().unwrap();
        let wit_rev = serde_json::to_vec(&CredentialWitness { is_revocation: true }).unwrap();
        profile
            .validate_transition(Some(&cred_bytes), &revoked_bytes, &wit_rev)
            .unwrap();
        registry.revoke(cred.revocation_tag());
        assert!(!registry.is_active(&cred));
        assert!(!registry.is_active(&revoked));
    }
}
