//! Private Real-World Asset (RWA) / Deed vertical profile (`RWA1`) for Zyoza.

use zyoza_core::{
    AssetId, AssetProfile, ZyozaError, ObjectViewingKey, ProfileId, ProfilePreview,
};
use serde::{Deserialize, Serialize};

/// 4-byte profile identifier for Zyoza RWAs & Deeds.
pub const RWA_PROFILE_ID: ProfileId = *b"RWA1";

/// Off-chain state of a `RWA1` Zyoza deed or invoice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwaDeedState {
    pub asset_id: AssetId,
    pub jurisdiction: String,
    pub asset_class: String,
    pub deed_title: String,
    pub valuation_usd_cents: u64,
    pub required_cred_claim: String,
    pub issuer_notary: String,
    pub encumbered: bool,
}

impl RwaDeedState {
    /// Serializes the RWA deed state to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZyozaError> {
        serde_json::to_vec(self)
            .map_err(|e| ZyozaError::InvalidEncoding(format!("rwa state serialize: {e}")))
    }

    /// Parses an `RwaDeedState` from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZyozaError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ZyozaError::InvalidEncoding(format!("rwa state parse: {e}")))
    }
}

/// Selective-disclosure compliance witness for `RWA1` transfers (`CRD1` + `RWA1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwaTransitionWitness {
    pub is_transfer: bool,
    pub holder_cred_active: bool,
    pub holder_cred_claim_type: String,
    pub notary_approved: bool,
}

/// `AssetProfile` implementation for `RWA1`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RwaProfile;

impl AssetProfile for RwaProfile {
    fn profile_id(&self) -> ProfileId {
        RWA_PROFILE_ID
    }

    fn validate_transition(
        &self,
        prev_state: Option<&[u8]>,
        next_state: &[u8],
        witness: &[u8],
    ) -> Result<(), ZyozaError> {
        let next = RwaDeedState::from_bytes(next_state)?;
        let wit: RwaTransitionWitness = serde_json::from_slice(witness)
            .map_err(|e| ZyozaError::InvalidTransition(format!("bad rwa witness: {e}")))?;

        if next.jurisdiction.trim().is_empty() || next.deed_title.trim().is_empty() {
            return Err(ZyozaError::InvalidTransition(
                "jurisdiction and deed_title must be non-empty".into(),
            ));
        }

        match prev_state {
            None => {
                if !wit.notary_approved {
                    return Err(ZyozaError::InvalidTransition(
                        "RWA mint requires notary approval".into(),
                    ));
                }
                Ok(())
            }
            Some(prev_bytes) => {
                let prev = RwaDeedState::from_bytes(prev_bytes)?;
                if prev.asset_id != next.asset_id
                    || prev.jurisdiction != next.jurisdiction
                    || prev.issuer_notary != next.issuer_notary
                {
                    return Err(ZyozaError::InvalidTransition(
                        "immutable RWA deed fields modified".into(),
                    ));
                }
                if wit.is_transfer {
                    if prev.encumbered {
                        return Err(ZyozaError::InvalidTransition(
                            "encumbered RWA deed cannot be transferred".into(),
                        ));
                    }
                    if !wit.holder_cred_active
                        || wit.holder_cred_claim_type != prev.required_cred_claim
                    {
                        return Err(ZyozaError::InvalidTransition(
                            "recipient lacks active required CRD1 compliance credential".into(),
                        ));
                    }
                    if !wit.notary_approved {
                        return Err(ZyozaError::InvalidTransition(
                            "RWA transfer requires notary countersignature".into(),
                        ));
                    }
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
        let rwa = RwaDeedState::from_bytes(state)?;
        let authorized = viewing_key.is_some_and(|ovk| ovk.asset_id == rwa.asset_id);
        if authorized {
            Ok(ProfilePreview {
                profile_id: RWA_PROFILE_ID,
                title: rwa.deed_title,
                summary: format!(
                    "{} ({}) — ${:.2}",
                    rwa.asset_class,
                    rwa.jurisdiction,
                    (rwa.valuation_usd_cents as f64) / 100.0
                ),
                attributes_json: serde_json::json!({
                    "jurisdiction": rwa.jurisdiction,
                    "asset_class": rwa.asset_class,
                    "required_cred_claim": rwa.required_cred_claim,
                    "encumbered": rwa.encumbered,
                })
                .to_string(),
            })
        } else {
            Ok(ProfilePreview {
                profile_id: RWA_PROFILE_ID,
                title: "Shielded Zyoza RWA Deed".to_string(),
                summary: "shielded (ObjectViewingKey required)".to_string(),
                attributes_json: "{}".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rwa_compliance_credential_and_encumbrance_enforcement() {
        let profile = RwaProfile;
        let asset_id = AssetId::derive(&[0x01; 32], b"zyoza:rwa:tbill:1");

        let deed = RwaDeedState {
            asset_id,
            jurisdiction: "CH-ZUG".into(),
            asset_class: "TreasuryBill".into(),
            deed_title: "Zug Treasury Note #1".into(),
            valuation_usd_cents: 10_000_000,
            required_cred_claim: "AccreditedInvestor".into(),
            issuer_notary: "notary-ch".into(),
            encumbered: false,
        };
        let deed_bytes = deed.to_bytes().unwrap();

        let w_mint = serde_json::to_vec(&RwaTransitionWitness {
            is_transfer: false,
            holder_cred_active: true,
            holder_cred_claim_type: "AccreditedInvestor".into(),
            notary_approved: true,
        })
        .unwrap();
        profile.validate_transition(None, &deed_bytes, &w_mint).unwrap();

        // Compliant transfer succeeds
        let w_ok = serde_json::to_vec(&RwaTransitionWitness {
            is_transfer: true,
            holder_cred_active: true,
            holder_cred_claim_type: "AccreditedInvestor".into(),
            notary_approved: true,
        })
        .unwrap();
        profile
            .validate_transition(Some(&deed_bytes), &deed_bytes, &w_ok)
            .unwrap();

        // Missing CRD1 credential fails
        let w_no_cred = serde_json::to_vec(&RwaTransitionWitness {
            is_transfer: true,
            holder_cred_active: false,
            holder_cred_claim_type: "AccreditedInvestor".into(),
            notary_approved: true,
        })
        .unwrap();
        assert!(profile
            .validate_transition(Some(&deed_bytes), &deed_bytes, &w_no_cred)
            .is_err());

        // Encumbered deed transfer fails
        let mut enc = deed.clone();
        enc.encumbered = true;
        let enc_bytes = enc.to_bytes().unwrap();
        assert!(profile
            .validate_transition(Some(&enc_bytes), &enc_bytes, &w_ok)
            .is_err());
    }
}
