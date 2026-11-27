//! Ticketing & Access vertical profile (`TKT1`) for Zyoza (Phase 3).

use blake2b_simd::Params;
use zyoza_core::{
    AssetId, AssetProfile, ZyozaError, ObjectViewingKey, ProfileId, ProfilePreview,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Mutex;

/// 4-byte profile identifier for Zyoza Tickets.
pub const TICKET_PROFILE_ID: ProfileId = *b"TKT1";

const PERSONAL_CHECKIN_NF: &[u8; 16] = b"ZYOZA-TKT-NF1___";

/// Off-chain state of a `TKT1` Zyoza ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketState {
    pub asset_id: AssetId,
    pub event_id: String,
    pub event_name: String,
    pub seat_tier: String,
    pub transferable: bool,
    pub checked_in: bool,
}

impl TicketState {
    /// Serializes the ticket state to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZyozaError> {
        serde_json::to_vec(self)
            .map_err(|e| ZyozaError::InvalidEncoding(format!("ticket state serialize: {e}")))
    }

    /// Parses a `TicketState` from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZyozaError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ZyozaError::InvalidEncoding(format!("ticket state parse: {e}")))
    }

    /// Derives the one-time anonymous check-in nullifier `Hash(secret || event_id)`.
    pub fn derive_checkin_nullifier(&self, holder_secret: &[u8]) -> [u8; 32] {
        let mut h = Params::new()
            .hash_length(32)
            .personal(PERSONAL_CHECKIN_NF)
            .to_state();
        h.update(holder_secret);
        h.update(self.event_id.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}

/// Witness for `TKT1` state transitions (resale vs check-in).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketTransitionWitness {
    pub is_checkin: bool,
}

/// `AssetProfile` implementation for `TKT1`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TicketProfile;

impl AssetProfile for TicketProfile {
    fn profile_id(&self) -> ProfileId {
        TICKET_PROFILE_ID
    }

    fn validate_transition(
        &self,
        prev_state: Option<&[u8]>,
        next_state: &[u8],
        witness: &[u8],
    ) -> Result<(), ZyozaError> {
        let next = TicketState::from_bytes(next_state)?;
        let wit: TicketTransitionWitness = serde_json::from_slice(witness)
            .map_err(|e| ZyozaError::InvalidTransition(format!("bad ticket witness: {e}")))?;

        if next.event_id.trim().is_empty() || next.seat_tier.trim().is_empty() {
            return Err(ZyozaError::InvalidTransition(
                "event_id and seat_tier must be non-empty".into(),
            ));
        }

        match prev_state {
            None => {
                if next.checked_in {
                    return Err(ZyozaError::InvalidTransition(
                        "newly minted ticket cannot start checked_in".into(),
                    ));
                }
                Ok(())
            }
            Some(prev_bytes) => {
                let prev = TicketState::from_bytes(prev_bytes)?;
                if prev.asset_id != next.asset_id
                    || prev.event_id != next.event_id
                    || prev.seat_tier != next.seat_tier
                {
                    return Err(ZyozaError::InvalidTransition(
                        "immutable ticket fields modified".into(),
                    ));
                }
                if prev.checked_in {
                    return Err(ZyozaError::InvalidTransition(
                        "ticket already checked in".into(),
                    ));
                }
                if !wit.is_checkin && !prev.transferable {
                    return Err(ZyozaError::InvalidTransition(
                        "ticket is non-transferable".into(),
                    ));
                }
                if wit.is_checkin && !next.checked_in {
                    return Err(ZyozaError::InvalidTransition(
                        "check-in transition must set checked_in = true".into(),
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
        let tkt = TicketState::from_bytes(state)?;
        let authorized = viewing_key.is_some_and(|ovk| ovk.asset_id == tkt.asset_id);
        if authorized {
            Ok(ProfilePreview {
                profile_id: TICKET_PROFILE_ID,
                title: tkt.event_name,
                summary: format!("Tier: {} (checked_in={})", tkt.seat_tier, tkt.checked_in),
                attributes_json: serde_json::json!({
                    "event_id": tkt.event_id,
                    "seat_tier": tkt.seat_tier,
                    "checked_in": tkt.checked_in,
                })
                .to_string(),
            })
        } else {
            Ok(ProfilePreview {
                profile_id: TICKET_PROFILE_ID,
                title: "Shielded Zyoza Ticket".to_string(),
                summary: "shielded (ObjectViewingKey required)".to_string(),
                attributes_json: "{}".to_string(),
            })
        }
    }
}

/// Venue door gatekeeper enforcing one-time anonymous check-in via nullifiers.
#[derive(Default)]
pub struct TicketGatekeeper {
    spent_nullifiers: Mutex<HashSet<[u8; 32]>>,
}

impl TicketGatekeeper {
    /// Verifies and consumes a one-time check-in nullifier, rejecting any replay.
    pub fn check_in(&self, nullifier: [u8; 32]) -> Result<(), ZyozaError> {
        let mut guard = self.spent_nullifiers.lock().unwrap();
        if !guard.insert(nullifier) {
            return Err(ZyozaError::InvalidTransition(
                "ticket replay rejected: check-in nullifier already used".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_mint_resale_and_anonymous_checkin_replay_rejection() {
        let profile = TicketProfile;
        let asset_id = AssetId::derive(&[0x01; 32], b"zyoza:ticket:zcon:vip-1");

        let mint = TicketState {
            asset_id,
            event_id: "zcon-2026".into(),
            event_name: "Zcon 2026".into(),
            seat_tier: "VIP".into(),
            transferable: true,
            checked_in: false,
        };
        let mint_bytes = mint.to_bytes().unwrap();

        let wit_mint = serde_json::to_vec(&TicketTransitionWitness { is_checkin: false }).unwrap();
        profile.validate_transition(None, &mint_bytes, &wit_mint).unwrap();

        // Private resale
        let resale_bytes = mint.to_bytes().unwrap();
        profile
            .validate_transition(Some(&mint_bytes), &resale_bytes, &wit_mint)
            .unwrap();

        // Check-in transition + gatekeeper nullifier
        let mut checked = mint.clone();
        checked.checked_in = true;
        let checked_bytes = checked.to_bytes().unwrap();
        let wit_in = serde_json::to_vec(&TicketTransitionWitness { is_checkin: true }).unwrap();
        profile
            .validate_transition(Some(&resale_bytes), &checked_bytes, &wit_in)
            .unwrap();

        let gate = TicketGatekeeper::default();
        let nf = checked.derive_checkin_nullifier(b"bob-ticket-secret");
        gate.check_in(nf).unwrap();
        // Replay must fail!
        assert!(gate.check_in(nf).is_err());

        // Further transition after check-in must fail!
        assert!(profile
            .validate_transition(Some(&checked_bytes), &checked_bytes, &wit_mint)
            .is_err());
    }
}
