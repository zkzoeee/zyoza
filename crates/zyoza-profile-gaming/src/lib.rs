//! Gaming / Mutable-State vertical profile (`GAM1`) for Zyoza.

use zyoza_core::{
    AssetId, AssetProfile, ZyozaError, ObjectViewingKey, ProfileId, ProfilePreview,
};
use serde::{Deserialize, Serialize};

/// 4-byte profile identifier for Zyoza Gaming items.
pub const GAME_PROFILE_ID: ProfileId = *b"GAM1";

/// Mutable off-chain state of a `GAM1` Zyoza game item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameItemState {
    pub asset_id: AssetId,
    pub game_id: String,
    pub item_name: String,
    pub rarity: String,
    pub level: u32,
    pub xp: u64,
    pub equipped_slots: Vec<String>,
    pub soulbound: bool,
    pub upgrade_count: u64,
}

impl GameItemState {
    /// Serializes the game item state to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZyozaError> {
        serde_json::to_vec(self)
            .map_err(|e| ZyozaError::InvalidEncoding(format!("game state serialize: {e}")))
    }

    /// Parses a `GameItemState` from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZyozaError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ZyozaError::InvalidEncoding(format!("game state parse: {e}")))
    }
}

/// Allowed `GAM1` state-transition actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GameAction {
    Mint,
    Transfer,
    Upgrade { xp_cost: u64 },
    Equip { slot: String },
}

/// Witness supplied when validating a `GAM1` transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameTransitionWitness {
    pub action: GameAction,
}

/// `AssetProfile` implementation for `GAM1`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GameProfile;

impl AssetProfile for GameProfile {
    fn profile_id(&self) -> ProfileId {
        GAME_PROFILE_ID
    }

    fn validate_transition(
        &self,
        prev_state: Option<&[u8]>,
        next_state: &[u8],
        witness: &[u8],
    ) -> Result<(), ZyozaError> {
        let next = GameItemState::from_bytes(next_state)?;
        let wit: GameTransitionWitness = serde_json::from_slice(witness)
            .map_err(|e| ZyozaError::InvalidTransition(format!("bad game witness: {e}")))?;

        if next.game_id.trim().is_empty() || next.item_name.trim().is_empty() {
            return Err(ZyozaError::InvalidTransition(
                "game_id and item_name must be non-empty".into(),
            ));
        }

        match prev_state {
            None => {
                if wit.action != GameAction::Mint || next.level == 0 {
                    return Err(ZyozaError::InvalidTransition(
                        "mint requires GameAction::Mint and level >= 1".into(),
                    ));
                }
                Ok(())
            }
            Some(prev_bytes) => {
                let prev = GameItemState::from_bytes(prev_bytes)?;
                if prev.asset_id != next.asset_id || prev.game_id != next.game_id {
                    return Err(ZyozaError::InvalidTransition(
                        "immutable game item fields modified".into(),
                    ));
                }
                match wit.action {
                    GameAction::Mint => Err(ZyozaError::InvalidTransition(
                        "cannot mint over existing item".into(),
                    )),
                    GameAction::Transfer => {
                        if prev.soulbound {
                            return Err(ZyozaError::InvalidTransition(
                                "soulbound game item cannot be transferred".into(),
                            ));
                        }
                        Ok(())
                    }
                    GameAction::Upgrade { xp_cost } => {
                        if next.level != prev.level + 1
                            || next.upgrade_count != prev.upgrade_count + 1
                            || prev.xp < xp_cost
                            || next.xp != prev.xp - xp_cost
                        {
                            return Err(ZyozaError::InvalidTransition(
                                "invalid upgrade level, count, or XP deduction".into(),
                            ));
                        }
                        Ok(())
                    }
                    GameAction::Equip { slot } => {
                        if !next.equipped_slots.contains(&slot) {
                            return Err(ZyozaError::InvalidTransition(
                                "equip must include target slot".into(),
                            ));
                        }
                        Ok(())
                    }
                }
            }
        }
    }

    fn public_preview(
        &self,
        state: &[u8],
        viewing_key: Option<&ObjectViewingKey>,
    ) -> Result<ProfilePreview, ZyozaError> {
        let item = GameItemState::from_bytes(state)?;
        let authorized = viewing_key.is_some_and(|ovk| ovk.asset_id == item.asset_id);
        if authorized {
            Ok(ProfilePreview {
                profile_id: GAME_PROFILE_ID,
                title: format!("{} (Lv.{})", item.item_name, item.level),
                summary: format!("{} — {} [{}]", item.game_id, item.rarity, item.xp),
                attributes_json: serde_json::json!({
                    "game_id": item.game_id,
                    "rarity": item.rarity,
                    "level": item.level,
                    "xp": item.xp,
                    "equipped_slots": item.equipped_slots,
                })
                .to_string(),
            })
        } else {
            Ok(ProfilePreview {
                profile_id: GAME_PROFILE_ID,
                title: "Shielded Zyoza Game Item".to_string(),
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
    fn game_item_mint_upgrade_equip_and_soulbound_guard() {
        let profile = GameProfile;
        let asset_id = AssetId::derive(&[0x01; 32], b"zyoza:game:blade:1");

        let mint = GameItemState {
            asset_id,
            game_id: "shadow-dumpling".into(),
            item_name: "Obsidian Cleaver".into(),
            rarity: "mythic".into(),
            level: 1,
            xp: 500,
            equipped_slots: vec![],
            soulbound: true,
            upgrade_count: 0,
        };
        let mint_bytes = mint.to_bytes().unwrap();
        let w_mint = serde_json::to_vec(&GameTransitionWitness {
            action: GameAction::Mint,
        })
        .unwrap();
        profile.validate_transition(None, &mint_bytes, &w_mint).unwrap();

        // Soulbound transfer fails
        let w_xfer = serde_json::to_vec(&GameTransitionWitness {
            action: GameAction::Transfer,
        })
        .unwrap();
        assert!(profile
            .validate_transition(Some(&mint_bytes), &mint_bytes, &w_xfer)
            .is_err());

        // Upgrade Lv1 -> Lv2 spending 200 XP
        let mut upgraded = mint.clone();
        upgraded.level = 2;
        upgraded.xp = 300;
        upgraded.upgrade_count = 1;
        let upg_bytes = upgraded.to_bytes().unwrap();
        let w_upg = serde_json::to_vec(&GameTransitionWitness {
            action: GameAction::Upgrade { xp_cost: 200 },
        })
        .unwrap();
        profile
            .validate_transition(Some(&mint_bytes), &upg_bytes, &w_upg)
            .unwrap();

        // Equip main_hand
        let mut equipped = upgraded.clone();
        equipped.equipped_slots.push("main_hand".into());
        let eq_bytes = equipped.to_bytes().unwrap();
        let w_eq = serde_json::to_vec(&GameTransitionWitness {
            action: GameAction::Equip {
                slot: "main_hand".into(),
            },
        })
        .unwrap();
        profile
            .validate_transition(Some(&upg_bytes), &eq_bytes, &w_eq)
            .unwrap();
    }
}
