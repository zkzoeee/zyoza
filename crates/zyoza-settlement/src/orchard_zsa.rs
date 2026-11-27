use blake2b_simd::Params;
use zyoza_core::{
    AssetBase, AssetId, ZyozaError, OrchardMemoSeal, SettlementAdapter, SettlementReceipt,
    ORCHARD_MEMO_LEN,
};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

const PERSONAL_ZSA_NF: &[u8; 16] = b"ZYOZA-ZSA-NF1___";
const PERSONAL_ZSA_TX: &[u8; 16] = b"ZYOZA-ZSA-TX1___";

/// Native ZIP 226/227 OrchardZSA note representation (`value = 1` for NFTs/Tickets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZsaNote {
    pub tx_id: [u8; 32],
    pub asset_id: AssetId,
    pub asset_base: AssetBase,
    pub value: u64,
    pub finalized_supply: bool,
    pub state_commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub spent: bool,
}

#[derive(Default)]
struct ZsaLedger {
    next_height: u64,
    notes: HashMap<[u8; 32], ZsaNote>,
    spent_nullifiers: HashSet<[u8; 32]>,
    finalized_assets: HashSet<AssetId>,
}

/// Phase 4 `SettlementAdapter` targeting native ZIP 226/227 OrchardZSA notes.
pub struct OrchardZsaAdapter {
    ledger: Mutex<ZsaLedger>,
}

impl Default for OrchardZsaAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl OrchardZsaAdapter {
    /// Creates a new `OrchardZsaAdapter` starting at height 1.
    pub fn new() -> Self {
        Self {
            ledger: Mutex::new(ZsaLedger {
                next_height: 1,
                notes: HashMap::new(),
                spent_nullifiers: HashSet::new(),
                finalized_assets: HashSet::new(),
            }),
        }
    }

    /// Returns the ZSA note for a given state commitment, if present.
    pub fn get_note(&self, commitment: &[u8; 32]) -> Option<ZsaNote> {
        self.ledger.lock().unwrap().notes.get(commitment).cloned()
    }

    fn derive_nullifier(asset_base: &AssetBase, commitment: &[u8; 32]) -> [u8; 32] {
        let mut h = Params::new()
            .hash_length(32)
            .personal(PERSONAL_ZSA_NF)
            .to_state();
        h.update(&asset_base.0);
        h.update(commitment);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }

    fn derive_tx_id(height: u64, commitment: &[u8; 32]) -> [u8; 32] {
        let mut h = Params::new()
            .hash_length(32)
            .personal(PERSONAL_ZSA_TX)
            .to_state();
        h.update(&height.to_be_bytes());
        h.update(commitment);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}

impl SettlementAdapter for OrchardZsaAdapter {
    fn anchor_mint(
        &self,
        asset_id: &AssetId,
        state_commitment: [u8; 32],
        memo: &[u8; ORCHARD_MEMO_LEN],
    ) -> Result<SettlementReceipt, ZyozaError> {
        let parsed = OrchardMemoSeal::from_bytes(memo)?;
        if parsed.asset_id != *asset_id {
            return Err(ZyozaError::Settlement(
                "ZSA mint memo asset_id mismatch".into(),
            ));
        }

        let mut guard = self.ledger.lock().unwrap();
        if !guard.finalized_assets.insert(*asset_id) {
            return Err(ZyozaError::Settlement(
                "ZSA supply already finalized (1/1 NFT)".into(),
            ));
        }

        let asset_base = asset_id.to_asset_base();
        let nullifier = Self::derive_nullifier(&asset_base, &state_commitment);
        let height = guard.next_height;
        guard.next_height += 1;
        let tx_id = Self::derive_tx_id(height, &state_commitment);

        guard.notes.insert(
            state_commitment,
            ZsaNote {
                tx_id,
                asset_id: *asset_id,
                asset_base,
                value: 1,
                finalized_supply: true,
                state_commitment,
                nullifier,
                spent: false,
            },
        );

        Ok(SettlementReceipt {
            backend: "orchard_zsa".to_string(),
            tx_id,
            commitment: state_commitment,
            block_height: Some(height),
        })
    }

    fn anchor_transfer(
        &self,
        asset_id: &AssetId,
        prev_commitment: [u8; 32],
        next_commitment: [u8; 32],
        memo: &[u8; ORCHARD_MEMO_LEN],
    ) -> Result<SettlementReceipt, ZyozaError> {
        let parsed = OrchardMemoSeal::from_bytes(memo)?;
        if parsed.asset_id != *asset_id {
            return Err(ZyozaError::Settlement(
                "ZSA transfer memo asset_id mismatch".into(),
            ));
        }

        let asset_base = asset_id.to_asset_base();
        let mut guard = self.ledger.lock().unwrap();
        let prev_nf = {
            let prev = guard.notes.get_mut(&prev_commitment).ok_or_else(|| {
                ZyozaError::Settlement("ZSA input note not found".into())
            })?;
            if prev.asset_base != asset_base || prev.value != 1 {
                return Err(ZyozaError::Settlement(
                    "ZSA input note asset_base or value mismatch".into(),
                ));
            }
            if prev.spent {
                return Err(ZyozaError::Settlement(
                    "double-spend rejected: ZSA note already spent".into(),
                ));
            }
            prev.spent = true;
            prev.nullifier
        };

        if !guard.spent_nullifiers.insert(prev_nf) {
            return Err(ZyozaError::Settlement(
                "double-spend rejected: ZSA nullifier already spent".into(),
            ));
        }

        let nullifier = Self::derive_nullifier(&asset_base, &next_commitment);
        let height = guard.next_height;
        guard.next_height += 1;
        let tx_id = Self::derive_tx_id(height, &next_commitment);

        guard.notes.insert(
            next_commitment,
            ZsaNote {
                tx_id,
                asset_id: *asset_id,
                asset_base,
                value: 1,
                finalized_supply: true,
                state_commitment: next_commitment,
                nullifier,
                spent: false,
            },
        );

        Ok(SettlementReceipt {
            backend: "orchard_zsa".to_string(),
            tx_id,
            commitment: next_commitment,
            block_height: Some(height),
        })
    }

    fn verify_seal(&self, receipt: &SettlementReceipt) -> Result<bool, ZyozaError> {
        let guard = self.ledger.lock().unwrap();
        Ok(guard
            .notes
            .get(&receipt.commitment)
            .is_some_and(|n| !n.spent && n.tx_id == receipt.tx_id))
    }
}
