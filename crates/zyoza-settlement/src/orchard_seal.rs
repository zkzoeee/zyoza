use blake2b_simd::Params;
use zyoza_core::{
    AssetId, ZyozaError, OrchardMemoSeal, SettlementAdapter, SettlementReceipt, ORCHARD_MEMO_LEN,
};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

const PERSONAL_SEAL_NF: &[u8; 16] = b"ZYOZA-SEAL-NF1__";
const PERSONAL_TX_ID: &[u8; 16] = b"ZYOZA-TXID-v1___";

/// Recorded Orchard single-use seal anchored on-chain (or in a local regtest ledger).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrchardSealRecord {
    pub tx_id: [u8; 32],
    pub block_height: u64,
    pub asset_id: AssetId,
    pub state_commitment: [u8; 32],
    pub memo: [u8; ORCHARD_MEMO_LEN],
    pub nullifier: [u8; 32],
    pub spent: bool,
}

#[derive(Default)]
struct LedgerState {
    next_height: u64,
    seals: HashMap<[u8; 32], OrchardSealRecord>,
    spent_nullifiers: HashSet<[u8; 32]>,
}

/// Phase 1 `SettlementAdapter` anchoring Zyoza commitments in 512-byte Orchard memo seals.
pub struct OrchardSealAdapter {
    state: Mutex<LedgerState>,
}

impl Default for OrchardSealAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl OrchardSealAdapter {
    /// Creates a new `OrchardSealAdapter` starting at block height 1.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(LedgerState {
                next_height: 1,
                seals: HashMap::new(),
                spent_nullifiers: HashSet::new(),
            }),
        }
    }

    /// Derives a real Orchard shielded payment address (`[u8; 43]` raw encoding) from a 32-byte ZIP-32 seed
    /// using the `orchard` protocol crate (`SpendingKey -> FullViewingKey -> Address`).
    pub fn derive_orchard_address(seed: &[u8; 32]) -> Result<[u8; 43], ZyozaError> {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};
        let mut candidate = *seed;
        for ctr in 0u8..=255 {
            candidate[0] = seed[0].wrapping_add(ctr);
            if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(candidate)) {
                let fvk = FullViewingKey::from(&sk);
                let addr = fvk.address_at(0u32, Scope::External);
                return Ok(addr.to_raw_address_bytes());
            }
        }
        Err(ZyozaError::Settlement("unable to derive Orchard SpendingKey".into()))
    }

    /// Scans and parses a 512-byte Orchard memo into an `OrchardMemoSeal`.
    pub fn scan_memo(memo: &[u8; ORCHARD_MEMO_LEN]) -> Result<OrchardMemoSeal, ZyozaError> {
        OrchardMemoSeal::from_bytes(memo)
    }

    /// Looks up a seal record by its 32-byte state commitment.
    pub fn get_seal(&self, commitment: &[u8; 32]) -> Option<OrchardSealRecord> {
        self.state.lock().unwrap().seals.get(commitment).cloned()
    }

    /// Anchors a mint governed by a `CollectionSpec` (1/1 unique, capped supply, unique media,
    /// or timed drop) by atomically consuming its deterministic mint nullifiers.
    pub fn anchor_governed_mint(
        &self,
        spec: &zyoza_core::CollectionSpec,
        claim: &zyoza_core::MintClaim,
        state_commitment: [u8; 32],
        memo: &[u8; ORCHARD_MEMO_LEN],
    ) -> Result<SettlementReceipt, ZyozaError> {
        let parsed = OrchardMemoSeal::from_bytes(memo)?;
        if parsed.asset_id != claim.asset_id {
            return Err(ZyozaError::Settlement(
                "memo asset_id does not match claim asset_id".to_string(),
            ));
        }

        {
            let mut guard = self.state.lock().unwrap();
            crate::claim_mint_nullifiers(&mut guard.spent_nullifiers, spec, claim)?;
        }

        self.anchor_mint(&claim.asset_id, state_commitment, memo)
    }

    fn derive_nullifier(asset_id: &AssetId, commitment: &[u8; 32]) -> [u8; 32] {
        let mut h = Params::new()
            .hash_length(32)
            .personal(PERSONAL_SEAL_NF)
            .to_state();
        h.update(&asset_id.0);
        h.update(commitment);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }

    fn derive_tx_id(height: u64, commitment: &[u8; 32]) -> [u8; 32] {
        let mut h = Params::new()
            .hash_length(32)
            .personal(PERSONAL_TX_ID)
            .to_state();
        h.update(&height.to_be_bytes());
        h.update(commitment);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }
}

impl SettlementAdapter for OrchardSealAdapter {
    fn anchor_mint(
        &self,
        asset_id: &AssetId,
        state_commitment: [u8; 32],
        memo: &[u8; ORCHARD_MEMO_LEN],
    ) -> Result<SettlementReceipt, ZyozaError> {
        let parsed = OrchardMemoSeal::from_bytes(memo)?;
        if parsed.asset_id != *asset_id {
            return Err(ZyozaError::Settlement(
                "memo asset_id does not match mint asset_id".to_string(),
            ));
        }

        let mut guard = self.state.lock().unwrap();
        if guard.seals.contains_key(&state_commitment) {
            return Err(ZyozaError::Settlement(
                "commitment already anchored".to_string(),
            ));
        }

        let height = guard.next_height;
        guard.next_height += 1;
        let tx_id = Self::derive_tx_id(height, &state_commitment);
        let nullifier = Self::derive_nullifier(asset_id, &state_commitment);

        guard.seals.insert(
            state_commitment,
            OrchardSealRecord {
                tx_id,
                block_height: height,
                asset_id: *asset_id,
                state_commitment,
                memo: *memo,
                nullifier,
                spent: false,
            },
        );

        Ok(SettlementReceipt {
            backend: "orchard_seal".to_string(),
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
                "memo asset_id does not match transfer asset_id".to_string(),
            ));
        }

        let mut guard = self.state.lock().unwrap();
        let prev_nf = {
            let prev = guard.seals.get_mut(&prev_commitment).ok_or_else(|| {
                ZyozaError::Settlement("previous seal commitment not found".to_string())
            })?;
            if prev.asset_id != *asset_id {
                return Err(ZyozaError::Settlement(
                    "previous seal asset_id mismatch".to_string(),
                ));
            }
            if prev.spent {
                return Err(ZyozaError::Settlement(
                    "double-spend rejected: previous seal already spent".to_string(),
                ));
            }
            prev.spent = true;
            prev.nullifier
        };

        if !guard.spent_nullifiers.insert(prev_nf) {
            return Err(ZyozaError::Settlement(
                "double-spend rejected: nullifier already revealed".to_string(),
            ));
        }

        if guard.seals.contains_key(&next_commitment) {
            return Err(ZyozaError::Settlement(
                "next commitment already exists".to_string(),
            ));
        }

        let height = guard.next_height;
        guard.next_height += 1;
        let tx_id = Self::derive_tx_id(height, &next_commitment);
        let nullifier = Self::derive_nullifier(asset_id, &next_commitment);

        guard.seals.insert(
            next_commitment,
            OrchardSealRecord {
                tx_id,
                block_height: height,
                asset_id: *asset_id,
                state_commitment: next_commitment,
                memo: *memo,
                nullifier,
                spent: false,
            },
        );

        Ok(SettlementReceipt {
            backend: "orchard_seal".to_string(),
            tx_id,
            commitment: next_commitment,
            block_height: Some(height),
        })
    }

    fn verify_seal(&self, receipt: &SettlementReceipt) -> Result<bool, ZyozaError> {
        let guard = self.state.lock().unwrap();
        Ok(guard
            .seals
            .get(&receipt.commitment)
            .is_some_and(|rec| !rec.spent && rec.tx_id == receipt.tx_id))
    }
}
