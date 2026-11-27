//! Tachyon aggregated bundle (`Tachystamp` / `Tachygram`) & Oblivious Sync adapter.

use blake2b_simd::Params;
use zyoza_core::{
    AssetId, ZyozaError, OrchardMemoSeal, SettlementAdapter, SettlementReceipt, ORCHARD_MEMO_LEN,
};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

const PERSONAL_TACHYGRAM: &[u8; 16] = b"TACHYGRAM-v1____";
const PERSONAL_TACHYSTAMP: &[u8; 16] = b"TACHYSTAMP-v1___";
const PERSONAL_MERKLE_NODE: &[u8; 16] = b"TACHY-MERKLE-v1_";

/// Uniform 32-byte Tachyon accumulator element (commitment or nullifier).
pub type Tachygram = [u8; 32];

/// O(log N) Merkle inclusion witness for oblivious light-client verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleWitness {
    pub epoch: u64,
    pub leaf_index: usize,
    pub siblings: Vec<([u8; 32], bool)>, // (sibling_hash, is_right)
    pub root: [u8; 32],
}

impl MerkleWitness {
    /// Verifies that `gram` is included in `self.root` in O(log N) hashes.
    pub fn verify(&self, gram: &Tachygram) -> bool {
        let mut cur = *gram;
        for (sib, sib_is_right) in &self.siblings {
            cur = if *sib_is_right {
                hash_merkle_node(&cur, sib)
            } else {
                hash_merkle_node(sib, &cur)
            };
        }
        cur == self.root
    }
}

fn hash_merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Params::new()
        .hash_length(32)
        .personal(PERSONAL_MERKLE_NODE)
        .to_state();
    h.update(left);
    h.update(right);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Aggregated Tachyon block/epoch bundle compressing up to tens of thousands of actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tachystamp {
    pub epoch: u64,
    pub root: [u8; 32],
    pub count: usize,
}

#[derive(Default)]
struct TachyonState {
    epoch: u64,
    pending_grams: Vec<Tachygram>,
    epochs: Vec<Tachystamp>,
    live_commitments: HashMap<[u8; 32], AssetId>,
    spent_nullifiers: HashSet<Tachygram>,
    /// Epoch-indexed tachygram buckets for oblivious bucketed sync.
    epoch_buckets: HashMap<u64, Vec<Tachygram>>,
}

/// Phase 5 `SettlementAdapter` supporting Tachyon bundle aggregation and oblivious sync.
pub struct TachyonAdapter {
    state: Mutex<TachyonState>,
}

impl Default for TachyonAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl TachyonAdapter {
    /// Creates a new `TachyonAdapter` at epoch 1.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(TachyonState {
                epoch: 1,
                ..Default::default()
            }),
        }
    }

    /// Computes a deterministic 32-byte `Tachygram` for `(asset_id, commitment)`.
    pub fn compute_tachygram(asset_id: &AssetId, commitment: &[u8; 32]) -> Tachygram {
        let mut h = Params::new()
            .hash_length(32)
            .personal(PERSONAL_TACHYGRAM)
            .to_state();
        h.update(&asset_id.0);
        h.update(commitment);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }

    /// Aggregates all pending tachygrams into a single compact `Tachystamp` epoch root.
    pub fn flush_tachystamp(&self) -> Tachystamp {
        let mut guard = self.state.lock().unwrap();
        let epoch = guard.epoch;
        guard.epoch += 1;

        let grams = std::mem::take(&mut guard.pending_grams);
        let count = grams.len();
        let mut h = Params::new()
            .hash_length(32)
            .personal(PERSONAL_TACHYSTAMP)
            .to_state();
        h.update(&epoch.to_be_bytes());
        for g in &grams {
            h.update(g);
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(h.finalize().as_bytes());

        let stamp = Tachystamp { epoch, root, count };
        guard.epochs.push(stamp.clone());
        guard.epoch_buckets.insert(epoch, grams);
        stamp
    }

    /// Oblivious sync endpoint: returns the full compact tachygram bucket for an epoch
    /// without the server learning which `AssetId` or `Tachygram` the client is checking.
    pub fn fetch_oblivious_epoch_bucket(&self, epoch: u64) -> Vec<Tachygram> {
        self.state
            .lock()
            .unwrap()
            .epoch_buckets
            .get(&epoch)
            .cloned()
            .unwrap_or_default()
    }

    /// Generates an O(log N) Merkle inclusion witness for `gram` in `epoch`,
    /// enabling prunable light-client sync without downloading the full bucket.
    pub fn merkle_witness(&self, epoch: u64, gram: &Tachygram) -> Option<MerkleWitness> {
        let guard = self.state.lock().unwrap();
        let grams = guard.epoch_buckets.get(&epoch)?;
        let pos = grams.iter().position(|g| g == gram)?;

        let mut layer = grams.clone();
        if layer.len() == 1 {
            return Some(MerkleWitness {
                epoch,
                leaf_index: 0,
                siblings: vec![],
                root: layer[0],
            });
        }

        let mut idx = pos;
        let mut siblings = Vec::new();
        while layer.len() > 1 {
            if layer.len() % 2 == 1 {
                layer.push(*layer.last().unwrap());
            }
            let is_right_sib = idx % 2 == 0;
            let sib_idx = if is_right_sib { idx + 1 } else { idx - 1 };
            siblings.push((layer[sib_idx], is_right_sib));

            let mut next = Vec::with_capacity(layer.len() / 2);
            for pair in layer.chunks_exact(2) {
                next.push(hash_merkle_node(&pair[0], &pair[1]));
            }
            layer = next;
            idx /= 2;
        }

        Some(MerkleWitness {
            epoch,
            leaf_index: pos,
            siblings,
            root: layer[0],
        })
    }

    /// Prunes the raw tachygram bucket for `epoch` after clients have synced their O(log N) witnesses.
    pub fn prune_epoch_bucket(&self, epoch: u64) -> bool {
        self.state
            .lock()
            .unwrap()
            .epoch_buckets
            .remove(&epoch)
            .is_some()
    }

    /// Anchors a governed mint into Tachyon's pending `Tachygram` batch, atomically
    /// consuming all collection mint nullifiers and adding them to `pending_grams`.
    pub fn anchor_governed_mint(
        &self,
        spec: &zyoza_core::CollectionSpec,
        claim: &zyoza_core::MintClaim,
        state_commitment: [u8; 32],
        memo: &[u8; ORCHARD_MEMO_LEN],
    ) -> Result<SettlementReceipt, ZyozaError> {
        let parsed = OrchardMemoSeal::from_bytes(memo)?;
        if parsed.asset_id != claim.asset_id {
            return Err(ZyozaError::Settlement("tachyon memo asset_id mismatch".into()));
        }

        {
            let mut guard = self.state.lock().unwrap();
            let nfs = crate::claim_mint_nullifiers(&mut guard.spent_nullifiers, spec, claim)?;
            guard.pending_grams.extend(nfs);
        }

        self.anchor_mint(&claim.asset_id, state_commitment, memo)
    }
}

impl SettlementAdapter for TachyonAdapter {
    fn anchor_mint(
        &self,
        asset_id: &AssetId,
        state_commitment: [u8; 32],
        memo: &[u8; ORCHARD_MEMO_LEN],
    ) -> Result<SettlementReceipt, ZyozaError> {
        let parsed = OrchardMemoSeal::from_bytes(memo)?;
        if parsed.asset_id != *asset_id {
            return Err(ZyozaError::Settlement("tachyon memo asset_id mismatch".into()));
        }

        let gram = Self::compute_tachygram(asset_id, &state_commitment);
        let mut guard = self.state.lock().unwrap();
        let epoch = guard.epoch;
        guard.live_commitments.insert(state_commitment, *asset_id);
        guard.pending_grams.push(gram);

        Ok(SettlementReceipt {
            backend: "tachyon".to_string(),
            tx_id: gram,
            commitment: state_commitment,
            block_height: Some(epoch),
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
            return Err(ZyozaError::Settlement("tachyon memo asset_id mismatch".into()));
        }

        let prev_nf = Self::compute_tachygram(asset_id, &prev_commitment);
        let next_gram = Self::compute_tachygram(asset_id, &next_commitment);

        let mut guard = self.state.lock().unwrap();
        if guard.live_commitments.remove(&prev_commitment).is_none()
            || !guard.spent_nullifiers.insert(prev_nf)
        {
            return Err(ZyozaError::Settlement(
                "double-spend rejected in Tachyon bundle".into(),
            ));
        }

        let epoch = guard.epoch;
        guard.live_commitments.insert(next_commitment, *asset_id);
        guard.pending_grams.push(prev_nf);
        guard.pending_grams.push(next_gram);

        Ok(SettlementReceipt {
            backend: "tachyon".to_string(),
            tx_id: next_gram,
            commitment: next_commitment,
            block_height: Some(epoch),
        })
    }

    fn verify_seal(&self, receipt: &SettlementReceipt) -> Result<bool, ZyozaError> {
        let guard = self.state.lock().unwrap();
        Ok(guard.live_commitments.contains_key(&receipt.commitment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zyoza_core::PROTOCOL_VERSION;

    #[test]
    fn tachyon_10k_drop_aggregation_and_oblivious_sync() {
        let adapter = TachyonAdapter::new();
        let target_asset = AssetId::derive(&[0x01; 32], b"zyoza:drop:4242");
        let target_commit = [0x42; 32];

        let t0 = std::time::Instant::now();
        for i in 0u32..10_000 {
            let mut desc = [0u8; 32];
            desc[..4].copy_from_slice(&i.to_le_bytes());
            let (asset_id, commit) = if i == 4242 {
                (target_asset, target_commit)
            } else {
                (AssetId::derive(&[0x01; 32], &desc), desc)
            };

            let memo = OrchardMemoSeal {
                version: PROTOCOL_VERSION,
                profile_id: *b"NFT1",
                asset_id,
                state_root: commit,
                nonce: [0u8; 32],
                oob_pointer_hash: [0u8; 32],
                oob_uri: "mem://drop".into(),
            }
            .to_bytes()
            .unwrap();
            adapter.anchor_mint(&asset_id, commit, &memo).unwrap();
        }
        let stamp = adapter.flush_tachystamp();
        let agg_ms = t0.elapsed().as_millis();

        assert_eq!(stamp.count, 10_000);
        assert_eq!(stamp.epoch, 1);

        // Oblivious sync: client fetches epoch bucket without revealing target_asset
        let t_sync = std::time::Instant::now();
        let bucket = adapter.fetch_oblivious_epoch_bucket(stamp.epoch);
        let expected_gram = TachyonAdapter::compute_tachygram(&target_asset, &target_commit);
        assert!(bucket.contains(&expected_gram));
        let sync_ms = t_sync.elapsed().as_millis();

        // O(log N) Merkle witness + epoch pruning
        let witness = adapter
            .merkle_witness(stamp.epoch, &expected_gram)
            .expect("witness generated");
        assert_eq!(witness.siblings.len(), 14); // ceil(log2(10000)) = 14
        assert!(witness.verify(&expected_gram));
        assert!(!witness.verify(&[0xFF; 32]));
        assert!(adapter.prune_epoch_bucket(stamp.epoch));
        assert!(adapter.fetch_oblivious_epoch_bucket(stamp.epoch).is_empty());
        assert!(witness.verify(&expected_gram));

        println!(
            "Tachyon 10k-mint drop: aggregate={agg_ms}ms oblivious_sync={sync_ms}ms bucket_len={} merkle_depth={}",
            bucket.len(),
            witness.siblings.len()
        );
    }
}
