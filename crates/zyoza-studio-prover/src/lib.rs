//! Zyoza Studio proof jobs.
//!
//! A [`ProofJob`] is everything an owner's device needs to produce one Studio proof, as plain
//! data. The server prepares a job and later checks the [`ProofOutput`]; the proving in between
//! runs wherever this crate runs: natively in tests, or in the visitor's browser when the crate
//! is compiled to WebAssembly (see the `wasm` module and `scripts/build-studio-wasm.sh`).
//!
//! The lineage proof itself (about 34 MB uncompressed) never leaves the prover. A
//! [`LineageStore`] keeps it, and only the public part (header fields plus the 6 KB compressed
//! proof) is sent to the server.
//!
//! Studio actors (`alice`, `bob`, `carol`) use fixed, publicly derivable stand-in secrets, so
//! this demonstrates where proving happens, not key custody.

use blake2b_simd::Params as Blake2bParams;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zyoza_core::{AssetId, OwnershipProofRequest, ProofEngine};
use zyoza_proofs::{
    derive_creator_tag, derive_owner_tag, IssuanceCapEngine, RaguCapProof, RaguPcdEngine,
    RaguPcdProof, RaguStepKind, RaguStepWitness,
};

/// Demo stand-in for the creator's royalty receipt secret.
pub const CREATOR_ROYALTY_SECRET: &[u8] = b"zyoza-demo-creator-escrow-receipt-key";
/// Receipt secret used by the Studio's "unpaid royalty" negative test.
pub const UNPAID_ROYALTY_SECRET: &[u8] = b"unpaid-missing-receipt";
/// The event Studio tickets check in to.
pub const TICKET_EVENT_ID: [u8; 32] = *b"ZCON-2026-MAIN-STAGE-EVENT-ID-01";
/// Owner secret used by the Studio's "wrong secret" negative test.
pub const WRONG_OWNER_SECRET: &[u8] = b"wrong-attacker-secret-0000000000";

/// Derives a deterministic 32-byte demo secret stand-in for simulated Studio actors (`alice`, `bob`, `carol`).
pub fn derive_demo_actor_secret(actor: &str) -> [u8; 32] {
    let mut h = Blake2bParams::new()
        .hash_length(32)
        .personal(b"ZYOZA-DEMO-ACT1_")
        .to_state();
    h.update(actor.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// One proof the Studio asks an owner to produce.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ProofJob {
    /// Seed the lineage (`MintCircuit`) and prove the slot is within the supply cap.
    Mint {
        asset_id: AssetId,
        commitment: [u8; 32],
        collection_id: [u8; 32],
        token_index: u64,
        cap_blinding: [u8; 32],
        max_supply: u64,
    },
    /// Fold one step onto the stored lineage and compress it for the verifier.
    Fold {
        asset_id: AssetId,
        kind: RaguStepKind,
        profile_id: [u8; 4],
        next_commit: [u8; 32],
        owner: String,
        next_owner: Option<String>,
        unpaid_royalty: bool,
        /// Set on ticket check-ins: the event whose nullifier the step exposes.
        #[serde(default)]
        event_id: Option<[u8; 32]>,
    },
    /// Prove one committed trait of the object.
    Trait {
        asset_id: AssetId,
        key: String,
        val: String,
        path: Vec<([u8; 32], bool)>,
        owner: String,
        challenge: [u8; 32],
    },
    /// Prove ownership against a collection root and a one-time challenge.
    Ownership {
        asset_id: AssetId,
        state_root: [u8; 32],
        collection_root: [u8; 32],
        path: Vec<([u8; 32], bool)>,
        owner: String,
        challenge: [u8; 32],
        wrong_secret: bool,
    },
    /// Prove the current owner authorises burning the Stage I seal.
    Migration {
        asset_id: AssetId,
        commitment: [u8; 32],
        owner: String,
    },
}

impl ProofJob {
    pub fn asset_id(&self) -> AssetId {
        match self {
            ProofJob::Mint { asset_id, .. }
            | ProofJob::Fold { asset_id, .. }
            | ProofJob::Trait { asset_id, .. }
            | ProofJob::Ownership { asset_id, .. }
            | ProofJob::Migration { asset_id, .. } => *asset_id,
        }
    }
}

/// What the prover hands back. `pcd` is always the public view: no uncompressed proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ProofOutput {
    Mint { pcd: RaguPcdProof, cap_proof: RaguCapProof },
    Fold { pcd: RaguPcdProof },
    Trait { proof: Vec<u8> },
    Ownership { proof: Vec<u8>, pcd: RaguPcdProof },
    Migration { proof: Vec<u8>, pcd: RaguPcdProof },
}

/// The public part of a lineage proof: header fields and the compressed proof, without the
/// uncompressed (foldable) proof.
pub fn public_view(p: &RaguPcdProof) -> RaguPcdProof {
    RaguPcdProof {
        asset_id: p.asset_id,
        genesis_commitment: p.genesis_commitment,
        latest_commitment: p.latest_commitment,
        owner_tag_bytes: p.owner_tag_bytes,
        step_count: p.step_count,
        last_step: p.last_step,
        last_profile: p.last_profile,
        royalty_required: p.royalty_required,
        creator_tag_bytes: p.creator_tag_bytes,
        event_nullifier_bytes: p.event_nullifier_bytes,
        uncompressed_proof: Vec::new(),
        compressed_proof: p.compressed_proof.clone(),
    }
}

/// The prover's own copy of each object's lineage proof.
///
/// A mint or fold is first *staged*. The caller promotes it once the ledger accepted the step,
/// or discards it if the step was rejected (for example a replayed ticket check-in), so the
/// stored lineage never runs ahead of the ledger.
#[derive(Default)]
pub struct LineageStore {
    live: HashMap<[u8; 32], RaguPcdProof>,
    staged: HashMap<[u8; 32], RaguPcdProof>,
}

impl LineageStore {
    pub fn has(&self, asset_id: &AssetId) -> bool {
        self.live.contains_key(&asset_id.0)
    }

    /// Makes the staged proof for `asset_id` the live one. Returns false if nothing was staged.
    pub fn promote(&mut self, asset_id: &AssetId) -> bool {
        match self.staged.remove(&asset_id.0) {
            Some(p) => {
                self.live.insert(asset_id.0, p);
                true
            }
            None => false,
        }
    }

    pub fn discard(&mut self, asset_id: &AssetId) {
        self.staged.remove(&asset_id.0);
    }

    pub fn clear(&mut self) {
        self.live.clear();
        self.staged.clear();
    }

    fn live(&self, asset_id: &AssetId) -> Result<&RaguPcdProof, String> {
        self.live.get(&asset_id.0).ok_or_else(|| {
            "this browser no longer holds the object's lineage proof (the page was reloaded or \
             the session was minted elsewhere). Reset the session and mint again."
                .to_string()
        })
    }

    /// Compresses the live proof if needed and returns its public view.
    fn compressed_public(&mut self, asset_id: &AssetId) -> Result<RaguPcdProof, String> {
        self.live(asset_id)?;
        let p = self.live.get_mut(&asset_id.0).expect("checked above");
        RaguPcdEngine.compress_pcd(p).map_err(|e| e.to_string())?;
        Ok(public_view(p))
    }

    /// Runs one job. Mint and fold results are staged, not yet live.
    pub fn run(&mut self, job: &ProofJob) -> Result<ProofOutput, String> {
        match job {
            ProofJob::Mint {
                asset_id,
                commitment,
                collection_id,
                token_index,
                cap_blinding,
                max_supply,
            } => {
                let pcd = RaguPcdEngine
                    .fold_step_deferred(
                        None,
                        &RaguStepWitness {
                            kind: RaguStepKind::MintStep,
                            profile_id: *b"NFT1",
                            asset_id: *asset_id,
                            state_commitment: *commitment,
                            secret_witness: derive_demo_actor_secret("alice").to_vec(),
                            next_owner_tag: None,
                            royalty_required: true,
                            creator_tag: derive_creator_tag(CREATOR_ROYALTY_SECRET),
                            creator_ack_secret: None,
                            event_id: None,
                        },
                    )
                    .map_err(|e| e.to_string())?;
                let cap_proof = IssuanceCapEngine
                    .prove_cap(*collection_id, asset_id, *token_index, *cap_blinding, *max_supply)
                    .map_err(|e| e.to_string())?;
                let out = ProofOutput::Mint { pcd: public_view(&pcd), cap_proof };
                self.staged.insert(asset_id.0, pcd);
                Ok(out)
            }
            ProofJob::Fold {
                asset_id,
                kind,
                profile_id,
                next_commit,
                owner,
                next_owner,
                unpaid_royalty,
                event_id,
            } => {
                let prev = self.live(asset_id)?;
                let ack: &[u8] = if *unpaid_royalty {
                    UNPAID_ROYALTY_SECRET
                } else {
                    CREATOR_ROYALTY_SECRET
                };
                let next = RaguPcdEngine
                    .fold_step(
                        Some(prev),
                        &RaguStepWitness {
                            kind: *kind,
                            profile_id: *profile_id,
                            asset_id: *asset_id,
                            state_commitment: *next_commit,
                            secret_witness: derive_demo_actor_secret(owner).to_vec(),
                            next_owner_tag: next_owner
                                .as_deref()
                                .map(|n| derive_owner_tag(&derive_demo_actor_secret(n))),
                            royalty_required: prev.royalty_required,
                            creator_tag: prev.creator_tag_bytes,
                            creator_ack_secret: Some(ack.to_vec()),
                            event_id: *event_id,
                        },
                    )
                    .map_err(|e| e.to_string())?;
                let out = ProofOutput::Fold { pcd: public_view(&next) };
                self.staged.insert(asset_id.0, next);
                Ok(out)
            }
            ProofJob::Trait { asset_id, key, val, path, owner, challenge } => {
                let proof = RaguPcdEngine
                    .prove_attribute(
                        asset_id,
                        key,
                        val,
                        path,
                        &derive_demo_actor_secret(owner),
                        *challenge,
                    )
                    .map_err(|e| e.to_string())?;
                Ok(ProofOutput::Trait { proof })
            }
            ProofJob::Ownership {
                asset_id,
                state_root,
                collection_root,
                path,
                owner,
                challenge,
                wrong_secret,
            } => {
                let pcd = self.compressed_public(asset_id)?;
                let secret = if *wrong_secret {
                    WRONG_OWNER_SECRET.to_vec()
                } else {
                    derive_demo_actor_secret(owner).to_vec()
                };
                let proof = RaguPcdEngine
                    .prove_ownership(&OwnershipProofRequest {
                        asset_id: *asset_id,
                        state_root: *state_root,
                        collection_root: *collection_root,
                        merkle_siblings: path.clone(),
                        secret_witness: secret,
                        challenge: *challenge,
                    })
                    .map_err(|e| e.to_string())?;
                Ok(ProofOutput::Ownership { proof, pcd })
            }
            ProofJob::Migration { asset_id, commitment, owner } => {
                let pcd = self.compressed_public(asset_id)?;
                let proof = RaguPcdEngine
                    .prove_migration(asset_id, *commitment, &derive_demo_actor_secret(owner))
                    .map_err(|e| e.to_string())?;
                Ok(ProofOutput::Migration { proof, pcd })
            }
        }
    }
}

/// Browser bindings. One `LineageStore` lives in the page's prover worker.
#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use std::cell::RefCell;
    use wasm_bindgen::prelude::*;

    thread_local! {
        static STORE: RefCell<LineageStore> = RefCell::new(LineageStore::default());
    }

    fn asset_from_hex(hex: &str) -> Result<AssetId, JsValue> {
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok())
            .collect();
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| JsValue::from_str("asset id must be 64 hex characters"))?;
        Ok(AssetId(arr))
    }

    /// Builds the Ragu application. Takes a while; call it once, early.
    #[wasm_bindgen]
    pub fn warmup() {
        zyoza_proofs::warmup_prover();
    }

    /// Runs a `ProofJob` given as JSON and returns the `ProofOutput` as JSON.
    #[wasm_bindgen]
    pub fn run_job(job_json: &str) -> Result<String, JsValue> {
        let job: ProofJob = serde_json::from_str(job_json)
            .map_err(|e| JsValue::from_str(&format!("bad proof job: {e}")))?;
        let out = STORE
            .with(|s| s.borrow_mut().run(&job))
            .map_err(|e| JsValue::from_str(&e))?;
        serde_json::to_string(&out).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn promote(asset_hex: &str) -> Result<bool, JsValue> {
        let id = asset_from_hex(asset_hex)?;
        Ok(STORE.with(|s| s.borrow_mut().promote(&id)))
    }

    #[wasm_bindgen]
    pub fn discard(asset_hex: &str) -> Result<(), JsValue> {
        let id = asset_from_hex(asset_hex)?;
        STORE.with(|s| s.borrow_mut().discard(&id));
        Ok(())
    }

    #[wasm_bindgen]
    pub fn has_lineage(asset_hex: &str) -> Result<bool, JsValue> {
        let id = asset_from_hex(asset_hex)?;
        Ok(STORE.with(|s| s.borrow().has(&id)))
    }

    #[wasm_bindgen]
    pub fn forget_all() {
        STORE.with(|s| s.borrow_mut().clear());
    }
}
