use crate::{CommitBidRequest, GalleryService, RevealBidRequest};
use anyhow::{bail, Result};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use zyoza_core::{
    AssetDesc, AssetId, AssetProfile, CollectionSpec, MintClaim, ObjectViewingKey, OrchardMemoSeal,
    OwnershipProofRequest, ProfilePreview, ProofEngine, SettlementAdapter, ZyEnvelopeAlias,
    PROTOCOL_VERSION,
};
use zyoza_oob::{InMemoryStorage, OobEnvelope, OobKeypair, OobStorage};
use zyoza_profile_nft::{CollectionPolicy, MediaManifest, NftProfile, NftState, ProvenanceEvent};
use zyoza_proofs::{
    derive_creator_tag, derive_owner_tag, CollectionMerkleTree, IssuanceCapEngine, RaguCapProof,
    RaguPcdEngine, RaguPcdProof, RaguStepKind, RaguStepWitness, TraitMerkleTree,
};
use zyoza_settlement::{
    aggregate_signatures, keygen_dealer, round1_commit, round2_sign, verify_frost_signature,
    OrchardSealAdapter, OrchardZsaAdapter,
};

pub use zyoza_studio_prover::{derive_demo_actor_secret, CREATOR_ROYALTY_SECRET};

const ALLOWED_PRESETS: &[&str] = &["nounz-venetian", "nounz-mesh", "nounz-ovk", "lootz-kit"];

pub fn validate_preset(preset: &str) -> Result<BTreeMap<String, String>> {
    if !ALLOWED_PRESETS.contains(&preset) {
        bail!(
            "unsupported preset {:?}: expected one of {:?}",
            preset,
            ALLOWED_PRESETS
        );
    }
    let traits = match preset {
        "nounz-venetian" => BTreeMap::from([
            ("collection".into(), "nounz".into()),
            ("head".into(), "dumpling".into()),
            ("shades".into(), "venetian-gold".into()),
        ]),
        "nounz-mesh" => BTreeMap::from([
            ("collection".into(), "nounz".into()),
            ("head".into(), "crt-terminal".into()),
            ("shades".into(), "stealth-mesh".into()),
        ]),
        "nounz-ovk" => BTreeMap::from([
            ("collection".into(), "nounz".into()),
            ("head".into(), "cypher-hood".into()),
            ("shades".into(), "ovk-peek".into()),
        ]),
        "lootz-kit" => BTreeMap::from([
            ("collection".into(), "lootz".into()),
            ("bag".into(), "syndicate-kit-07".into()),
            ("tier".into(), "genesis".into()),
        ]),
        _ => unreachable!(),
    };
    Ok(traits)
}

#[derive(Deserialize)]
pub struct DemoMintReq {
    pub preset: String,
    pub token_index: u64,
}

#[derive(Serialize)]
pub struct DemoMintResp {
    pub session_id: String,
    pub preset: String,
    pub token_index: u64,
    pub asset_id: String,
    pub asset_base: String,
    pub commitment: String,
    pub oob_uri: String,
    pub ovk: String,
    pub nullifiers: Vec<String>,
    pub slot_commitment: String,
    pub compressed_proof_bytes: usize,
    pub pcd_steps: u64,
}

#[derive(Deserialize)]
pub struct SessionReq {
    pub session_id: String,
}

#[derive(Serialize)]
pub struct DemoSessionStatusResp {
    pub session_id: String,
    pub preset: String,
    pub token_index: u64,
    pub asset_id: String,
    pub asset_base: String,
    pub commitment: String,
    pub oob_uri: String,
    pub owner: String,
    pub pcd_steps: u64,
    pub last_step: String,
    pub listing_id: Option<u64>,
    pub crystallized: bool,
    pub busy: bool,
    pub browser: bool,
}

#[derive(Serialize)]
pub struct DemoTransferResp {
    pub prev_spent: bool,
    pub new_commitment: String,
    pub new_oob_uri: String,
    pub owner: String,
    pub pcd_steps: u64,
    pub compressed_proof_bytes: usize,
}

#[derive(Deserialize)]
pub struct DemoDecryptReq {
    pub session_id: String,
    pub actor: String,
}

#[derive(Serialize)]
pub struct DemoDecryptResp {
    pub decrypted_summary: String,
}

#[derive(Deserialize)]
pub struct DemoPreviewReq {
    pub session_id: String,
    pub use_ovk: bool,
}

#[derive(Deserialize)]
pub struct DemoFoldReq {
    pub session_id: String,
    pub step_kind: String,
    pub profile_id: String,
    #[serde(default)]
    pub simulate_unpaid_royalty: bool,
}

#[derive(Serialize)]
pub struct DemoFoldResp {
    pub step_count: u64,
    pub last_step: String,
    pub compressed_proof_bytes: usize,
    pub verify_ms: u128,
    pub owner_tag_hex: String,
    pub event_nullifier_hex: String,
    pub latest_commitment_hex: String,
}

#[derive(Deserialize)]
pub struct DemoListReq {
    pub session_id: String,
    pub reserve_zatoshis: u64,
}

#[derive(Serialize)]
pub struct DemoListResp {
    pub listing_id: u64,
    pub prove_ms: u128,
    pub verify_ms: u128,
    pub proof_bytes: usize,
    pub collection_root_hex: String,
    pub state_root_hex: String,
    pub challenge_hex: String,
    pub collection_size: usize,
    pub title: String,
}

#[derive(Serialize)]
pub struct DemoTraitProofResp {
    pub trait_key: String,
    pub trait_val: String,
    pub traits_root_hex: String,
    pub proof_bytes: usize,
    pub prove_ms: u128,
    pub verify_ms: u128,
}

/// Phase-1 commit request: browser sends ONLY `commitment_hex` (computed locally via Web Crypto SHA-256).
#[derive(Deserialize)]
pub struct DemoCommitBidReq {
    pub session_id: String,
    pub bidder_id: String,
    pub commitment_hex: String,
}

#[derive(Serialize)]
pub struct DemoCommitBidResp {
    pub listing_id: u64,
    pub bidder_id: String,
    pub commitment_hex: String,
}

#[derive(Deserialize)]
pub struct DemoRevealBidReq {
    pub session_id: String,
    pub bidder_id: String,
    pub bid_zatoshis: u64,
    pub salt_hex: String,
}

#[derive(Serialize)]
pub struct DemoClearAuctionResp {
    pub winning_bidder: String,
    pub clearing_price_zatoshis: u64,
    pub new_commitment: String,
    pub new_oob_uri: String,
    pub pcd_steps: u64,
}

#[derive(Serialize)]
pub struct DemoCrystallizeResp {
    pub zsa_txid: String,
    pub asset_id: String,
    pub asset_base: String,
    pub burn_nullifier: String,
    pub frost_signers: String,
    pub value: u64,
    pub finalized: bool,
}

#[derive(Clone)]
pub struct DemoSession {
    pub preset: String,
    pub token_index: u64,
    pub asset_id: AssetId,
    pub asset_base_hex: String,
    pub nft_state: NftState,
    pub commitment: [u8; 32],
    pub oob_uri: String,
    pub ovk: ObjectViewingKey,
    pub pcd: RaguPcdProof,
    pub cap_proof: RaguCapProof,
    pub owner: String,
    pub listing_id: Option<u64>,
    pub crystallized: bool,
    pub busy: bool,
    /// True when the visitor's browser holds the lineage proof and does the proving. The server
    /// then keeps only the public view (header fields and the compressed proof).
    pub browser: bool,
}

/// Interactive cryptographic workbench backing `/demo` (Zyoza Studio).
pub struct DemoWorkbench {
    next_num: u64,
    actors: HashMap<String, OobKeypair>,
    storage: InMemoryStorage,
    pub orchard: OrchardSealAdapter,
    pub zsa: OrchardZsaAdapter,
    pub sessions: HashMap<String, DemoSession>,
    pub spent_ticket_nullifiers: HashSet<[u8; 32]>,
    background_holdings: Vec<(AssetId, [u8; 32], [u8; 32])>,
    /// Proof jobs handed to a browser and not yet committed, by ticket.
    pub pending: HashMap<String, crate::browser_flow::PendingJob>,
    pub next_ticket: u64,
}

impl Default for DemoWorkbench {
    fn default() -> Self {
        let mut actors = HashMap::new();
        for name in ["alice", "bob", "carol"] {
            actors.insert(
                name.to_string(),
                OobKeypair::from_seed_bytes(&derive_demo_actor_secret(name)),
            );
        }
        // Populate realistic background collection members so Merkle proofs operate on a multi-holder tree!
        let mut background_holdings = Vec::new();
        for idx in 1u8..=3 {
            let aid = AssetId::derive(&[0x07; 32], &[b'b', b'g', idx]);
            let st = [0xD0 + idx; 32];
            let tag = derive_owner_tag(&[0xE0 + idx; 32]);
            background_holdings.push((aid, st, tag));
        }

        Self {
            next_num: 0,
            actors,
            storage: InMemoryStorage::default(),
            orchard: OrchardSealAdapter::new(),
            zsa: OrchardZsaAdapter::new(),
            sessions: HashMap::new(),
            spent_ticket_nullifiers: HashSet::new(),
            background_holdings,
            pending: HashMap::new(),
            next_ticket: 0,
        }
    }
}

impl DemoWorkbench {
    pub fn keypair_for(&mut self, actor: &str) -> OobKeypair {
        if let Some(k) = self.actors.get(actor) {
            return k.clone();
        }
        let kp = OobKeypair::from_seed_bytes(&derive_demo_actor_secret(actor));
        self.actors.insert(actor.to_string(), kp.clone());
        kp
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Builds the authoritative multi-holder `CollectionMerkleTree` from background collection items
    /// plus all live Stage I sessions, returning `(tree, index_of_session, total_entries)`.
    pub fn build_collection_tree(
        &self,
        target_session_id: Option<&str>,
    ) -> Result<(CollectionMerkleTree, Option<usize>, usize)> {
        let mut entries = self.background_holdings.clone();
        let mut session_keys: Vec<_> = self.sessions.keys().cloned().collect();
        session_keys.sort();

        let mut target_idx = None;
        for sid in session_keys {
            let sess = &self.sessions[&sid];
            if sess.crystallized {
                continue;
            }
            if entries.len() >= (1 << zyoza_proofs::MERKLE_DEPTH) {
                break;
            }
            if target_session_id == Some(sid.as_str()) {
                target_idx = Some(entries.len());
            }
            entries.push((
                sess.asset_id,
                sess.nft_state.state_root()?,
                sess.pcd.owner_tag_bytes,
            ));
        }
        let count = entries.len();
        Ok((
            CollectionMerkleTree::from_public_tags(&entries),
            target_idx,
            count,
        ))
    }

    /// Marks a server-proved session busy. Browser-proved sessions are refused here.
    pub fn acquire_busy(&mut self, session_id: &str) -> Result<DemoSession> {
        self.acquire_busy_mode(session_id, false)
    }

    pub fn acquire_busy_mode(&mut self, session_id: &str, browser: bool) -> Result<DemoSession> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("session {session_id} not found (reset or mint first)"))?;
        if sess.browser != browser {
            if sess.browser {
                bail!("session {session_id} proves in the browser; the server does not hold its lineage proof");
            }
            bail!("session {session_id} proves on the server; reset to switch to browser proving");
        }
        if sess.busy {
            bail!("another proof is currently in progress for session {session_id}");
        }
        sess.busy = true;
        Ok(sess.clone())
    }

    pub fn release_busy(&mut self, session_id: &str) {
        if let Some(sess) = self.sessions.get_mut(session_id) {
            sess.busy = false;
        }
    }

    pub fn session_status(&self, session_id: &str) -> Result<DemoSessionStatusResp> {
        let sess = self
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        Ok(DemoSessionStatusResp {
            session_id: session_id.to_string(),
            preset: sess.preset.clone(),
            token_index: sess.token_index,
            asset_id: sess.asset_id.to_hex(),
            asset_base: sess.asset_base_hex.clone(),
            commitment: hex::encode(sess.commitment),
            oob_uri: sess.oob_uri.clone(),
            owner: sess.owner.clone(),
            pcd_steps: sess.pcd.step_count,
            last_step: format!("{:?}", sess.pcd.last_step),
            listing_id: sess.listing_id,
            crystallized: sess.crystallized,
            busy: sess.busy,
            browser: sess.browser,
        })
    }

    /// Prepares a governed mint under the fast mutex (<1 ms) before heavy Ragu proving runs off-lock.
    pub fn prep_mint(&mut self, req: &DemoMintReq) -> Result<PreparedMint> {
        let traits = validate_preset(&req.preset)?;
        let rng = &mut UnwrapErr(SysRng);
        let issuer_vk = [0x07; 32];
        let spec = CollectionSpec {
            issuer_vk,
            slug: req.preset.clone(),
            max_supply: Some(100),
            unique_media: true,
            mint_window: None,
        };
        let desc = AssetDesc {
            namespace: "zyoza".into(),
            collection: req.preset.clone(),
            item_id: req.token_index.to_string(),
        };
        let (asset_id, asset_base) =
            AssetId::derive_with_base(&issuer_vk, &desc.to_canonical_bytes());

        let mut media_sha = [0u8; 32];
        media_sha[0..8].copy_from_slice(&req.token_index.to_be_bytes());
        media_sha[8] = req.preset.len() as u8;

        let claim = MintClaim {
            asset_id,
            token_index: req.token_index,
            media_sha256: media_sha,
            timestamp_unix: 1_700_000_000,
        };
        let nfs = spec.validate_and_nullifiers(&claim)?;

        let title = format!("{} #{}", req.preset, req.token_index);
        let nft_state = NftState {
            asset_id,
            title,
            description: "Shielded Zyoza Specimen (Simulated Ledger)".into(),
            creator: "dumpling-syndicate".into(),
            media: MediaManifest {
                mime: "image/svg+xml".into(),
                sha256_hex: hex::encode(media_sha),
                encrypted_blob_uri: format!("mem://{}", req.preset),
            },
            traits,
            policy: CollectionPolicy {
                royalty_bps: 500,
                lockup_until_unix: None,
            },
            provenance: vec![ProvenanceEvent {
                step: 0,
                kind: "mint".into(),
                commitment_hex: "00".repeat(32),
                timestamp_unix: 1_700_000_000,
            }],
        };
        let state_bytes = nft_state.to_bytes()?;
        let state_root = nft_state.state_root()?;
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let env = ZyEnvelopeAlias {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id,
            state_root,
            prev_commitment: None,
            nonce,
        };
        let commitment = env.state_commitment();

        let alice = self.keypair_for("alice");
        let oob = OobEnvelope::seal(rng, &env, &alice.public, &state_bytes)?;
        let oob_pointer_hash = oob.pointer_hash()?;
        let mut cap_blinding = [0u8; 32];
        rng.fill_bytes(&mut cap_blinding);

        Ok(PreparedMint {
            preset: req.preset.clone(),
            token_index: req.token_index,
            spec,
            claim,
            nfs,
            asset_id,
            asset_base_hex: asset_base.to_hex(),
            nft_state,
            state_root,
            nonce,
            commitment,
            oob,
            oob_pointer_hash,
            cap_blinding,
        })
    }

    pub fn commit_mint(
        &mut self,
        prep: PreparedMint,
        pcd: RaguPcdProof,
        cap_proof: RaguCapProof,
        gallery: &mut GalleryService,
    ) -> Result<DemoMintResp> {
        let oob_uri = self.storage.put(&prep.oob)?;
        let memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id: prep.asset_id,
            state_root: prep.state_root,
            nonce: prep.nonce,
            oob_pointer_hash: prep.oob_pointer_hash,
            oob_uri: oob_uri.clone(),
        }
        .to_bytes()?;

        self.orchard
            .anchor_governed_mint(&prep.spec, &prep.claim, prep.commitment, &memo)?;

        let compressed_proof_bytes = zyoza_proofs::compressed_proof_len();
        let slot_commitment = hex::encode(cap_proof.slot_commitment_bytes);
        let ovk = ObjectViewingKey::derive(prep.asset_id, &derive_demo_actor_secret("alice"));

        self.next_num += 1;
        let session_id = format!("zyoz-{}", self.next_num);
        self.sessions.insert(
            session_id.clone(),
            DemoSession {
                preset: prep.preset.clone(),
                token_index: prep.token_index,
                asset_id: prep.asset_id,
                asset_base_hex: prep.asset_base_hex.clone(),
                nft_state: prep.nft_state,
                commitment: prep.commitment,
                oob_uri: oob_uri.clone(),
                ovk: ovk.clone(),
                pcd,
                cap_proof,
                owner: "alice".into(),
                listing_id: None,
                crystallized: false,
                busy: false,
                browser: false,
            },
        );

        let (tree, _, _) = self.build_collection_tree(None)?;
        gallery.register_collection_root(tree.root());

        Ok(DemoMintResp {
            session_id,
            preset: prep.preset,
            token_index: prep.token_index,
            asset_id: prep.asset_id.to_hex(),
            asset_base: prep.asset_base_hex,
            commitment: hex::encode(prep.commitment),
            oob_uri,
            ovk: hex::encode(ovk.key_bytes),
            nullifiers: prep.nfs.iter().map(hex::encode).collect(),
            slot_commitment,
            compressed_proof_bytes,
            pcd_steps: 1,
        })
    }

    /// Prepares an ownership transfer (re-wrapping OOB DEK via OS randomness + preparing next seal commitment).
    pub fn prep_transfer(
        &mut self,
        session_id: &str,
        new_owner: &str,
    ) -> Result<PreparedTransfer> {
        self.prep_transfer_mode(session_id, new_owner, false)
    }

    pub fn prep_transfer_mode(
        &mut self,
        session_id: &str,
        new_owner: &str,
        browser: bool,
    ) -> Result<PreparedTransfer> {
        let sess = self.acquire_busy_mode(session_id, browser)?;
        if sess.crystallized {
            self.release_busy(session_id);
            bail!("Stage I seal already burned and crystallized into Stage II ZSA");
        }
        if sess.owner == new_owner {
            self.release_busy(session_id);
            bail!("object is already owned by {new_owner}");
        }

        let from_kp = self.keypair_for(&sess.owner);
        let to_kp = self.keypair_for(new_owner);
        let prev_oob = match self.storage.get(&sess.oob_uri) {
            Ok(o) => o,
            Err(e) => {
                self.release_busy(session_id);
                return Err(e.into());
            }
        };

        let rng = &mut UnwrapErr(SysRng);
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let new_oob = match prev_oob.rewrap_for_recipient(rng, &from_kp.secret, &to_kp.public, nonce)
        {
            Ok(o) => o,
            Err(e) => {
                self.release_busy(session_id);
                return Err(e.into());
            }
        };

        let state_root = sess.nft_state.state_root()?;
        let env = ZyEnvelopeAlias {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id: sess.asset_id,
            state_root,
            prev_commitment: Some(sess.commitment),
            nonce,
        };
        let next_commit = env.state_commitment();

        Ok(PreparedTransfer {
            session_id: session_id.to_string(),
            prev_owner: sess.owner,
            new_owner: new_owner.to_string(),
            asset_id: sess.asset_id,
            state_root,
            prev_commit: sess.commitment,
            next_commit,
            nonce,
            new_oob,
            prev_pcd: sess.pcd,
        })
    }

    pub fn commit_transfer(
        &mut self,
        prep: PreparedTransfer,
        next_pcd: RaguPcdProof,
        gallery: &mut GalleryService,
    ) -> Result<DemoTransferResp> {
        let new_oob_uri = self.storage.put(&prep.new_oob)?;
        let memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id: prep.asset_id,
            state_root: prep.state_root,
            nonce: prep.nonce,
            oob_pointer_hash: prep.new_oob.pointer_hash()?,
            oob_uri: new_oob_uri.clone(),
        }
        .to_bytes()?;

        let res = self.orchard.anchor_transfer(
            &prep.asset_id,
            prep.prev_commit,
            prep.next_commit,
            &memo,
        );
        if let Err(e) = res {
            self.release_busy(&prep.session_id);
            return Err(e.into());
        }

        let compressed_proof_bytes = next_pcd.compressed_proof.len();
        let pcd_steps = next_pcd.step_count;

        let sess = self.sessions.get_mut(&prep.session_id).unwrap();
        sess.commitment = prep.next_commit;
        sess.oob_uri = new_oob_uri.clone();
        sess.owner = prep.new_owner.clone();
        sess.pcd = next_pcd;
        sess.busy = false;

        let (tree, _, _) = self.build_collection_tree(None)?;
        gallery.register_collection_root(tree.root());

        Ok(DemoTransferResp {
            prev_spent: true,
            new_commitment: hex::encode(prep.next_commit),
            new_oob_uri,
            owner: prep.new_owner,
            pcd_steps,
            compressed_proof_bytes,
        })
    }

    pub fn decrypt(&mut self, req: DemoDecryptReq) -> Result<DemoDecryptResp> {
        let kp = self.keypair_for(&req.actor);
        let sess = self
            .sessions
            .get(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        let oob = self.storage.get(&sess.oob_uri)?;
        match oob.open(&kp.secret) {
            Ok(plain) => {
                let parsed = NftState::from_bytes(&plain)?;
                Ok(DemoDecryptResp {
                    decrypted_summary: format!("{} (creator: {})", parsed.title, parsed.creator),
                })
            }
            Err(_) => bail!(
                "{} does not hold the current decryption key (DEK is wrapped for {})",
                req.actor,
                sess.owner
            ),
        }
    }

    pub fn preview(&self, req: DemoPreviewReq) -> Result<ProfilePreview> {
        let sess = self
            .sessions
            .get(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        let ovk = if req.use_ovk { Some(&sess.ovk) } else { None };
        Ok(NftProfile.public_preview(&sess.nft_state.to_bytes()?, ovk)?)
    }

    pub fn commit_folded_step(
        &mut self,
        session_id: &str,
        step_kind: String,
        kind: RaguStepKind,
        next_commit: [u8; 32],
        nonce: [u8; 32],
        next_pcd: RaguPcdProof,
        verify_ms: u128,
    ) -> Result<DemoFoldResp> {
        if kind == RaguStepKind::TicketCheckInStep {
            let nf = next_pcd.event_nullifier_bytes;
            if !self.spent_ticket_nullifiers.insert(nf) {
                self.release_busy(session_id);
                bail!(
                    "TicketCheckInCircuit replay blocked: event nullifier {} already spent!",
                    hex::encode(&nf[..8])
                );
            }
        }

        let sess = self.sessions.get(session_id).unwrap().clone();
        let oob = self.storage.get(&sess.oob_uri)?;
        let memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: next_pcd.last_profile,
            asset_id: sess.asset_id,
            state_root: sess.nft_state.state_root()?,
            nonce,
            oob_pointer_hash: oob.pointer_hash()?,
            oob_uri: sess.oob_uri.clone(),
        }
        .to_bytes()?;
        if let Err(e) =
            self.orchard
                .anchor_transfer(&sess.asset_id, sess.commitment, next_commit, &memo)
        {
            self.release_busy(session_id);
            return Err(e.into());
        }

        let compressed_proof_bytes = next_pcd.compressed_proof.len();
        let owner_tag_hex = hex::encode(next_pcd.owner_tag_bytes);
        let event_nullifier_hex = hex::encode(next_pcd.event_nullifier_bytes);
        let latest_commitment_hex = hex::encode(next_pcd.latest_commitment);
        let step_count = next_pcd.step_count;

        let s_mut = self.sessions.get_mut(session_id).unwrap();
        s_mut.commitment = next_commit;
        s_mut.pcd = next_pcd;
        s_mut.busy = false;

        Ok(DemoFoldResp {
            step_count,
            last_step: step_kind,
            compressed_proof_bytes,
            verify_ms,
            owner_tag_hex,
            event_nullifier_hex,
            latest_commitment_hex,
        })
    }

    pub fn commit_bid(
        &self,
        req: DemoCommitBidReq,
        gallery: &mut GalleryService,
    ) -> Result<DemoCommitBidResp> {
        let sess = self
            .sessions
            .get(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        let listing_id = sess
            .listing_id
            .ok_or_else(|| anyhow::anyhow!("session is not listed yet"))?;

        gallery.commit_sealed_bid(
            listing_id,
            CommitBidRequest {
                bidder_id: req.bidder_id.clone(),
                commitment_hex: req.commitment_hex.clone(),
            },
        )?;
        Ok(DemoCommitBidResp {
            listing_id,
            bidder_id: req.bidder_id,
            commitment_hex: req.commitment_hex,
        })
    }

    pub fn reveal_bid(&self, req: DemoRevealBidReq, gallery: &mut GalleryService) -> Result<()> {
        let sess = self
            .sessions
            .get(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        let listing_id = sess
            .listing_id
            .ok_or_else(|| anyhow::anyhow!("session is not listed yet"))?;
        gallery.reveal_sealed_bid(
            listing_id,
            RevealBidRequest {
                bidder_id: req.bidder_id,
                bid_zatoshis: req.bid_zatoshis,
                salt_hex: req.salt_hex,
            },
        )
    }

    pub fn commit_crystallize(
        &mut self,
        session_id: &str,
        burn_nullifier_hex: String,
    ) -> Result<DemoCrystallizeResp> {
        let rng = &mut UnwrapErr(SysRng);
        let sess = self.sessions.get(session_id).unwrap().clone();

        let mut burn_nonce = [0u8; 32];
        rng.fill_bytes(&mut burn_nonce);
        let burn_memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id: sess.asset_id,
            state_root: [0xFF; 32],
            nonce: burn_nonce,
            oob_pointer_hash: [0xDD; 32],
            oob_uri: "burn://zsa".into(),
        }
        .to_bytes()?;
        let mut burn_commit = sess.commitment;
        burn_commit[0] ^= burn_nonce[0] | 1;
        if let Err(e) =
            self.orchard
                .anchor_transfer(&sess.asset_id, sess.commitment, burn_commit, &burn_memo)
        {
            self.release_busy(session_id);
            return Err(e.into());
        }

        let (group_pk, shares) = keygen_dealer(rng, 2, 3)?;
        let c1 = round1_commit(rng, &shares[0]);
        let c3 = round1_commit(rng, &shares[2]);
        let commits = vec![c1.clone(), c3.clone()];
        let p1 = round2_sign(&shares[0], &c1, &commits, &sess.asset_id.0);
        let p3 = round2_sign(&shares[2], &c3, &commits, &sess.asset_id.0);
        let sig = aggregate_signatures(&commits, &[p1, p3])?;
        if !verify_frost_signature(&group_pk, &sess.asset_id.0, &sig)? {
            self.release_busy(session_id);
            bail!("FROST signature verification failed");
        }

        let mut zsa_nonce = [0u8; 32];
        rng.fill_bytes(&mut zsa_nonce);
        let state_root = sess.nft_state.state_root()?;
        let zsa_memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id: sess.asset_id,
            state_root,
            nonce: zsa_nonce,
            oob_pointer_hash: [0x11; 32],
            oob_uri: sess.oob_uri.clone(),
        }
        .to_bytes()?;
        let rcpt = self.zsa.anchor_mint(&sess.asset_id, state_root, &zsa_memo)?;

        let s_mut = self.sessions.get_mut(session_id).unwrap();
        s_mut.crystallized = true;
        s_mut.busy = false;

        Ok(DemoCrystallizeResp {
            zsa_txid: hex::encode(rcpt.tx_id),
            asset_id: sess.asset_id.to_hex(),
            asset_base: sess.asset_base_hex,
            burn_nullifier: burn_nullifier_hex,
            frost_signers: "Signers #1 & #3 (2-of-3 Pallas Schnorr, trusted-dealer setup)".into(),
            value: 1,
            finalized: true,
        })
    }
}

pub struct PreparedMint {
    pub preset: String,
    pub token_index: u64,
    pub spec: CollectionSpec,
    pub claim: MintClaim,
    pub nfs: Vec<[u8; 32]>,
    pub asset_id: AssetId,
    pub asset_base_hex: String,
    pub nft_state: NftState,
    pub state_root: [u8; 32],
    pub nonce: [u8; 32],
    pub commitment: [u8; 32],
    pub oob: OobEnvelope,
    pub oob_pointer_hash: [u8; 32],
    pub cap_blinding: [u8; 32],
}

pub struct PreparedTransfer {
    pub session_id: String,
    pub prev_owner: String,
    pub new_owner: String,
    pub asset_id: AssetId,
    pub state_root: [u8; 32],
    pub prev_commit: [u8; 32],
    pub next_commit: [u8; 32],
    pub nonce: [u8; 32],
    pub new_oob: OobEnvelope,
    pub prev_pcd: RaguPcdProof,
}

/// Pure off-lock Ragu proving helpers executed inside `tokio::task::spawn_blocking`.
pub fn prove_mint_bundle(prep: &PreparedMint) -> Result<(RaguPcdProof, RaguCapProof)> {
    let alice_secret = derive_demo_actor_secret("alice");
    let creator_tag = derive_creator_tag(CREATOR_ROYALTY_SECRET);
    // Nobody verifies the mint proof on its own, so skip compressing it. `verify_pcd`
    // compresses on demand if the object is listed or crystallized before any transfer.
    let pcd = RaguPcdEngine.fold_step_deferred(
        None,
        &RaguStepWitness {
            kind: RaguStepKind::MintStep,
            profile_id: *b"NFT1",
            asset_id: prep.asset_id,
            state_commitment: prep.commitment,
            secret_witness: alice_secret.to_vec(),
            next_owner_tag: None,
            royalty_required: true,
            creator_tag,
            creator_ack_secret: None,
        },
    )?;
    let col_id = prep.spec.collection_id();
    let cap_proof = IssuanceCapEngine.prove_cap(
        col_id,
        &prep.asset_id,
        prep.token_index,
        prep.cap_blinding,
        100,
    )?;
    if !IssuanceCapEngine.verify_cap(col_id, &prep.asset_id, 100, &cap_proof)? {
        bail!("IssuanceCapCircuit verification failed");
    }
    Ok((pcd, cap_proof))
}

pub fn prove_transfer_step(prep: &PreparedTransfer) -> Result<RaguPcdProof> {
    let from_secret = derive_demo_actor_secret(&prep.prev_owner);
    let to_tag = derive_owner_tag(&derive_demo_actor_secret(&prep.new_owner));
    let next_pcd = RaguPcdEngine.fold_step(
        Some(&prep.prev_pcd),
        &RaguStepWitness {
            kind: RaguStepKind::RoyaltyStep,
            profile_id: *b"NFT1",
            asset_id: prep.asset_id,
            state_commitment: prep.next_commit,
            secret_witness: from_secret.to_vec(),
            next_owner_tag: Some(to_tag),
            royalty_required: prep.prev_pcd.royalty_required,
            creator_tag: prep.prev_pcd.creator_tag_bytes,
            creator_ack_secret: Some(CREATOR_ROYALTY_SECRET.to_vec()),
        },
    )?;
    if !RaguPcdEngine.verify_pcd(&next_pcd)? {
        bail!("Ragu verify_compressed failed after transfer fold");
    }
    Ok(next_pcd)
}

pub fn prove_custom_fold(
    sess: &DemoSession,
    kind: RaguStepKind,
    prof: [u8; 4],
    simulate_unpaid_royalty: bool,
) -> Result<(RaguPcdProof, [u8; 32], [u8; 32], u128)> {
    let mut nonce = [0u8; 32];
    if kind == RaguStepKind::TicketCheckInStep {
        // Deterministic event commitment for Zcon demo so a second check-in collides on event_nullifier!
        nonce = *b"ZCON-2026-MAIN-STAGE-EVENT-ID-01";
    } else {
        UnwrapErr(SysRng).fill_bytes(&mut nonce);
    }
    let env = ZyEnvelopeAlias {
        version: PROTOCOL_VERSION,
        profile_id: prof,
        asset_id: sess.asset_id,
        state_root: sess.nft_state.state_root()?,
        prev_commitment: Some(sess.commitment),
        nonce,
    };
    let next_commit = env.state_commitment();
    let owner_secret = derive_demo_actor_secret(&sess.owner);
    let ack_secret = if simulate_unpaid_royalty {
        Some(b"unpaid-missing-receipt".to_vec())
    } else {
        Some(CREATOR_ROYALTY_SECRET.to_vec())
    };

    let next_pcd = RaguPcdEngine.fold_step(
        Some(&sess.pcd),
        &RaguStepWitness {
            kind,
            profile_id: prof,
            asset_id: sess.asset_id,
            state_commitment: next_commit,
            secret_witness: owner_secret.to_vec(),
            next_owner_tag: None,
            royalty_required: sess.pcd.royalty_required,
            creator_tag: sess.pcd.creator_tag_bytes,
            creator_ack_secret: ack_secret,
        },
    )?;
    let t_ver = std::time::Instant::now();
    let ok = RaguPcdEngine.verify_pcd(&next_pcd)?;
    let verify_ms = t_ver.elapsed().as_millis();
    if !ok {
        bail!("Ragu verify_compressed rejected proof");
    }
    Ok((next_pcd, next_commit, nonce, verify_ms))
}

pub fn prove_listing_ownership(
    sess: &DemoSession,
    collection_root: [u8; 32],
    merkle_path: Vec<([u8; 32], bool)>,
    challenge: [u8; 32],
    use_wrong_secret: bool,
) -> Result<(Vec<u8>, [u8; 32], u128)> {
    // Verify current lineage proof & ledger commitment agreement before listing!
    if sess.pcd.latest_commitment != sess.commitment {
        bail!("lineage proof latest_commitment does not match ledger commitment");
    }
    if !RaguPcdEngine.verify_pcd(&sess.pcd)? {
        bail!("session lineage proof failed verify_compressed");
    }

    let state_root = sess.nft_state.state_root()?;
    let secret = if use_wrong_secret {
        b"wrong-attacker-secret-0000000000".to_vec()
    } else {
        derive_demo_actor_secret(&sess.owner).to_vec()
    };

    let t0 = std::time::Instant::now();
    let proof = RaguPcdEngine.prove_ownership(&OwnershipProofRequest {
        asset_id: sess.asset_id,
        state_root,
        collection_root,
        merkle_siblings: merkle_path,
        secret_witness: secret,
        challenge,
    })?;
    let prove_ms = t0.elapsed().as_millis();
    Ok((proof, state_root, prove_ms))
}

pub fn prove_session_trait(sess: &DemoSession) -> Result<DemoTraitProofResp> {
    let pairs: Vec<(&str, &str)> = sess
        .nft_state
        .traits
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let (first_k, first_v) = *pairs
        .first()
        .ok_or_else(|| anyhow::anyhow!("asset has no traits"))?;
    let trait_tree = TraitMerkleTree::from_traits(pairs);
    let traits_root = trait_tree.root();
    let mut challenge = [0u8; 32];
    UnwrapErr(SysRng).fill_bytes(&mut challenge);

    let owner_secret = derive_demo_actor_secret(&sess.owner);
    let t0 = std::time::Instant::now();
    let proof = RaguPcdEngine.prove_attribute(
        &sess.asset_id,
        first_k,
        first_v,
        &trait_tree.path(0),
        &owner_secret,
        challenge,
    )?;
    let prove_ms = t0.elapsed().as_millis();

    let t1 = std::time::Instant::now();
    let ok = RaguPcdEngine.verify_attribute(
        &sess.asset_id,
        traits_root,
        sess.pcd.owner_tag_bytes,
        first_k,
        first_v,
        challenge,
        &proof,
    )?;
    let verify_ms = t1.elapsed().as_millis();
    if !ok {
        bail!("AttributeCircuit verification failed");
    }

    Ok(DemoTraitProofResp {
        trait_key: first_k.to_string(),
        trait_val: first_v.to_string(),
        traits_root_hex: hex::encode(traits_root),
        proof_bytes: proof.len(),
        prove_ms,
        verify_ms,
    })
}

pub fn prove_session_migration(sess: &DemoSession) -> Result<String> {
    if sess.pcd.latest_commitment != sess.commitment {
        bail!("lineage proof latest_commitment does not match ledger commitment");
    }
    if !RaguPcdEngine.verify_pcd(&sess.pcd)? {
        bail!("lineage proof failed verify_compressed prior to crystallization");
    }
    let owner_secret = derive_demo_actor_secret(&sess.owner);
    let mig_proof = RaguPcdEngine.prove_migration(&sess.asset_id, sess.commitment, &owner_secret)?;
    if !RaguPcdEngine.verify_migration(
        &sess.asset_id,
        sess.commitment,
        sess.pcd.owner_tag_bytes,
        &mig_proof,
    )? {
        bail!("MigrationCircuit proof verification failed");
    }
    let parsed: zyoza_proofs::RaguMigrationProof = serde_json::from_slice(&mig_proof)?;
    Ok(hex::encode(parsed.burn_nullifier_bytes))
}
