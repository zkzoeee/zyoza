use crate::{
    compute_bid_commitment, AuctionClearResult, CommitBidRequest, GalleryService, RevealBidRequest,
};
use anyhow::{bail, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use zyoza_core::{
    AssetDesc, AssetId, AssetProfile, CollectionSpec, MintClaim, ObjectViewingKey, OrchardMemoSeal,
    OwnershipProofRequest, OwnershipVerifyRequest, ProfilePreview, ProofEngine, SettlementAdapter,
    ZyEnvelopeAlias, PROTOCOL_VERSION,
};
use zyoza_oob::{InMemoryStorage, OobEnvelope, OobKeypair, OobStorage};
use zyoza_profile_nft::{CollectionPolicy, MediaManifest, NftProfile, NftState, ProvenanceEvent};
use zyoza_proofs::{
    CollectionMerkleTree, RaguPcdEngine, RaguPcdProof, RaguStepKind, RaguStepWitness,
};
use zyoza_settlement::{
    aggregate_signatures, keygen_dealer, round1_commit, round2_sign, verify_frost_signature,
    OrchardSealAdapter, OrchardZsaAdapter,
};

#[derive(Deserialize)]
pub struct DemoMintReq {
    pub preset: String,
    pub token_index: u64,
}

#[derive(Serialize)]
pub struct DemoMintResp {
    pub session_id: String,
    pub asset_id: String,
    pub asset_base: String,
    pub commitment: String,
    pub oob_uri: String,
    pub ovk: String,
    pub nullifiers: Vec<String>,
    pub compressed_proof_bytes: usize,
    pub pcd_steps: u64,
}

#[derive(Deserialize)]
pub struct SessionReq {
    pub session_id: String,
}

#[derive(Serialize)]
pub struct DemoTransferResp {
    pub prev_spent: bool,
    pub new_commitment: String,
    pub new_oob_uri: String,
    pub owner: String,
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
}

#[derive(Serialize)]
pub struct DemoFoldResp {
    pub step_count: u64,
    pub last_step: String,
    pub compressed_proof_bytes: usize,
    pub verify_ms: u128,
    pub header_hex: String,
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
    pub challenge_hex: String,
    pub title: String,
}

#[derive(Deserialize)]
pub struct DemoCommitBidReq {
    pub session_id: String,
    pub bidder_id: String,
    pub bid_zatoshis: u64,
}

#[derive(Serialize)]
pub struct DemoCommitBidResp {
    pub bidder_id: String,
    pub commitment_hex: String,
    pub salt_hex: String,
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
}

#[derive(Serialize)]
pub struct DemoCrystallizeResp {
    pub zsa_txid: String,
    pub asset_id: String,
    pub asset_base: String,
    pub frost_signers: String,
    pub value: u64,
    pub finalized: bool,
}

struct DemoSession {
    asset_id: AssetId,
    asset_base_hex: String,
    nft_state: NftState,
    commitment: [u8; 32],
    oob_uri: String,
    ovk: ObjectViewingKey,
    pcd: RaguPcdProof,
    owner: String,
    listing_id: Option<u64>,
    crystallized: bool,
}

/// Interactive cryptographic workbench backing `/demo` (Zyoza Studio).
pub struct DemoWorkbench {
    next_num: u64,
    actors: HashMap<String, OobKeypair>,
    storage: InMemoryStorage,
    orchard: OrchardSealAdapter,
    zsa: OrchardZsaAdapter,
    sessions: HashMap<String, DemoSession>,
}

impl Default for DemoWorkbench {
    fn default() -> Self {
        let mut actors = HashMap::new();
        actors.insert("alice".into(), OobKeypair::from_seed_bytes(&[0xA1; 32]));
        actors.insert("bob".into(), OobKeypair::from_seed_bytes(&[0xB2; 32]));
        actors.insert("carol".into(), OobKeypair::from_seed_bytes(&[0xC3; 32]));
        Self {
            next_num: 0,
            actors,
            storage: InMemoryStorage::default(),
            orchard: OrchardSealAdapter::new(),
            zsa: OrchardZsaAdapter::new(),
            sessions: HashMap::new(),
        }
    }
}

impl DemoWorkbench {
    fn keypair_for(&mut self, actor: &str) -> OobKeypair {
        if let Some(k) = self.actors.get(actor) {
            return k.clone();
        }
        let mut seed = [0u8; 32];
        for (i, b) in actor.bytes().take(32).enumerate() {
            seed[i] = b ^ 0x5A;
        }
        let kp = OobKeypair::from_seed_bytes(&seed);
        self.actors.insert(actor.to_string(), kp.clone());
        kp
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn mint(&mut self, req: DemoMintReq) -> Result<DemoMintResp> {
        let mut rng = StdRng::seed_from_u64(1000 + req.token_index);
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
            traits: BTreeMap::from([("preset".into(), req.preset.clone())]),
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
        let env = ZyEnvelopeAlias {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id,
            state_root,
            prev_commitment: None,
            nonce: [req.token_index as u8; 32],
        };
        let commitment = env.state_commitment();

        let alice = self.keypair_for("alice");
        let oob = OobEnvelope::seal(&mut rng, &env, &alice.public, &state_bytes)?;
        let oob_uri = self.storage.put(&oob)?;
        let memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id,
            state_root,
            nonce: env.nonce,
            oob_pointer_hash: oob.pointer_hash()?,
            oob_uri: oob_uri.clone(),
        }
        .to_bytes()?;

        self.orchard
            .anchor_governed_mint(&spec, &claim, commitment, &memo)?;

        let pcd = RaguPcdEngine.fold_step(
            None,
            &RaguStepWitness {
                kind: RaguStepKind::MintStep,
                profile_id: *b"NFT1",
                asset_id,
                state_commitment: commitment,
                secret_witness: b"alice".to_vec(),
                royalty_required: false,
                royalty_paid: false,
            },
        )?;
        let compressed_proof_bytes = pcd.compressed_proof.len();
        let ovk = ObjectViewingKey::derive(asset_id, &[0xA1; 32]);

        self.next_num += 1;
        let session_id = format!("zyoz-{}", self.next_num);
        self.sessions.insert(
            session_id.clone(),
            DemoSession {
                asset_id,
                asset_base_hex: asset_base.to_hex(),
                nft_state,
                commitment,
                oob_uri: oob_uri.clone(),
                ovk: ovk.clone(),
                pcd,
                owner: "alice".into(),
                listing_id: None,
                crystallized: false,
            },
        );

        Ok(DemoMintResp {
            session_id,
            asset_id: asset_id.to_hex(),
            asset_base: asset_base.to_hex(),
            commitment: hex::encode(commitment),
            oob_uri,
            ovk: hex::encode(ovk.key_bytes),
            nullifiers: nfs.iter().map(hex::encode).collect(),
            compressed_proof_bytes,
            pcd_steps: 1,
        })
    }

    pub fn transfer(&mut self, req: SessionReq) -> Result<DemoTransferResp> {
        self.transfer_to(&req.session_id, "bob")
    }

    fn transfer_to(&mut self, session_id: &str, new_owner: &str) -> Result<DemoTransferResp> {
        let mut rng = StdRng::seed_from_u64(2026);
        let to_kp = self.keypair_for(new_owner);
        let cur_owner = self
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?
            .owner
            .clone();
        let from_kp = self.keypair_for(&cur_owner);

        let sess = self.sessions.get_mut(session_id).unwrap();
        if sess.crystallized {
            bail!("Stage I seal already burned and crystallized into Stage II ZSA");
        }
        if sess.owner == new_owner {
            bail!("object is already owned by {new_owner}");
        }

        let prev_oob = self.storage.get(&sess.oob_uri)?;
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let new_oob =
            prev_oob.rewrap_for_recipient(&mut rng, &from_kp.secret, &to_kp.public, nonce)?;
        let new_oob_uri = self.storage.put(&new_oob)?;

        let mut next_commit = sess.commitment;
        next_commit[0] = next_commit[0].wrapping_add(1);
        next_commit[1] ^= nonce[0];
        let memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id: sess.asset_id,
            state_root: sess.nft_state.state_root()?,
            nonce,
            oob_pointer_hash: new_oob.pointer_hash()?,
            oob_uri: new_oob_uri.clone(),
        }
        .to_bytes()?;

        self.orchard
            .anchor_transfer(&sess.asset_id, sess.commitment, next_commit, &memo)?;
        sess.commitment = next_commit;
        sess.oob_uri = new_oob_uri.clone();
        sess.owner = new_owner.to_string();

        Ok(DemoTransferResp {
            prev_spent: true,
            new_commitment: hex::encode(next_commit),
            new_oob_uri,
            owner: new_owner.to_string(),
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

    pub fn fold(&mut self, req: DemoFoldReq) -> Result<DemoFoldResp> {
        let sess = self
            .sessions
            .get_mut(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        if sess.crystallized {
            bail!("Stage I seal already burned and crystallized into Stage II ZSA");
        }

        // Strict parse: unknown step kinds like "Bogus" are rejected!
        let kind = RaguStepKind::parse_strict(&req.step_kind)?;
        if req.profile_id.len() != 4 {
            bail!("profile_id must be a 4-character tag (e.g. NFT1, TKT1, GAM1)");
        }
        let mut prof = [0u8; 4];
        prof.copy_from_slice(req.profile_id.as_bytes());

        let next_pcd = RaguPcdEngine.fold_step(
            Some(&sess.pcd),
            &RaguStepWitness {
                kind,
                profile_id: prof,
                asset_id: sess.asset_id,
                state_commitment: sess.commitment,
                secret_witness: sess.owner.as_bytes().to_vec(),
                royalty_required: kind == RaguStepKind::RoyaltyStep,
                royalty_paid: true,
            },
        )?;
        let t_ver = std::time::Instant::now();
        let ok = RaguPcdEngine.verify_pcd(&next_pcd)?;
        let verify_ms = t_ver.elapsed().as_millis();
        if !ok {
            bail!("Ragu verify_compressed failed");
        }
        let compressed_proof_bytes = next_pcd.compressed_proof.len();
        sess.pcd = next_pcd;

        Ok(DemoFoldResp {
            step_count: sess.pcd.step_count,
            last_step: req.step_kind,
            compressed_proof_bytes,
            verify_ms,
            header_hex: hex::encode(sess.pcd.header_bytes),
        })
    }

    pub fn list_on_gallery(
        &mut self,
        req: DemoListReq,
        gallery: &mut GalleryService,
    ) -> Result<DemoListResp> {
        let sess = self
            .sessions
            .get_mut(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        if sess.crystallized {
            bail!("Stage I seal already burned and crystallized into Stage II ZSA");
        }
        if sess.listing_id.is_some() {
            bail!("session is already listed on the gallery");
        }

        // Build real Poseidon Merkle tree from actual owner secret & generate fresh challenge!
        let owner_secret = sess.owner.as_bytes().to_vec();
        let tree = CollectionMerkleTree::from_holdings(&[(sess.asset_id, &owner_secret)]);
        let collection_root = tree.root();
        let mut challenge = [0u8; 32];
        rand::rng().fill_bytes(&mut challenge);

        let t0 = std::time::Instant::now();
        let proof = RaguPcdEngine.prove_ownership(&OwnershipProofRequest {
            asset_id: sess.asset_id,
            collection_root,
            merkle_siblings: tree.path(0),
            secret_witness: owner_secret,
            challenge,
        })?;
        let prove_ms = t0.elapsed().as_millis();

        let t1 = std::time::Instant::now();
        let listing = gallery.submit_listing(
            &sess.ovk,
            &OwnershipVerifyRequest {
                collection_root,
                challenge,
            },
            &proof,
            &sess.nft_state.to_bytes()?,
            req.reserve_zatoshis,
        )?;
        let verify_ms = t1.elapsed().as_millis();
        sess.listing_id = Some(listing.listing_id);

        Ok(DemoListResp {
            listing_id: listing.listing_id,
            prove_ms,
            verify_ms,
            proof_bytes: proof.len(),
            collection_root_hex: hex::encode(collection_root),
            challenge_hex: hex::encode(challenge),
            title: listing.preview.title,
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

        let mut salt = [0u8; 32];
        rand::rng().fill_bytes(&mut salt);
        let commitment_hex = hex::encode(compute_bid_commitment(
            listing_id,
            &req.bidder_id,
            req.bid_zatoshis,
            &salt,
        ));
        gallery.commit_sealed_bid(
            listing_id,
            CommitBidRequest {
                bidder_id: req.bidder_id.clone(),
                commitment_hex: commitment_hex.clone(),
            },
        )?;
        Ok(DemoCommitBidResp {
            bidder_id: req.bidder_id,
            commitment_hex,
            salt_hex: hex::encode(salt),
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

    pub fn clear_and_settle(
        &mut self,
        req: SessionReq,
        gallery: &mut GalleryService,
    ) -> Result<DemoClearAuctionResp> {
        let listing_id = self
            .sessions
            .get(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?
            .listing_id
            .ok_or_else(|| anyhow::anyhow!("session is not listed"))?;

        let cleared: AuctionClearResult = gallery.clear_auction(listing_id)?;
        // Actually execute OOB DEK re-wrap & simulated seal transfer to the auction winner!
        let xfer = self.transfer_to(&req.session_id, &cleared.winning_bidder)?;
        Ok(DemoClearAuctionResp {
            winning_bidder: cleared.winning_bidder,
            clearing_price_zatoshis: cleared.clearing_price_zatoshis,
            new_commitment: xfer.new_commitment,
            new_oob_uri: xfer.new_oob_uri,
        })
    }

    pub fn crystallize(&mut self, req: SessionReq) -> Result<DemoCrystallizeResp> {
        let mut rng = StdRng::seed_from_u64(4444);
        let sess = self
            .sessions
            .get_mut(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        if sess.crystallized {
            bail!("already crystallized into Stage II ZSA");
        }

        let mig_proof = RaguPcdEngine.prove_migration(
            &sess.asset_id,
            sess.commitment,
            sess.owner.as_bytes(),
        )?;
        if !RaguPcdEngine.verify_migration(&sess.asset_id, sess.commitment, &mig_proof)? {
            bail!("migration proof invalid");
        }

        let burn_memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id: sess.asset_id,
            state_root: [0xFF; 32],
            nonce: [0xEE; 32],
            oob_pointer_hash: [0xDD; 32],
            oob_uri: "burn://zsa".into(),
        }
        .to_bytes()?;
        let mut burn_commit = sess.commitment;
        burn_commit[1] ^= 0xAA;
        self.orchard
            .anchor_transfer(&sess.asset_id, sess.commitment, burn_commit, &burn_memo)?;

        let (group_pk, shares) = keygen_dealer(&mut rng, 2, 3)?;
        let c1 = round1_commit(&mut rng, &shares[0]);
        let c3 = round1_commit(&mut rng, &shares[2]);
        let commits = vec![c1.clone(), c3.clone()];
        let p1 = round2_sign(&shares[0], &c1, &commits, &sess.asset_id.0);
        let p3 = round2_sign(&shares[2], &c3, &commits, &sess.asset_id.0);
        let sig = aggregate_signatures(&commits, &[p1, p3])?;
        if !verify_frost_signature(&group_pk, &sess.asset_id.0, &sig)? {
            bail!("FROST signature verification failed");
        }

        let zsa_memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id: sess.asset_id,
            state_root: sess.nft_state.state_root()?,
            nonce: [0x99; 32],
            oob_pointer_hash: [0x11; 32],
            oob_uri: sess.oob_uri.clone(),
        }
        .to_bytes()?;
        let rcpt = self
            .zsa
            .anchor_mint(&sess.asset_id, sess.nft_state.state_root()?, &zsa_memo)?;
        sess.crystallized = true;

        Ok(DemoCrystallizeResp {
            zsa_txid: hex::encode(rcpt.tx_id),
            asset_id: sess.asset_id.to_hex(),
            asset_base: sess.asset_base_hex.clone(),
            frost_signers: "Signers #1 & #3 (2-of-3 Pallas Schnorr, trusted-dealer setup)".into(),
            value: 1,
            finalized: true,
        })
    }
}
