use crate::GalleryService;
use anyhow::{bail, Result};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use zyoza_core::{
    AssetDesc, AssetId, CollectionSpec, MintClaim, ObjectViewingKey, OrchardMemoSeal,
    OwnershipProofRequest, OwnershipVerifyRequest, ProofEngine, SettlementAdapter, ZyEnvelopeAlias,
    PROTOCOL_VERSION,
};
use zyoza_oob::{InMemoryStorage, OobEnvelope, OobKeypair, OobStorage};
use zyoza_profile_nft::{CollectionPolicy, MediaManifest, NftState, ProvenanceEvent};
use zyoza_proofs::{Halo2ProofEngine, RaguPcdEngine, RaguPcdProof, RaguStepKind, RaguStepWitness};
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
    pub pcd_bytes: usize,
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
pub struct DemoFoldReq {
    pub session_id: String,
    pub step_kind: String,
    pub profile_id: String,
}

#[derive(Serialize)]
pub struct DemoFoldResp {
    pub step_count: u64,
    pub last_step: String,
    pub ipa_bytes: usize,
    pub json_bytes: usize,
    pub verify_ms: u128,
    pub acc_hex: String,
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
    pub title: String,
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
    nft_state: NftState,
    commitment: [u8; 32],
    oob_uri: String,
    ovk: ObjectViewingKey,
    pcd: RaguPcdProof,
}

/// Interactive cryptographic workbench backing `/demo`.
pub struct DemoWorkbench {
    next_num: u64,
    alice: OobKeypair,
    bob: OobKeypair,
    storage: InMemoryStorage,
    orchard: OrchardSealAdapter,
    zsa: OrchardZsaAdapter,
    sessions: HashMap<String, DemoSession>,
}

impl Default for DemoWorkbench {
    fn default() -> Self {
        Self {
            next_num: 0,
            alice: OobKeypair::from_seed_bytes(&[0xA1; 32]),
            bob: OobKeypair::from_seed_bytes(&[0xB2; 32]),
            storage: InMemoryStorage::default(),
            orchard: OrchardSealAdapter::new(),
            zsa: OrchardZsaAdapter::new(),
            sessions: HashMap::new(),
        }
    }
}

impl DemoWorkbench {
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
        let asset_id = AssetId::derive(&issuer_vk, &desc.to_canonical_bytes());
        let asset_base = asset_id.to_asset_base();

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
            description: "Shielded Zyoza Specimen".into(),
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

        let oob = OobEnvelope::seal(&mut rng, &env, &self.alice.public, &state_bytes)?;
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
                secret_witness: b"alice-mint".to_vec(),
            },
        )?;
        let pcd_bytes = serde_json::to_vec(&pcd)?.len();
        let ovk = ObjectViewingKey::derive(asset_id, &[0xA1; 32]);

        self.next_num += 1;
        let session_id = format!("zyoz-{}", self.next_num);
        self.sessions.insert(
            session_id.clone(),
            DemoSession {
                asset_id,
                nft_state,
                commitment,
                oob_uri: oob_uri.clone(),
                ovk: ovk.clone(),
                pcd,
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
            pcd_bytes,
            pcd_steps: 1,
        })
    }

    pub fn transfer(&mut self, req: SessionReq) -> Result<DemoTransferResp> {
        let mut rng = StdRng::seed_from_u64(2026);
        let sess = self
            .sessions
            .get_mut(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;

        let prev_oob = self.storage.get(&sess.oob_uri)?;
        let new_oob = prev_oob.rewrap_for_recipient(
            &mut rng,
            &self.alice.secret,
            &self.bob.public,
            [0x42; 32],
        )?;
        let new_oob_uri = self.storage.put(&new_oob)?;

        let mut next_commit = sess.commitment;
        next_commit[0] ^= 0xFF;
        let memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id: sess.asset_id,
            state_root: sess.nft_state.state_root()?,
            nonce: [0x42; 32],
            oob_pointer_hash: new_oob.pointer_hash()?,
            oob_uri: new_oob_uri.clone(),
        }
        .to_bytes()?;

        self.orchard
            .anchor_transfer(&sess.asset_id, sess.commitment, next_commit, &memo)?;
        sess.commitment = next_commit;
        sess.oob_uri = new_oob_uri.clone();

        Ok(DemoTransferResp {
            prev_spent: true,
            new_commitment: hex::encode(next_commit),
            new_oob_uri,
            owner: "bob".into(),
        })
    }

    pub fn decrypt(&self, req: DemoDecryptReq) -> Result<DemoDecryptResp> {
        let sess = self
            .sessions
            .get(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        let oob = self.storage.get(&sess.oob_uri)?;
        let sk = match req.actor.as_str() {
            "alice" => &self.alice.secret,
            "bob" => &self.bob.secret,
            other => bail!("unknown actor: {other}"),
        };
        let plain = oob.open(sk)?;
        let parsed = NftState::from_bytes(&plain)?;
        Ok(DemoDecryptResp {
            decrypted_summary: format!("{} (creator: {})", parsed.title, parsed.creator),
        })
    }

    pub fn fold(&mut self, req: DemoFoldReq) -> Result<DemoFoldResp> {
        let sess = self
            .sessions
            .get_mut(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        let kind = match req.step_kind.as_str() {
            "RoyaltyStep" => RaguStepKind::RoyaltyStep,
            "TicketCheckInStep" => RaguStepKind::TicketCheckInStep,
            "AttributeUpgradeStep" => RaguStepKind::AttributeUpgradeStep,
            _ => RaguStepKind::TransferStep,
        };
        let mut prof = [b' '; 4];
        for (i, b) in req.profile_id.bytes().take(4).enumerate() {
            prof[i] = b;
        }
        let prev_acc = sess.pcd.acc_bytes;
        let next_pcd = RaguPcdEngine.fold_step(
            Some(&sess.pcd),
            &RaguStepWitness {
                kind,
                profile_id: prof,
                asset_id: sess.asset_id,
                state_commitment: sess.commitment,
                secret_witness: b"fold-witness".to_vec(),
            },
        )?;
        let t_ver = std::time::Instant::now();
        let ok = RaguPcdEngine.verify_pcd_against_prev(Some(prev_acc), &next_pcd)?;
        let verify_ms = t_ver.elapsed().as_millis();
        if !ok {
            bail!("PCD verification failed");
        }
        let ipa_bytes = next_pcd.payload.ipa_proof.len();
        let json_bytes = serde_json::to_vec(&next_pcd)?.len();
        sess.pcd = next_pcd;

        Ok(DemoFoldResp {
            step_count: sess.pcd.step_count,
            last_step: req.step_kind,
            ipa_bytes,
            json_bytes,
            verify_ms,
            acc_hex: hex::encode(sess.pcd.acc_bytes),
        })
    }

    pub fn list_on_gallery(
        &self,
        req: DemoListReq,
        gallery: &mut GalleryService,
    ) -> Result<DemoListResp> {
        let sess = self
            .sessions
            .get(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        let collection_root = [0x33; 32];
        let challenge = [0x44; 32];

        let t0 = std::time::Instant::now();
        let proof = Halo2ProofEngine.prove_ownership(&OwnershipProofRequest {
            asset_id: sess.asset_id,
            collection_root,
            secret_witness: b"holder-sk".to_vec(),
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

        Ok(DemoListResp {
            listing_id: listing.listing_id,
            prove_ms,
            verify_ms,
            proof_bytes: proof.len(),
            title: listing.preview.title,
        })
    }

    pub fn crystallize(&mut self, req: SessionReq) -> Result<DemoCrystallizeResp> {
        let mut rng = StdRng::seed_from_u64(4444);
        let sess = self
            .sessions
            .get_mut(&req.session_id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;

        // 1. Halo2 migration proof
        let mig_proof =
            Halo2ProofEngine.prove_migration(&sess.asset_id, sess.commitment, b"owner-sk")?;
        if !Halo2ProofEngine.verify_migration(&sess.asset_id, sess.commitment, &mig_proof)? {
            bail!("migration proof invalid");
        }

        // 2. Burn Stage I Orchard seal
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

        // 3. 2-of-3 Pallas FROST threshold signature
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

        // 4. Mint native ZSA note
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

        Ok(DemoCrystallizeResp {
            zsa_txid: hex::encode(rcpt.tx_id),
            asset_id: sess.asset_id.to_hex(),
            asset_base: sess.asset_id.to_asset_base().to_hex(),
            frost_signers: "Signers #1 & #3 (2-of-3 Pallas FROST)".into(),
            value: 1,
            finalized: true,
        })
    }
}
