//! Browser-proved Studio steps.
//!
//! Each step is split in three. `prepare` does the server's part (ledger checks, key re-wrap,
//! challenge) and hands the browser a [`ProofJob`] under a one-use ticket. The browser proves.
//! `commit` checks the returned public proof against what the server expects and only then
//! updates the simulated ledger. The server never holds the uncompressed lineage proof for
//! these sessions.

use crate::demo_engine::{
    DemoClearAuctionResp, DemoListResp, DemoMintReq, DemoTraitProofResp, DemoWorkbench,
    PreparedMint, PreparedTransfer,
};
use crate::{AuctionClearResult, GalleryService};
use anyhow::{anyhow, bail, Result};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zyoza_core::{OwnershipVerifyRequest, ZyEnvelopeAlias, PROTOCOL_VERSION};
use zyoza_proofs::{
    derive_creator_tag, derive_owner_tag, IssuanceCapEngine, RaguMigrationProof, RaguPcdEngine,
    RaguPcdProof, RaguStepKind, TraitMerkleTree,
};
use zyoza_studio_prover::{
    derive_demo_actor_secret, ProofJob, ProofOutput, CREATOR_ROYALTY_SECRET, TICKET_EVENT_ID,
};

const MAX_SUPPLY: u64 = 100;

/// What the server remembers between `prepare` and `commit`.
pub enum PendingJob {
    Mint(Box<PreparedMint>),
    Transfer {
        prep: Box<PreparedTransfer>,
        cleared: Option<AuctionClearResult>,
    },
    Fold {
        session_id: String,
        step_kind: String,
        kind: RaguStepKind,
        profile_id: [u8; 4],
        next_commit: [u8; 32],
        nonce: [u8; 32],
    },
    Trait {
        session_id: String,
        key: String,
        val: String,
        traits_root: [u8; 32],
        challenge: [u8; 32],
    },
    List {
        session_id: String,
        collection_root: [u8; 32],
        state_root: [u8; 32],
        challenge: [u8; 32],
        collection_size: usize,
        reserve_zatoshis: u64,
        wrong_secret: bool,
    },
    Crystallize {
        session_id: String,
    },
}

impl PendingJob {
    fn session_id(&self) -> Option<&str> {
        match self {
            PendingJob::Mint(_) => None,
            PendingJob::Transfer { prep, .. } => Some(&prep.session_id),
            PendingJob::Fold { session_id, .. }
            | PendingJob::Trait { session_id, .. }
            | PendingJob::List { session_id, .. }
            | PendingJob::Crystallize { session_id } => Some(session_id),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BrowserPrepareReq {
    Mint {
        preset: String,
        token_index: u64,
    },
    Transfer {
        session_id: String,
    },
    Fold {
        session_id: String,
        step_kind: String,
        profile_id: String,
        #[serde(default)]
        simulate_unpaid_royalty: bool,
    },
    Trait {
        session_id: String,
    },
    List {
        session_id: String,
        #[serde(default)]
        reserve_zatoshis: u64,
        #[serde(default)]
        wrong_secret: bool,
    },
    Clear {
        session_id: String,
    },
    Crystallize {
        session_id: String,
    },
}

#[derive(Serialize)]
pub struct BrowserPrepareResp {
    pub ticket: String,
    pub job: ProofJob,
}

#[derive(Deserialize)]
pub struct BrowserCommitReq {
    pub ticket: String,
    pub output: ProofOutput,
    /// How long the browser spent proving. Shown back to the visitor; not trusted for anything.
    #[serde(default)]
    pub prove_ms: u64,
}

fn owner_tag(actor: &str) -> [u8; 32] {
    derive_owner_tag(&derive_demo_actor_secret(actor))
}

fn issue_ticket(wb: &mut DemoWorkbench, pending: PendingJob, job: ProofJob) -> BrowserPrepareResp {
    let mut salt = [0u8; 8];
    UnwrapErr(SysRng).fill_bytes(&mut salt);
    wb.next_ticket += 1;
    let ticket = format!("job-{}-{}", wb.next_ticket, hex::encode(salt));
    wb.pending.insert(ticket.clone(), pending);
    BrowserPrepareResp { ticket, job }
}

/// A browser that closed mid-proof leaves its session busy. A new request for the same session
/// replaces that abandoned job.
fn drop_stale(wb: &mut DemoWorkbench, session_id: &str) {
    let stale: Vec<String> = wb
        .pending
        .iter()
        .filter(|(_, p)| p.session_id() == Some(session_id))
        .map(|(t, _)| t.clone())
        .collect();
    for t in stale {
        wb.pending.remove(&t);
        wb.release_busy(session_id);
    }
}

pub fn prepare(
    wb: &mut DemoWorkbench,
    gal: &mut GalleryService,
    req: BrowserPrepareReq,
) -> Result<BrowserPrepareResp> {
    match req {
        BrowserPrepareReq::Mint { preset, token_index } => {
            if wb
                .sessions
                .values()
                .any(|s| s.preset == preset && s.token_index == token_index)
            {
                bail!(
                    "governed mint rejected: CollectionSpec nullifiers NF_aid / NF_idx #{token_index} / NF_med already claimed for {preset}"
                );
            }
            let prep = wb.prep_mint(&DemoMintReq { preset, token_index })?;
            let job = ProofJob::Mint {
                asset_id: prep.asset_id,
                commitment: prep.commitment,
                collection_id: prep.spec.collection_id(),
                token_index: prep.token_index,
                cap_blinding: prep.cap_blinding,
                max_supply: MAX_SUPPLY,
            };
            Ok(issue_ticket(wb, PendingJob::Mint(Box::new(prep)), job))
        }
        BrowserPrepareReq::Transfer { session_id } => {
            drop_stale(wb, &session_id);
            let prep = wb.prep_transfer_mode(&session_id, "bob", true)?;
            let job = transfer_job(&prep);
            Ok(issue_ticket(
                wb,
                PendingJob::Transfer { prep: Box::new(prep), cleared: None },
                job,
            ))
        }
        BrowserPrepareReq::Clear { session_id } => {
            drop_stale(wb, &session_id);
            let sess = wb
                .sessions
                .get(&session_id)
                .ok_or_else(|| anyhow!("session {session_id} not found (reset or mint first)"))?;
            if !sess.browser {
                bail!("session {session_id} proves on the server; reset to switch to browser proving");
            }
            let listing_id = sess.listing_id.ok_or_else(|| anyhow!("session is not listed"))?;
            let cleared = gal.clear_auction(listing_id)?;
            let prep = wb.prep_transfer_mode(&session_id, &cleared.winning_bidder, true)?;
            let job = transfer_job(&prep);
            Ok(issue_ticket(
                wb,
                PendingJob::Transfer { prep: Box::new(prep), cleared: Some(cleared) },
                job,
            ))
        }
        BrowserPrepareReq::Fold { session_id, step_kind, profile_id, simulate_unpaid_royalty } => {
            let kind = RaguStepKind::parse_strict(&step_kind)?;
            let prof: [u8; 4] = profile_id
                .as_bytes()
                .try_into()
                .map_err(|_| anyhow!("profile_id must be a 4-character tag"))?;
            drop_stale(wb, &session_id);
            let sess = wb.acquire_busy_mode(&session_id, true)?;
            if sess.crystallized {
                wb.release_busy(&session_id);
                bail!("Stage I seal already burned and crystallized into Stage II ZSA");
            }
            if kind == RaguStepKind::TicketCheckInStep {
                if let Err(e) = wb.ensure_ticket_unused(&sess.asset_id) {
                    wb.release_busy(&session_id);
                    return Err(e);
                }
            }
            let mut nonce = [0u8; 32];
            UnwrapErr(SysRng).fill_bytes(&mut nonce);
            let state_root = match sess.nft_state.state_root() {
                Ok(r) => r,
                Err(e) => {
                    wb.release_busy(&session_id);
                    return Err(e.into());
                }
            };
            let next_commit = ZyEnvelopeAlias {
                version: PROTOCOL_VERSION,
                profile_id: prof,
                asset_id: sess.asset_id,
                state_root,
                prev_commitment: Some(sess.commitment),
                nonce,
            }
            .state_commitment();
            let job = ProofJob::Fold {
                asset_id: sess.asset_id,
                kind,
                profile_id: prof,
                next_commit,
                owner: sess.owner.clone(),
                next_owner: None,
                unpaid_royalty: simulate_unpaid_royalty,
                event_id: (kind == RaguStepKind::TicketCheckInStep).then_some(TICKET_EVENT_ID),
            };
            Ok(issue_ticket(
                wb,
                PendingJob::Fold { session_id, step_kind, kind, profile_id: prof, next_commit, nonce },
                job,
            ))
        }
        BrowserPrepareReq::Trait { session_id } => {
            drop_stale(wb, &session_id);
            let sess = wb.acquire_busy_mode(&session_id, true)?;
            let pairs: Vec<(&str, &str)> = sess
                .nft_state
                .traits
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let Some(&(key, val)) = pairs.first() else {
                wb.release_busy(&session_id);
                bail!("asset has no traits");
            };
            let tree = TraitMerkleTree::from_traits(pairs.clone());
            let mut challenge = [0u8; 32];
            UnwrapErr(SysRng).fill_bytes(&mut challenge);
            let job = ProofJob::Trait {
                asset_id: sess.asset_id,
                key: key.to_string(),
                val: val.to_string(),
                path: tree.path(0),
                owner: sess.owner.clone(),
                challenge,
            };
            let pending = PendingJob::Trait {
                session_id,
                key: key.to_string(),
                val: val.to_string(),
                traits_root: tree.root(),
                challenge,
            };
            Ok(issue_ticket(wb, pending, job))
        }
        BrowserPrepareReq::List { session_id, reserve_zatoshis, wrong_secret } => {
            drop_stale(wb, &session_id);
            let sess = wb.acquire_busy_mode(&session_id, true)?;
            let fail = |wb: &mut DemoWorkbench, msg: String| -> Result<BrowserPrepareResp> {
                wb.release_busy(&session_id);
                Err(anyhow!(msg))
            };
            if sess.crystallized {
                return fail(wb, "Stage I seal already burned and crystallized into Stage II ZSA".into());
            }
            if !wrong_secret && sess.listing_id.is_some() {
                return fail(wb, "session is already listed on the gallery".into());
            }
            let (tree, idx, collection_size) = match wb.build_collection_tree(Some(&session_id)) {
                Ok(t) => t,
                Err(e) => return fail(wb, e.to_string()),
            };
            let state_root = match sess.nft_state.state_root() {
                Ok(r) => r,
                Err(e) => return fail(wb, e.to_string()),
            };
            let collection_root = tree.root();
            gal.register_collection_root(collection_root);
            let challenge = gal.issue_challenge();
            let job = ProofJob::Ownership {
                asset_id: sess.asset_id,
                state_root,
                collection_root,
                path: tree.path(idx.unwrap_or(0)),
                owner: sess.owner.clone(),
                challenge,
                wrong_secret,
            };
            let pending = PendingJob::List {
                session_id: session_id.clone(),
                collection_root,
                state_root,
                challenge,
                collection_size,
                reserve_zatoshis: if wrong_secret { 50_000_000 } else { reserve_zatoshis },
                wrong_secret,
            };
            Ok(issue_ticket(wb, pending, job))
        }
        BrowserPrepareReq::Crystallize { session_id } => {
            drop_stale(wb, &session_id);
            let sess = wb.acquire_busy_mode(&session_id, true)?;
            if sess.crystallized {
                wb.release_busy(&session_id);
                bail!("already crystallized into Stage II ZSA");
            }
            let job = ProofJob::Migration {
                asset_id: sess.asset_id,
                commitment: sess.commitment,
                owner: sess.owner.clone(),
            };
            Ok(issue_ticket(wb, PendingJob::Crystallize { session_id }, job))
        }
    }
}

fn transfer_job(prep: &PreparedTransfer) -> ProofJob {
    ProofJob::Fold {
        asset_id: prep.asset_id,
        kind: RaguStepKind::RoyaltyStep,
        profile_id: *b"NFT1",
        next_commit: prep.next_commit,
        owner: prep.prev_owner.clone(),
        next_owner: Some(prep.new_owner.clone()),
        unpaid_royalty: false,
        event_id: None,
    }
}

/// Drops a job the browser could not finish and frees its session.
pub fn abort(wb: &mut DemoWorkbench, ticket: &str) {
    if let Some(p) = wb.pending.remove(ticket) {
        if let Some(sid) = p.session_id() {
            let sid = sid.to_string();
            wb.release_busy(&sid);
        }
    }
}

/// The public proof must carry no foldable proof, and where the server verifies it, a
/// compressed proof of the right size.
fn sanitize(pcd: &mut RaguPcdProof, need_compressed: bool) -> Result<()> {
    pcd.uncompressed_proof.clear();
    if need_compressed && pcd.compressed_proof.len() != zyoza_proofs::compressed_proof_len() {
        bail!("browser proof is missing its compressed proof");
    }
    Ok(())
}

/// Checks that `next` is exactly one step past `prev` with the values the server prepared, then
/// verifies it. The header fields are what `verify_compressed` binds, so a proof for any other
/// statement fails here.
fn check_step(
    prev: &RaguPcdProof,
    next: &mut RaguPcdProof,
    next_commit: [u8; 32],
    owner: &str,
    kind: RaguStepKind,
    profile_id: [u8; 4],
) -> Result<()> {
    sanitize(next, true)?;
    if next.asset_id != prev.asset_id
        || next.genesis_commitment != prev.genesis_commitment
        || next.royalty_required != prev.royalty_required
        || next.creator_tag_bytes != prev.creator_tag_bytes
    {
        bail!("browser proof does not continue this object's lineage");
    }
    if next.latest_commitment != next_commit {
        bail!("browser proof commits to a different state than the ledger prepared");
    }
    if next.step_count != prev.step_count + 1 || next.last_step != kind || next.last_profile != profile_id
    {
        bail!("browser proof is not the requested step");
    }
    if next.owner_tag_bytes != owner_tag(owner) {
        bail!("browser proof names a different owner");
    }
    if !RaguPcdEngine.verify_pcd(next)? {
        bail!("Ragu verify_compressed rejected the browser's proof");
    }
    Ok(())
}

/// Checks that the browser's compressed proof is for the lineage state the server recorded.
fn check_current(recorded: &RaguPcdProof, ledger_commit: [u8; 32], shown: &mut RaguPcdProof) -> Result<()> {
    sanitize(shown, true)?;
    let same = shown.asset_id == recorded.asset_id
        && shown.genesis_commitment == recorded.genesis_commitment
        && shown.latest_commitment == recorded.latest_commitment
        && shown.owner_tag_bytes == recorded.owner_tag_bytes
        && shown.step_count == recorded.step_count
        && shown.last_step == recorded.last_step
        && shown.last_profile == recorded.last_profile
        && shown.royalty_required == recorded.royalty_required
        && shown.creator_tag_bytes == recorded.creator_tag_bytes
        && shown.event_nullifier_bytes == recorded.event_nullifier_bytes;
    if !same {
        bail!("browser lineage proof does not match the session's recorded lineage");
    }
    if shown.latest_commitment != ledger_commit {
        bail!("lineage proof latest_commitment does not match ledger commitment");
    }
    if !RaguPcdEngine.verify_pcd(shown)? {
        bail!("session lineage proof failed verify_compressed");
    }
    Ok(())
}

pub fn commit(
    wb: &mut DemoWorkbench,
    gal: &mut GalleryService,
    req: BrowserCommitReq,
) -> Result<Value> {
    let pending = wb
        .pending
        .remove(&req.ticket)
        .ok_or_else(|| anyhow!("unknown or already used proof ticket"))?;
    let sid = pending.session_id().map(str::to_string);
    let res = commit_inner(wb, gal, pending, req.output, req.prove_ms);
    if res.is_err() {
        if let Some(sid) = sid {
            wb.release_busy(&sid);
        }
    }
    res
}

fn commit_inner(
    wb: &mut DemoWorkbench,
    gal: &mut GalleryService,
    pending: PendingJob,
    output: ProofOutput,
    prove_ms: u64,
) -> Result<Value> {
    match (pending, output) {
        (PendingJob::Mint(prep), ProofOutput::Mint { mut pcd, cap_proof }) => {
            sanitize(&mut pcd, false)?;
            let ok = pcd.asset_id == prep.asset_id
                && pcd.genesis_commitment == prep.commitment
                && pcd.latest_commitment == prep.commitment
                && pcd.step_count == 1
                && pcd.last_step == RaguStepKind::MintStep
                && pcd.last_profile == *b"NFT1"
                && pcd.royalty_required
                && pcd.creator_tag_bytes == derive_creator_tag(CREATOR_ROYALTY_SECRET)
                && pcd.owner_tag_bytes == owner_tag("alice");
            if !ok {
                bail!("browser mint proof does not match the prepared mint");
            }
            if !pcd.compressed_proof.is_empty() && !RaguPcdEngine.verify_pcd(&pcd)? {
                bail!("Ragu verify_compressed rejected the browser's mint proof");
            }
            let col_id = prep.spec.collection_id();
            if !IssuanceCapEngine.verify_cap(col_id, &prep.asset_id, MAX_SUPPLY, &cap_proof)? {
                bail!("IssuanceCapCircuit verification failed");
            }
            let resp = wb.commit_mint(*prep, pcd, cap_proof, gal)?;
            if let Some(s) = wb.sessions.get_mut(&resp.session_id) {
                s.browser = true;
            }
            Ok(json!(resp))
        }
        (PendingJob::Transfer { prep, cleared }, ProofOutput::Fold { mut pcd }) => {
            check_step(
                &prep.prev_pcd,
                &mut pcd,
                prep.next_commit,
                &prep.new_owner,
                RaguStepKind::RoyaltyStep,
                *b"NFT1",
            )?;
            let xfer = wb.commit_transfer(*prep, pcd, gal)?;
            Ok(match cleared {
                Some(c) => json!(DemoClearAuctionResp {
                    winning_bidder: c.winning_bidder,
                    clearing_price_zatoshis: c.clearing_price_zatoshis,
                    new_commitment: xfer.new_commitment,
                    new_oob_uri: xfer.new_oob_uri,
                    pcd_steps: xfer.pcd_steps,
                }),
                None => json!(xfer),
            })
        }
        (
            PendingJob::Fold { session_id, step_kind, kind, profile_id, next_commit, nonce },
            ProofOutput::Fold { mut pcd },
        ) => {
            let sess = wb
                .sessions
                .get(&session_id)
                .ok_or_else(|| anyhow!("session {session_id} not found"))?
                .clone();
            let t = std::time::Instant::now();
            check_step(&sess.pcd, &mut pcd, next_commit, &sess.owner, kind, profile_id)?;
            let verify_ms = t.elapsed().as_millis();
            let resp =
                wb.commit_folded_step(&session_id, step_kind, kind, next_commit, nonce, pcd, verify_ms)?;
            Ok(json!(resp))
        }
        (
            PendingJob::Trait { session_id, key, val, traits_root, challenge },
            ProofOutput::Trait { proof },
        ) => {
            let sess = wb
                .sessions
                .get(&session_id)
                .ok_or_else(|| anyhow!("session {session_id} not found"))?
                .clone();
            let t = std::time::Instant::now();
            let ok = RaguPcdEngine.verify_attribute(
                &sess.asset_id,
                traits_root,
                sess.pcd.owner_tag_bytes,
                &key,
                &val,
                challenge,
                &proof,
            )?;
            let verify_ms = t.elapsed().as_millis();
            if !ok {
                bail!("AttributeCircuit verification failed");
            }
            wb.release_busy(&session_id);
            Ok(json!(DemoTraitProofResp {
                trait_key: key,
                trait_val: val,
                traits_root_hex: hex::encode(traits_root),
                proof_bytes: proof.len(),
                prove_ms: prove_ms as u128,
                verify_ms,
            }))
        }
        (
            PendingJob::List {
                session_id,
                collection_root,
                state_root,
                challenge,
                collection_size,
                reserve_zatoshis,
                wrong_secret: _,
            },
            ProofOutput::Ownership { proof, mut pcd },
        ) => {
            let sess = wb
                .sessions
                .get(&session_id)
                .ok_or_else(|| anyhow!("session {session_id} not found"))?
                .clone();
            check_current(&sess.pcd, sess.commitment, &mut pcd)?;
            let t = std::time::Instant::now();
            let listing = gal.submit_listing(
                &sess.ovk,
                &OwnershipVerifyRequest { collection_root, state_root, challenge },
                &proof,
                &sess.nft_state.to_bytes()?,
                reserve_zatoshis,
            )?;
            let verify_ms = t.elapsed().as_millis();
            let s = wb.sessions.get_mut(&session_id).expect("session checked above");
            s.pcd = pcd;
            s.listing_id = Some(listing.listing_id);
            s.busy = false;
            Ok(json!(DemoListResp {
                listing_id: listing.listing_id,
                prove_ms: prove_ms as u128,
                verify_ms,
                proof_bytes: proof.len(),
                collection_root_hex: hex::encode(collection_root),
                state_root_hex: hex::encode(state_root),
                challenge_hex: hex::encode(challenge),
                collection_size,
                title: listing.preview.title,
            }))
        }
        (PendingJob::Crystallize { session_id }, ProofOutput::Migration { proof, mut pcd }) => {
            let sess = wb
                .sessions
                .get(&session_id)
                .ok_or_else(|| anyhow!("session {session_id} not found"))?
                .clone();
            check_current(&sess.pcd, sess.commitment, &mut pcd)?;
            if !RaguPcdEngine.verify_migration(
                &sess.asset_id,
                sess.commitment,
                pcd.owner_tag_bytes,
                &proof,
            )? {
                bail!("MigrationCircuit proof verification failed");
            }
            let parsed: RaguMigrationProof = serde_json::from_slice(&proof)?;
            wb.sessions.get_mut(&session_id).expect("session checked above").pcd = pcd;
            let resp = wb.commit_crystallize(&session_id, hex::encode(parsed.burn_nullifier_bytes))?;
            Ok(json!(resp))
        }
        _ => bail!("proof output does not match the prepared job"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_bid_commitment;
    use crate::demo_engine::{DemoCommitBidReq, DemoRevealBidReq};
    use zyoza_studio_prover::LineageStore;

    /// Plays the browser: prepare on the server, prove in a local `LineageStore`, commit.
    fn step(
        wb: &mut DemoWorkbench,
        gal: &mut GalleryService,
        store: &mut LineageStore,
        req: BrowserPrepareReq,
    ) -> Result<Value> {
        let BrowserPrepareResp { ticket, job } = prepare(wb, gal, req)?;
        let asset = job.asset_id();
        let output = match store.run(&job) {
            Ok(o) => o,
            Err(e) => {
                abort(wb, &ticket);
                store.discard(&asset);
                bail!(e);
            }
        };
        match commit(wb, gal, BrowserCommitReq { ticket, output, prove_ms: 1 }) {
            Ok(v) => {
                store.promote(&asset);
                Ok(v)
            }
            Err(e) => {
                store.discard(&asset);
                Err(e)
            }
        }
    }

    #[test]
    fn browser_proved_studio_flow_end_to_end() {
        let mut wb = DemoWorkbench::default();
        let mut gal = GalleryService::default();
        let mut store = LineageStore::default();
        let fold = |sid: &str, kind: &str, prof: &str, unpaid: bool| BrowserPrepareReq::Fold {
            session_id: sid.into(),
            step_kind: kind.into(),
            profile_id: prof.into(),
            simulate_unpaid_royalty: unpaid,
        };

        // Mint. The server ends up with the public view only.
        let minted = step(
            &mut wb,
            &mut gal,
            &mut store,
            BrowserPrepareReq::Mint { preset: "nounz-venetian".into(), token_index: 1 },
        )
        .unwrap();
        let sid = minted["session_id"].as_str().unwrap().to_string();
        assert!(wb.sessions[&sid].browser);
        assert!(wb.sessions[&sid].pcd.uncompressed_proof.is_empty());

        // The server-proved path refuses a browser session.
        let err = wb.acquire_busy(&sid).map(|_| ()).unwrap_err().to_string();
        assert!(err.contains("proves in the browser"), "{err}");

        // Duplicate mint is rejected before any proving.
        assert!(prepare(
            &mut wb,
            &mut gal,
            BrowserPrepareReq::Mint { preset: "nounz-venetian".into(), token_index: 1 },
        )
        .is_err());

        // Transfer to Bob: verified by the server before the ledger moves.
        let xfer = step(&mut wb, &mut gal, &mut store, BrowserPrepareReq::Transfer { session_id: sid.clone() })
            .unwrap();
        assert_eq!(xfer["owner"], "bob");
        assert_eq!(wb.sessions[&sid].pcd.step_count, 2);
        assert!(!wb.sessions[&sid].busy);

        // A proof for the wrong statement is rejected and the ledger does not move.
        let before = wb.sessions[&sid].commitment;
        let BrowserPrepareResp { ticket, job } =
            prepare(&mut wb, &mut gal, fold(&sid, "AttributeUpgradeStep", "GAM1", false)).unwrap();
        let ProofOutput::Fold { mut pcd } = store.run(&job).unwrap() else { panic!("fold output") };
        pcd.step_count += 1;
        let err = commit(
            &mut wb,
            &mut gal,
            BrowserCommitReq { ticket: ticket.clone(), output: ProofOutput::Fold { pcd }, prove_ms: 0 },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not the requested step"), "{err}");
        store.discard(&job.asset_id());
        assert_eq!(wb.sessions[&sid].commitment, before);
        assert!(!wb.sessions[&sid].busy);
        // A ticket is single-use.
        assert!(commit(
            &mut wb,
            &mut gal,
            BrowserCommitReq {
                ticket,
                output: ProofOutput::Trait { proof: vec![] },
                prove_ms: 0
            },
        )
        .is_err());

        // A ticket check-in works once and exposes the nullifier for this object at this event.
        let checked = step(&mut wb, &mut gal, &mut store, fold(&sid, "TicketCheckInStep", "TKT1", false)).unwrap();
        assert_eq!(checked["step_count"], 3);
        let nf = zyoza_proofs::derive_ticket_event_nullifier(&wb.sessions[&sid].asset_id, &TICKET_EVENT_ID);
        assert_eq!(checked["event_nullifier_hex"], hex::encode(nf));

        // A second check-in is refused up front, before the browser spends time proving.
        let err = step(&mut wb, &mut gal, &mut store, fold(&sid, "TicketCheckInStep", "TKT1", false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("replay blocked"), "{err}");
        assert!(!wb.sessions[&sid].busy);

        // And if a valid second proof is produced anyway, the gate still refuses it at commit:
        // it carries the same nullifier. The ledger and the browser's lineage do not move.
        let before = wb.sessions[&sid].commitment;
        wb.spent_ticket_nullifiers.remove(&nf);
        let BrowserPrepareResp { ticket, job } =
            prepare(&mut wb, &mut gal, fold(&sid, "TicketCheckInStep", "TKT1", false)).unwrap();
        wb.spent_ticket_nullifiers.insert(nf);
        let output = store.run(&job).unwrap();
        let err = commit(&mut wb, &mut gal, BrowserCommitReq { ticket, output, prove_ms: 0 })
            .unwrap_err()
            .to_string();
        assert!(err.contains("replay blocked"), "{err}");
        store.discard(&job.asset_id());
        assert_eq!(wb.sessions[&sid].commitment, before);
        assert_eq!(wb.sessions[&sid].pcd.step_count, 3);
        assert!(!wb.sessions[&sid].busy);

        // Unpaid royalty is refused by the prover itself; the session is released.
        assert!(step(&mut wb, &mut gal, &mut store, fold(&sid, "RoyaltyStep", "NFT1", true)).is_err());
        assert!(!wb.sessions[&sid].busy);

        // The lineage still folds after those rejections.
        let up = step(&mut wb, &mut gal, &mut store, fold(&sid, "AttributeUpgradeStep", "GAM1", false)).unwrap();
        assert_eq!(up["step_count"], 4);

        // Trait proof, wrong-secret listing, then a real listing.
        step(&mut wb, &mut gal, &mut store, BrowserPrepareReq::Trait { session_id: sid.clone() }).unwrap();
        assert!(step(
            &mut wb,
            &mut gal,
            &mut store,
            BrowserPrepareReq::List { session_id: sid.clone(), reserve_zatoshis: 0, wrong_secret: true },
        )
        .is_err());
        assert!(wb.sessions[&sid].listing_id.is_none());
        let listed = step(
            &mut wb,
            &mut gal,
            &mut store,
            BrowserPrepareReq::List { session_id: sid.clone(), reserve_zatoshis: 50_000_000, wrong_secret: false },
        )
        .unwrap();
        let listing_id = listed["listing_id"].as_u64().unwrap();

        // Sealed bid, reveal, clear: the winner becomes the owner.
        let salt = [0x5A; 32];
        wb.commit_bid(
            DemoCommitBidReq {
                session_id: sid.clone(),
                bidder_id: "carol".into(),
                commitment_hex: hex::encode(compute_bid_commitment(listing_id, "carol", 85_000_000, &salt)),
            },
            &mut gal,
        )
        .unwrap();
        wb.reveal_bid(
            DemoRevealBidReq {
                session_id: sid.clone(),
                bidder_id: "carol".into(),
                bid_zatoshis: 85_000_000,
                salt_hex: hex::encode(salt),
            },
            &mut gal,
        )
        .unwrap();
        let cleared = step(&mut wb, &mut gal, &mut store, BrowserPrepareReq::Clear { session_id: sid.clone() })
            .unwrap();
        assert_eq!(cleared["winning_bidder"], "carol");
        assert_eq!(wb.sessions[&sid].owner, "carol");

        // Crystallize, then everything is locked.
        let crys = step(&mut wb, &mut gal, &mut store, BrowserPrepareReq::Crystallize { session_id: sid.clone() })
            .unwrap();
        assert_eq!(crys["finalized"], true);
        assert!(step(&mut wb, &mut gal, &mut store, BrowserPrepareReq::Transfer { session_id: sid.clone() }).is_err());
        assert!(wb.pending.is_empty());

        // A browser without the lineage (page reload) gets a clear message, and the job is dropped.
        let minted2 = step(
            &mut wb,
            &mut gal,
            &mut store,
            BrowserPrepareReq::Mint { preset: "nounz-mesh".into(), token_index: 2 },
        )
        .unwrap();
        let sid2 = minted2["session_id"].as_str().unwrap().to_string();
        let mut empty = LineageStore::default();
        let err = step(&mut wb, &mut gal, &mut empty, BrowserPrepareReq::Transfer { session_id: sid2.clone() })
            .unwrap_err()
            .to_string();
        assert!(err.contains("no longer holds"), "{err}");
        assert!(!wb.sessions[&sid2].busy);
    }
}
