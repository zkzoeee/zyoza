//! Opt-in viewing-key gallery & commit-reveal sealed-bid auction service for Zyoza NFTs.

pub mod demo_engine;
pub mod http;

use anyhow::{bail, Result};
use blake2b_simd::Params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zyoza_core::{
    AssetProfile, ObjectViewingKey, OwnershipVerifyRequest, ProfilePreview, ProofEngine,
};
use zyoza_profile_nft::NftProfile;
use zyoza_proofs::RaguPcdEngine;

const PERSONAL_BID_COMMIT: &[u8; 16] = b"ZYOZA-BID-CMT1__";

/// Computes a salted BLAKE2b-256 commitment hiding `bid_zatoshis` during the bidding window:
/// `BLAKE2b-256("ZYOZA-BID-CMT1__", listing_id || bidder_id || bid_zatoshis || salt)`.
pub fn compute_bid_commitment(
    listing_id: u64,
    bidder_id: &str,
    bid_zatoshis: u64,
    salt: &[u8; 32],
) -> [u8; 32] {
    let mut h = Params::new()
        .hash_length(32)
        .personal(PERSONAL_BID_COMMIT)
        .to_state();
    h.update(&listing_id.to_be_bytes());
    h.update(&(bidder_id.len() as u32).to_be_bytes());
    h.update(bidder_id.as_bytes());
    h.update(&bid_zatoshis.to_be_bytes());
    h.update(salt);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// A privately listed NFT in the gallery, unlocked only via its `ObjectViewingKey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GalleryListing {
    pub listing_id: u64,
    pub preview: ProfilePreview,
    pub zk_verified_ownership: bool,
    pub reserve_zatoshis: u64,
    /// Publicly visible bid commitments; unrevealed bids hide their `revealed_zatoshis`.
    pub bids: Vec<SealedBidRecord>,
    pub cleared: bool,
}

/// Stored commit-reveal bid entry (`revealed_zatoshis` is `None` until revealed!).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBidRecord {
    pub bidder_id: String,
    pub commitment_hex: String,
    pub revealed_zatoshis: Option<u64>,
}

/// Phase-1 commit payload submitting only a salted hash commitment (no plaintext amount).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitBidRequest {
    pub bidder_id: String,
    pub commitment_hex: String,
}

/// Phase-2 reveal payload opening a previously committed sealed bid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealBidRequest {
    pub bidder_id: String,
    pub bid_zatoshis: u64,
    pub salt_hex: String,
}

/// Result of clearing a commit-reveal sealed-bid auction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionClearResult {
    pub listing_id: u64,
    pub winning_bidder: String,
    pub clearing_price_zatoshis: u64,
    pub commitment_hex: String,
}

/// Opt-in viewing-key gallery service with commit-reveal sealed bidding.
#[derive(Default)]
pub struct GalleryService {
    next_id: u64,
    listings: HashMap<u64, GalleryListing>,
}

impl GalleryService {
    /// Returns all current gallery listings sorted by `listing_id`.
    pub fn list_listings(&self) -> Vec<GalleryListing> {
        let mut items: Vec<_> = self.listings.values().cloned().collect();
        items.sort_by_key(|l| l.listing_id);
        items
    }

    /// Lists an NFT after verifying its Ragu Poseidon-Merkle ZK ownership proof and unlocking preview via OVK.
    pub fn submit_listing(
        &mut self,
        ovk: &ObjectViewingKey,
        verify_req: &OwnershipVerifyRequest,
        ownership_proof: &[u8],
        nft_state_bytes: &[u8],
        reserve_zatoshis: u64,
    ) -> Result<GalleryListing> {
        let zk_ok = RaguPcdEngine.verify_ownership(verify_req, ownership_proof)?;
        if !zk_ok {
            bail!("ZK ownership proof failed Poseidon-Merkle verification");
        }

        let preview = NftProfile.public_preview(nft_state_bytes, Some(ovk))?;
        self.next_id += 1;
        let listing = GalleryListing {
            listing_id: self.next_id,
            preview,
            zk_verified_ownership: true,
            reserve_zatoshis,
            bids: Vec::new(),
            cleared: false,
        };
        self.listings.insert(listing.listing_id, listing.clone());
        Ok(listing)
    }

    /// Commits a salted sealed bid without exposing the bid amount.
    pub fn commit_sealed_bid(&mut self, listing_id: u64, req: CommitBidRequest) -> Result<()> {
        let bytes = hex::decode(&req.commitment_hex)?;
        if bytes.len() != 32 {
            bail!("commitment_hex must be 32 bytes (64 hex chars)");
        }
        let listing = self
            .listings
            .get_mut(&listing_id)
            .ok_or_else(|| anyhow::anyhow!("listing {listing_id} not found"))?;
        if listing.cleared {
            bail!("listing {listing_id} already cleared");
        }
        listing.bids.push(SealedBidRecord {
            bidder_id: req.bidder_id,
            commitment_hex: req.commitment_hex.to_lowercase(),
            revealed_zatoshis: None,
        });
        Ok(())
    }

    /// Reveals a previously committed bid by verifying `(bid_zatoshis, salt)` against `commitment_hex`.
    pub fn reveal_sealed_bid(&mut self, listing_id: u64, req: RevealBidRequest) -> Result<()> {
        let salt_vec = hex::decode(&req.salt_hex)?;
        if salt_vec.len() != 32 {
            bail!("salt_hex must be 32 bytes (64 hex chars)");
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_vec);

        let expected = hex::encode(compute_bid_commitment(
            listing_id,
            &req.bidder_id,
            req.bid_zatoshis,
            &salt,
        ));

        let listing = self
            .listings
            .get_mut(&listing_id)
            .ok_or_else(|| anyhow::anyhow!("listing {listing_id} not found"))?;
        if listing.cleared {
            bail!("listing {listing_id} already cleared");
        }

        let record = listing
            .bids
            .iter_mut()
            .find(|b| b.bidder_id == req.bidder_id && b.commitment_hex == expected)
            .ok_or_else(|| {
                anyhow::anyhow!("reveal does not match any committed bid for {}", req.bidder_id)
            })?;
        record.revealed_zatoshis = Some(req.bid_zatoshis);
        Ok(())
    }

    /// Clears the auction using validly revealed bids >= reserve.
    pub fn clear_auction(&mut self, listing_id: u64) -> Result<AuctionClearResult> {
        let listing = self
            .listings
            .get_mut(&listing_id)
            .ok_or_else(|| anyhow::anyhow!("listing {listing_id} not found"))?;
        if listing.cleared {
            bail!("listing {listing_id} already cleared");
        }

        let winner = listing
            .bids
            .iter()
            .filter_map(|b| {
                b.revealed_zatoshis
                    .filter(|&amt| amt >= listing.reserve_zatoshis)
                    .map(|amt| (b.bidder_id.clone(), amt, b.commitment_hex.clone()))
            })
            .max_by_key(|(_, amt, _)| *amt)
            .ok_or_else(|| anyhow::anyhow!("no revealed bids met reserve"))?;

        listing.cleared = true;
        Ok(AuctionClearResult {
            listing_id,
            winning_bidder: winner.0,
            clearing_price_zatoshis: winner.1,
            commitment_hex: winner.2,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use zyoza_core::{AssetDesc, AssetId, OwnershipProofRequest};
    use zyoza_profile_nft::{CollectionPolicy, MediaManifest, NftState, ProvenanceEvent};
    use zyoza_proofs::CollectionMerkleTree;

    #[test]
    fn private_listing_merkle_zk_badge_and_commit_reveal_auction() {
        let asset_id = AssetId::derive(
            &[0x01; 32],
            &AssetDesc {
                namespace: "zyoza".into(),
                collection: "gallery".into(),
                item_id: "1".into(),
            }
            .to_canonical_bytes(),
        );
        let ovk = ObjectViewingKey::derive(asset_id, &[0xAA; 32]);

        let state = NftState {
            asset_id,
            title: "Midnight Zyoza".into(),
            description: "Limited dark-pool edition".into(),
            creator: "alice".into(),
            media: MediaManifest {
                mime: "image/png".into(),
                sha256_hex: "b".repeat(64),
                encrypted_blob_uri: "ipfs://bafy...".into(),
            },
            traits: BTreeMap::from([("edition".into(), "1/1".into())]),
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

        let tree = CollectionMerkleTree::from_holdings(&[(asset_id, b"alice-sk")]);
        let collection_root = tree.root();
        let challenge = [0x66; 32];
        let proof = RaguPcdEngine
            .prove_ownership(&OwnershipProofRequest {
                asset_id,
                collection_root,
                merkle_siblings: tree.path(0),
                secret_witness: b"alice-sk".to_vec(),
                challenge,
            })
            .unwrap();

        let mut gallery = GalleryService::default();
        let listing = gallery
            .submit_listing(
                &ovk,
                &OwnershipVerifyRequest {
                    collection_root,
                    challenge,
                },
                &proof,
                &state.to_bytes().unwrap(),
                100_000_000,
            )
            .unwrap();

        assert!(listing.zk_verified_ownership);
        assert_eq!(listing.preview.title, "Midnight Zyoza");

        // Commit two bids: amounts stay None in list_listings()!
        let bob_salt = [0x11; 32];
        let carol_salt = [0x22; 32];
        let bob_cmt = hex::encode(compute_bid_commitment(
            listing.listing_id,
            "bob",
            120_000_000,
            &bob_salt,
        ));
        let carol_cmt = hex::encode(compute_bid_commitment(
            listing.listing_id,
            "carol",
            150_000_000,
            &carol_salt,
        ));

        gallery
            .commit_sealed_bid(
                listing.listing_id,
                CommitBidRequest {
                    bidder_id: "bob".into(),
                    commitment_hex: bob_cmt,
                },
            )
            .unwrap();
        gallery
            .commit_sealed_bid(
                listing.listing_id,
                CommitBidRequest {
                    bidder_id: "carol".into(),
                    commitment_hex: carol_cmt,
                },
            )
            .unwrap();

        // Before reveal, GET /api/listings exposes NO bid amounts!
        for b in &gallery.list_listings()[0].bids {
            assert!(b.revealed_zatoshis.is_none());
        }

        // Wrong reveal amount fails!
        assert!(gallery
            .reveal_sealed_bid(
                listing.listing_id,
                RevealBidRequest {
                    bidder_id: "carol".into(),
                    bid_zatoshis: 999_000_000,
                    salt_hex: hex::encode(carol_salt),
                }
            )
            .is_err());

        //Carol reveals honestly (Bob keeps his losing bid unrevealed & private!)
        gallery
            .reveal_sealed_bid(
                listing.listing_id,
                RevealBidRequest {
                    bidder_id: "carol".into(),
                    bid_zatoshis: 150_000_000,
                    salt_hex: hex::encode(carol_salt),
                },
            )
            .unwrap();

        let cleared = gallery.clear_auction(listing.listing_id).unwrap();
        assert_eq!(cleared.winning_bidder, "carol");
        assert_eq!(cleared.clearing_price_zatoshis, 150_000_000);
        // Bob's losing bid stayed completely unrevealed!
        assert!(gallery.list_listings()[0].bids[0].revealed_zatoshis.is_none());
    }
}
