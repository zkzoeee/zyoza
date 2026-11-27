//! Opt-in viewing-key gallery & sealed-bid auction demo for Zyoza NFTs.

pub mod http;

use anyhow::{bail, Result};
use zyoza_core::{
    AssetProfile, ObjectViewingKey, OwnershipVerifyRequest, ProfilePreview, ProofEngine,
};
use zyoza_profile_nft::NftProfile;
use zyoza_proofs::Halo2ProofEngine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A privately listed NFT in the gallery, unlocked only via its `ObjectViewingKey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GalleryListing {
    pub listing_id: u64,
    pub preview: ProfilePreview,
    pub zk_verified_ownership: bool,
    pub reserve_zatoshis: u64,
    pub bids: Vec<SealedBid>,
    pub cleared: bool,
}

/// A shielded ZEC sealed bid submitted to a gallery listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBid {
    pub bidder_id: String,
    pub shielded_zec_commitment: [u8; 32],
    pub bid_zatoshis: u64,
}

/// Result of clearing a sealed-bid auction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionClearResult {
    pub listing_id: u64,
    pub winning_bidder: String,
    pub clearing_price_zatoshis: u64,
    pub shielded_zec_commitment: [u8; 32],
}

/// Opt-in viewing-key gallery service.
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

    /// Lists an NFT after verifying its Halo2 ZK ownership proof and unlocking preview via OVK.
    pub fn submit_listing(
        &mut self,
        ovk: &ObjectViewingKey,
        verify_req: &OwnershipVerifyRequest,
        ownership_proof: &[u8],
        nft_state_bytes: &[u8],
        reserve_zatoshis: u64,
    ) -> Result<GalleryListing> {
        let zk_ok = Halo2ProofEngine.verify_ownership(verify_req, ownership_proof)?;
        if !zk_ok {
            bail!("ZK ownership proof failed verification");
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

    /// Submits a sealed ZEC bid to an active listing.
    pub fn submit_sealed_bid(&mut self, listing_id: u64, bid: SealedBid) -> Result<()> {
        let listing = self
            .listings
            .get_mut(&listing_id)
            .ok_or_else(|| anyhow::anyhow!("listing {listing_id} not found"))?;
        if listing.cleared {
            bail!("listing {listing_id} already cleared");
        }
        listing.bids.push(bid);
        Ok(())
    }

    /// Clears the sealed-bid auction, awarding the NFT to the highest bid >= reserve.
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
            .filter(|b| b.bid_zatoshis >= listing.reserve_zatoshis)
            .max_by_key(|b| b.bid_zatoshis)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no sealed bids met reserve"))?;

        listing.cleared = true;
        Ok(AuctionClearResult {
            listing_id,
            winning_bidder: winner.bidder_id,
            clearing_price_zatoshis: winner.bid_zatoshis,
            shielded_zec_commitment: winner.shielded_zec_commitment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zyoza_core::{AssetDesc, AssetId, OwnershipProofRequest};
    use zyoza_profile_nft::{CollectionPolicy, MediaManifest, NftState, ProvenanceEvent};
    use std::collections::BTreeMap;

    #[test]
    fn private_listing_zk_badge_and_sealed_bid_clearing() {
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

        let collection_root = [0x55; 32];
        let challenge = [0x66; 32];
        let proof = Halo2ProofEngine
            .prove_ownership(&OwnershipProofRequest {
                asset_id,
                collection_root,
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

        gallery
            .submit_sealed_bid(
                listing.listing_id,
                SealedBid {
                    bidder_id: "bob".into(),
                    shielded_zec_commitment: [0x11; 32],
                    bid_zatoshis: 120_000_000,
                },
            )
            .unwrap();
        gallery
            .submit_sealed_bid(
                listing.listing_id,
                SealedBid {
                    bidder_id: "carol".into(),
                    shielded_zec_commitment: [0x22; 32],
                    bid_zatoshis: 150_000_000,
                },
            )
            .unwrap();

        let cleared = gallery.clear_auction(listing.listing_id).unwrap();
        assert_eq!(cleared.winning_bidder, "carol");
        assert_eq!(cleared.clearing_price_zatoshis, 150_000_000);
    }
}
