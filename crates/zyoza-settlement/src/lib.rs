//! Swappable Zcash settlement adapters (Orchard seal, OrchardZSA, Tachyon).

pub mod frost_issuer;
pub mod orchard_rpc;
pub mod orchard_seal;
pub mod orchard_zsa;
pub mod tachyon;

pub use frost_issuer::{
    aggregate_signatures, keygen_dealer, round1_commit, round2_sign, verify_frost_signature,
    FrostSignature, IssuerShare, NonceCommit, PartialSignature,
};
pub use zyoza_core;
pub use orchard;
pub use orchard_rpc::{OrchardRpcAdapter, RpcConfig, RpcTransport};
pub use orchard_seal::{OrchardSealAdapter, OrchardSealRecord};
pub use orchard_zsa::{OrchardZsaAdapter, ZsaNote};
pub use tachyon::{MerkleWitness, Tachygram, TachyonAdapter, Tachystamp};

/// Atomically validates `claim` against `spec` and inserts all derived mint nullifiers
/// into `spent`, rejecting duplicates, over-mints, or copy-minted media.
pub(crate) fn claim_mint_nullifiers(
    spent: &mut std::collections::HashSet<[u8; 32]>,
    spec: &zyoza_core::CollectionSpec,
    claim: &zyoza_core::MintClaim,
) -> Result<Vec<[u8; 32]>, zyoza_core::ZyozaError> {
    let nfs = spec.validate_and_nullifiers(claim)?;
    for nf in &nfs {
        if spent.contains(nf) {
            return Err(zyoza_core::ZyozaError::Settlement(
                "governed mint rejected: duplicate AssetId, slot index, or media hash".into(),
            ));
        }
    }
    for nf in &nfs {
        spent.insert(*nf);
    }
    Ok(nfs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zyoza_core::{AssetId, OrchardMemoSeal, SettlementAdapter, PROTOCOL_VERSION};

    #[test]
    fn orchard_seal_mint_transfer_and_double_spend_rejection() {
        let adapter = OrchardSealAdapter::new();
        let asset_id = AssetId::derive(&[0xAA; 32], b"zyoza:nft:seal-test");

        let memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id,
            state_root: [0x11; 32],
            nonce: [0x22; 32],
            oob_pointer_hash: [0x33; 32],
            oob_uri: "mem://mint".to_string(),
        }
        .to_bytes()
        .unwrap();

        let mint_rcpt = adapter.anchor_mint(&asset_id, [0x01; 32], &memo).unwrap();
        assert!(adapter.verify_seal(&mint_rcpt).unwrap());

        let xfer_rcpt = adapter
            .anchor_transfer(&asset_id, [0x01; 32], [0x02; 32], &memo)
            .unwrap();
        assert!(!adapter.verify_seal(&mint_rcpt).unwrap());
        assert!(adapter.verify_seal(&xfer_rcpt).unwrap());

        // Double spend of [0x01; 32] must fail.
        let err = adapter
            .anchor_transfer(&asset_id, [0x01; 32], [0x03; 32], &memo)
            .unwrap_err();
        assert!(err.to_string().contains("double-spend"));
    }

    #[test]
    fn governed_mint_policies_unique_capped_media_and_window() {
        use zyoza_core::{CollectionSpec, MintClaim};

        let adapter = OrchardSealAdapter::new();
        let spec = CollectionSpec {
            issuer_vk: [0x01; 32],
            slug: "genesis-100".into(),
            max_supply: Some(100),
            unique_media: true,
            mint_window: Some((1_700_000_000, 1_700_001_000)),
        };

        let mk_memo = |asset_id: AssetId| {
            OrchardMemoSeal {
                version: PROTOCOL_VERSION,
                profile_id: *b"NFT1",
                asset_id,
                state_root: [0x11; 32],
                nonce: [0x22; 32],
                oob_pointer_hash: [0x33; 32],
                oob_uri: "mem://gov".into(),
            }
            .to_bytes()
            .unwrap()
        };

        let a1 = AssetId::derive(&[0x01; 32], b"genesis-100:1");
        let a2 = AssetId::derive(&[0x01; 32], b"genesis-100:2");

        // Valid mint #1
        adapter
            .anchor_governed_mint(
                &spec,
                &MintClaim {
                    asset_id: a1,
                    token_index: 1,
                    media_sha256: [0xAA; 32],
                    timestamp_unix: 1_700_000_500,
                },
                [0x01; 32],
                &mk_memo(a1),
            )
            .unwrap();

        // Duplicate AssetId with fresh commitment -> rejected
        assert!(adapter
            .anchor_governed_mint(
                &spec,
                &MintClaim {
                    asset_id: a1,
                    token_index: 2,
                    media_sha256: [0xBB; 32],
                    timestamp_unix: 1_700_000_500,
                },
                [0x02; 32],
                &mk_memo(a1),
            )
            .is_err());

        // Duplicate slot index #1 with different AssetId -> rejected
        assert!(adapter
            .anchor_governed_mint(
                &spec,
                &MintClaim {
                    asset_id: a2,
                    token_index: 1,
                    media_sha256: [0xBB; 32],
                    timestamp_unix: 1_700_000_500,
                },
                [0x03; 32],
                &mk_memo(a2),
            )
            .is_err());

        // Duplicate media hash -> rejected
        assert!(adapter
            .anchor_governed_mint(
                &spec,
                &MintClaim {
                    asset_id: a2,
                    token_index: 2,
                    media_sha256: [0xAA; 32],
                    timestamp_unix: 1_700_000_500,
                },
                [0x04; 32],
                &mk_memo(a2),
            )
            .is_err());

        // Over-cap (#101 > 100) -> rejected
        assert!(adapter
            .anchor_governed_mint(
                &spec,
                &MintClaim {
                    asset_id: a2,
                    token_index: 101,
                    media_sha256: [0xBB; 32],
                    timestamp_unix: 1_700_000_500,
                },
                [0x05; 32],
                &mk_memo(a2),
            )
            .is_err());

        // Outside mint window -> rejected
        assert!(adapter
            .anchor_governed_mint(
                &spec,
                &MintClaim {
                    asset_id: a2,
                    token_index: 2,
                    media_sha256: [0xBB; 32],
                    timestamp_unix: 1_700_002_000,
                },
                [0x06; 32],
                &mk_memo(a2),
            )
            .is_err());
    }
}
