//! Core vertical-agnostic primitives and trait boundaries for Zyoza.

pub mod asset_id;
pub mod collection;
pub mod disclosure;
pub mod error;
pub mod traits;
pub mod types;

pub use asset_id::{AssetBase, AssetDesc, AssetId};
pub use collection::{CollectionSpec, MintClaim};
pub use disclosure::{DisclosureBundle, ObjectViewingKey};
pub use error::ZyozaError;
pub use traits::{AssetProfile, ProofEngine, SettlementAdapter};
pub use types::{
    ZyozaEnvelope, OrchardMemoSeal, OwnershipProofRequest, OwnershipVerifyRequest, ProfileId,
    ProfilePreview, ProofBytes, SettlementReceipt, MAX_OOB_URI_LEN, ORCHARD_MEMO_LEN,
    PROTOCOL_VERSION, SEAL_MAGIC,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    struct MockNftProfile;

    impl AssetProfile for MockNftProfile {
        fn profile_id(&self) -> ProfileId {
            *b"NFT1"
        }

        fn validate_transition(
            &self,
            _prev_state: Option<&[u8]>,
            next_state: &[u8],
            _witness: &[u8],
        ) -> Result<(), ZyozaError> {
            if next_state.is_empty() {
                return Err(ZyozaError::InvalidTransition(
                    "empty state rejected".to_string(),
                ));
            }
            Ok(())
        }

        fn public_preview(
            &self,
            _state: &[u8],
            viewing_key: Option<&ObjectViewingKey>,
        ) -> Result<ProfilePreview, ZyozaError> {
            let summary = if viewing_key.is_some() {
                "unlocked".to_string()
            } else {
                "shielded".to_string()
            };
            Ok(ProfilePreview {
                profile_id: self.profile_id(),
                title: "Mock Zyoza NFT".to_string(),
                summary,
                attributes_json: "{}".to_string(),
            })
        }
    }

    #[derive(Default)]
    struct MockSettlement {
        spent: Mutex<HashSet<[u8; 32]>>,
        live: Mutex<HashSet<[u8; 32]>>,
    }

    impl SettlementAdapter for MockSettlement {
        fn anchor_mint(
            &self,
            _asset_id: &AssetId,
            state_commitment: [u8; 32],
            memo: &[u8; ORCHARD_MEMO_LEN],
        ) -> Result<SettlementReceipt, ZyozaError> {
            let _ = OrchardMemoSeal::from_bytes(memo)?;
            self.live.lock().unwrap().insert(state_commitment);
            Ok(SettlementReceipt {
                backend: "mock".to_string(),
                tx_id: [0x11; 32],
                commitment: state_commitment,
                block_height: Some(1),
            })
        }

        fn anchor_transfer(
            &self,
            _asset_id: &AssetId,
            prev_commitment: [u8; 32],
            next_commitment: [u8; 32],
            memo: &[u8; ORCHARD_MEMO_LEN],
        ) -> Result<SettlementReceipt, ZyozaError> {
            let _ = OrchardMemoSeal::from_bytes(memo)?;
            let mut live = self.live.lock().unwrap();
            let mut spent = self.spent.lock().unwrap();
            if !live.remove(&prev_commitment) || !spent.insert(prev_commitment) {
                return Err(ZyozaError::Settlement(
                    "double-spend or unknown commitment".to_string(),
                ));
            }
            live.insert(next_commitment);
            Ok(SettlementReceipt {
                backend: "mock".to_string(),
                tx_id: [0x22; 32],
                commitment: next_commitment,
                block_height: Some(2),
            })
        }

        fn verify_seal(&self, receipt: &SettlementReceipt) -> Result<bool, ZyozaError> {
            Ok(self.live.lock().unwrap().contains(&receipt.commitment))
        }
    }

    struct MockProofEngine;

    impl ProofEngine for MockProofEngine {
        fn prove_ownership(&self, req: &OwnershipProofRequest) -> Result<ProofBytes, ZyozaError> {
            let mut proof = Vec::with_capacity(64);
            proof.extend_from_slice(&req.collection_root);
            proof.extend_from_slice(&req.challenge);
            Ok(proof)
        }

        fn verify_ownership(
            &self,
            req: &OwnershipVerifyRequest,
            proof: &[u8],
        ) -> Result<bool, ZyozaError> {
            Ok(proof.len() == 64
                && proof[..32] == req.collection_root
                && proof[32..] == req.challenge)
        }

        fn prove_transition(
            &self,
            _prev_proof: Option<&[u8]>,
            step_witness: &[u8],
        ) -> Result<ProofBytes, ZyozaError> {
            Ok(step_witness.to_vec())
        }

        fn verify_transition(
            &self,
            proof: &[u8],
            public_inputs: &[u8],
        ) -> Result<bool, ZyozaError> {
            Ok(proof == public_inputs)
        }
    }

    #[test]
    fn canonical_asset_id_and_seal_roundtrip() {
        let issuer_vk = [0xAA; 32];
        let asset_desc = b"zyoza:nft:genesis:0001";
        let asset_id = AssetId::derive(&issuer_vk, asset_desc);

        assert_eq!(
            asset_id.to_hex(),
            "4dc1131d5acc7767bdb447240316d5a8f7294b8f80ce90416b7e8fecc1870aa6"
        );

        let base1 = asset_id.to_asset_base();
        let base2 = AssetBase::from_asset_id(&asset_id);
        assert_eq!(base1, base2);

        let seal = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id,
            state_root: [0x11; 32],
            nonce: [0x22; 32],
            oob_pointer_hash: [0x33; 32],
            oob_uri: "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string(),
        };

        let bytes = seal.to_bytes().expect("seal serializes to 512 bytes");
        assert_eq!(bytes.len(), ORCHARD_MEMO_LEN);
        assert_eq!(&bytes[0..4], b"ZYOZ");

        let parsed = OrchardMemoSeal::from_bytes(&bytes).expect("seal parses cleanly");
        assert_eq!(parsed, seal);
    }

    #[test]
    fn envelope_commitment_and_ovk_disclosure() {
        let asset_id = AssetId::derive(&[0x02; 32], &AssetDesc {
            namespace: "zyoza".to_string(),
            collection: "genesis".to_string(),
            item_id: "42".to_string(),
        }.to_canonical_bytes());

        let env = ZyozaEnvelope {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id,
            state_root: [0x33; 32],
            prev_commitment: None,
            nonce: [0x44; 32],
        };
        let c1 = env.state_commitment();
        assert_eq!(c1, env.state_commitment());

        let ovk = ObjectViewingKey::derive(asset_id, &[0x99; 32]);
        let wrong_ovk = ObjectViewingKey::derive(asset_id, &[0x88; 32]);
        let secret_meta = br#"{"title":"Genesis Zyoza #42"}"#;

        let bundle = DisclosureBundle::seal(&ovk, [0x12; 12], secret_meta).unwrap();
        assert_eq!(bundle.open(&ovk).unwrap(), secret_meta);
        assert!(bundle.open(&wrong_ovk).is_err());
    }

    #[test]
    fn mock_traits_end_to_end() {
        let profile = MockNftProfile;
        let settlement = MockSettlement::default();
        let prover = MockProofEngine;

        let asset_id = AssetId::derive(&[0x01; 32], b"collection:1:item:1");
        profile
            .validate_transition(None, b"mint-state", b"witness")
            .unwrap();

        let seal = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: profile.profile_id(),
            asset_id,
            state_root: [0x44; 32],
            nonce: [0x55; 32],
            oob_pointer_hash: [0x66; 32],
            oob_uri: "https://example.invalid/zyoza/1.json".to_string(),
        };
        let memo = seal.to_bytes().unwrap();

        let mint_rcpt = settlement.anchor_mint(&asset_id, [0x44; 32], &memo).unwrap();
        assert!(settlement.verify_seal(&mint_rcpt).unwrap());

        let xfer_rcpt = settlement
            .anchor_transfer(&asset_id, [0x44; 32], [0x77; 32], &memo)
            .unwrap();
        assert!(!settlement.verify_seal(&mint_rcpt).unwrap());
        assert!(settlement.verify_seal(&xfer_rcpt).unwrap());

        assert!(settlement
            .anchor_transfer(&asset_id, [0x44; 32], [0x88; 32], &memo)
            .is_err());

        let proof = prover
            .prove_ownership(&OwnershipProofRequest {
                asset_id,
                collection_root: [0x99; 32],
                secret_witness: vec![1, 2, 3],
                challenge: [0xAB; 32],
            })
            .unwrap();
        assert!(prover
            .verify_ownership(
                &OwnershipVerifyRequest {
                    collection_root: [0x99; 32],
                    challenge: [0xAB; 32],
                },
                &proof
            )
            .unwrap());
    }
}
