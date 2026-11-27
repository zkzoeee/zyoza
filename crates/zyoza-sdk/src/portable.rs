//! Portable WASM / UniFFI-ready cross-profile bindings for Zyoza.
//!
//! All entrypoints take plain byte slices or UTF-8 strings and return JSON strings,
//! making them trivial to expose via `wasm-bindgen` or `uniffi` without duplicating
//! profile or proof logic.

use zyoza_core::{
    AssetProfile, ZyozaError, ObjectViewingKey, OrchardMemoSeal, OwnershipVerifyRequest,
    ProofEngine, ORCHARD_MEMO_LEN,
};
use zyoza_profile_cred::CredentialProfile;
use zyoza_profile_gaming::GameProfile;
use zyoza_profile_nft::NftProfile;
use zyoza_profile_rwa::RwaProfile;
use zyoza_profile_ticket::TicketProfile;
use zyoza_proofs::RaguPcdEngine;
use serde::Serialize;

#[derive(Serialize)]
struct MemoSealSummary {
    version: u16,
    profile_id: String,
    asset_id_hex: String,
    state_root_hex: String,
    oob_uri: String,
}

/// Resolves any supported 4-char profile tag (`NFT1`, `TKT1`, `CRD1`, `GAM1`, `RWA1`) to its `AssetProfile`.
pub fn resolve_profile(profile_tag: &str) -> Result<Box<dyn AssetProfile>, ZyozaError> {
    match profile_tag {
        "NFT1" => Ok(Box::new(NftProfile)),
        "TKT1" => Ok(Box::new(TicketProfile)),
        "CRD1" => Ok(Box::new(CredentialProfile)),
        "GAM1" => Ok(Box::new(GameProfile)),
        "RWA1" => Ok(Box::new(RwaProfile)),
        other => Err(ZyozaError::InvalidEncoding(format!(
            "unsupported profile_id: {other}"
        ))),
    }
}

/// Renders a `ProfilePreview` as JSON for any Zyoza profile (`NFT1`, `TKT1`, `CRD1`).
pub fn render_profile_preview_json(
    profile_tag: &str,
    state_bytes: &[u8],
    viewing_key: Option<&ObjectViewingKey>,
) -> Result<String, ZyozaError> {
    let profile = resolve_profile(profile_tag)?;
    let preview = profile.public_preview(state_bytes, viewing_key)?;
    serde_json::to_string(&preview)
        .map_err(|e| ZyozaError::InvalidEncoding(format!("preview json: {e}")))
}

/// Parses a 512-byte Orchard memo seal and returns a JSON summary.
pub fn parse_memo_seal_json(memo_bytes: &[u8; ORCHARD_MEMO_LEN]) -> Result<String, ZyozaError> {
    let seal = OrchardMemoSeal::from_bytes(memo_bytes)?;
    let summary = MemoSealSummary {
        version: seal.version,
        profile_id: String::from_utf8_lossy(&seal.profile_id).to_string(),
        asset_id_hex: seal.asset_id.to_hex(),
        state_root_hex: hex::encode(seal.state_root),
        oob_uri: seal.oob_uri,
    };
    serde_json::to_string(&summary)
        .map_err(|e| ZyozaError::InvalidEncoding(format!("seal json: {e}")))
}

/// Verifies a Ragu Pasta Poseidon-Merkle ownership proof from hex-encoded public inputs (WASM/FFI friendly).
pub fn verify_ownership_proof_hex(
    collection_root_hex: &str,
    challenge_hex: &str,
    proof_bytes: &[u8],
) -> Result<bool, ZyozaError> {
    let collection_root = parse_hex_32(collection_root_hex)?;
    let challenge = parse_hex_32(challenge_hex)?;
    RaguPcdEngine.verify_ownership(
        &OwnershipVerifyRequest {
            collection_root,
            challenge,
        },
        proof_bytes,
    )
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], ZyozaError> {
    let bytes = hex::decode(s).map_err(|e| ZyozaError::InvalidEncoding(format!("hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(ZyozaError::InvalidEncoding(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zyoza_core::{AssetId, OwnershipProofRequest};
    use zyoza_profile_cred::CredentialState;
    use zyoza_profile_nft::{CollectionPolicy, MediaManifest, NftState, ProvenanceEvent};
    use zyoza_profile_ticket::TicketState;
    use std::collections::BTreeMap;

    #[test]
    fn portable_sdk_dispatches_all_five_profiles_and_verifies_ragu() {
        let asset_id = AssetId::derive(&[0x01; 32], b"zyoza:multi:1");
        let ovk = ObjectViewingKey::derive(asset_id, &[0x42; 32]);

        let nft = NftState {
            asset_id,
            title: "Portable Zyoza".into(),
            description: "NFT".into(),
            creator: "alice".into(),
            media: MediaManifest {
                mime: "image/png".into(),
                sha256_hex: "c".repeat(64),
                encrypted_blob_uri: "ipfs://1".into(),
            },
            traits: BTreeMap::new(),
            policy: CollectionPolicy {
                royalty_bps: 0,
                lockup_until_unix: None,
            },
            provenance: vec![ProvenanceEvent {
                step: 0,
                kind: "mint".into(),
                commitment_hex: "00".repeat(32),
                timestamp_unix: 1,
            }],
        };
        let nft_json =
            render_profile_preview_json("NFT1", &nft.to_bytes().unwrap(), Some(&ovk)).unwrap();
        assert!(nft_json.contains("Portable Zyoza"));

        let tkt = TicketState {
            asset_id,
            event_id: "zcon-2026".into(),
            event_name: "Zcon 2026".into(),
            seat_tier: "GA".into(),
            transferable: true,
            checked_in: false,
        };
        let tkt_json =
            render_profile_preview_json("TKT1", &tkt.to_bytes().unwrap(), Some(&ovk)).unwrap();
        assert!(tkt_json.contains("Zcon 2026"));

        let crd = CredentialState {
            asset_id,
            issuer_id: "zcash-dao".into(),
            claim_type: "Member".into(),
            claim_summary: "Active".into(),
            claim_commitment: [0x11; 32],
            soulbound: true,
            revoked: false,
        };
        let crd_json =
            render_profile_preview_json("CRD1", &crd.to_bytes().unwrap(), Some(&ovk)).unwrap();
        assert!(crd_json.contains("Member"));

        let gam = zyoza_profile_gaming::GameItemState {
            asset_id,
            game_id: "shadow-dumpling".into(),
            item_name: "Stealth Wok".into(),
            rarity: "epic".into(),
            level: 3,
            xp: 120,
            equipped_slots: vec!["offhand".into()],
            soulbound: false,
            upgrade_count: 2,
        };
        let gam_json =
            render_profile_preview_json("GAM1", &gam.to_bytes().unwrap(), Some(&ovk)).unwrap();
        assert!(gam_json.contains("Stealth Wok"));

        let rwa = zyoza_profile_rwa::RwaDeedState {
            asset_id,
            jurisdiction: "CH-ZUG".into(),
            asset_class: "TreasuryBill".into(),
            deed_title: "Zug Note #7".into(),
            valuation_usd_cents: 500_000,
            required_cred_claim: "AccreditedInvestor".into(),
            issuer_notary: "notary-ch".into(),
            encumbered: false,
        };
        let rwa_json =
            render_profile_preview_json("RWA1", &rwa.to_bytes().unwrap(), Some(&ovk)).unwrap();
        assert!(rwa_json.contains("Zug Note #7"));

        let tree = zyoza_proofs::CollectionMerkleTree::from_holdings(&[(asset_id, b"secret")]);
        let root = tree.root();
        let chal = [0xBB; 32];
        let proof = RaguPcdEngine
            .prove_ownership(&OwnershipProofRequest {
                asset_id,
                collection_root: root,
                merkle_siblings: tree.path(0),
                secret_witness: b"secret".to_vec(),
                challenge: chal,
            })
            .unwrap();
        assert!(verify_ownership_proof_hex(&hex::encode(root), &hex::encode(chal), &proof).unwrap());
    }
}
