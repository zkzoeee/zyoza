use crate::{AuctionClearResult, GalleryListing, GalleryService, SealedBid};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use zyoza_core::{AssetId, ObjectViewingKey, OwnershipVerifyRequest};
use zyoza_profile_nft::NftState;
use serde::Deserialize;
use std::sync::{Arc, Mutex};

pub type SharedGallery = Arc<Mutex<GalleryService>>;

#[derive(Deserialize)]
pub struct CreateListingRequest {
    pub asset_id_hex: String,
    pub ovk_hex: String,
    pub collection_root_hex: String,
    pub challenge_hex: String,
    pub proof_hex: String,
    pub nft_state: NftState,
    pub reserve_zatoshis: u64,
}

/// Builds the Axum `Router` for the Zyoza Opt-In Viewing-Key Gallery.
pub fn gallery_router(state: SharedGallery) -> Router {
    Router::new()
        .route("/", get(index_page))
        .route("/api/listings", get(list_listings).post(create_listing))
        .route("/api/listings/{id}/bids", post(submit_bid))
        .route("/api/listings/{id}/clear", post(clear_auction))
        .with_state(state)
}

async fn index_page() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn list_listings(State(state): State<SharedGallery>) -> Json<Vec<GalleryListing>> {
    let guard = state.lock().unwrap();
    Json(guard.list_listings())
}

async fn create_listing(
    State(state): State<SharedGallery>,
    Json(req): Json<CreateListingRequest>,
) -> Result<(StatusCode, Json<GalleryListing>), (StatusCode, String)> {
    let asset_id = AssetId(parse_32(&req.asset_id_hex)?);
    let ovk = ObjectViewingKey {
        asset_id,
        key_bytes: parse_32(&req.ovk_hex)?,
    };
    let verify_req = OwnershipVerifyRequest {
        collection_root: parse_32(&req.collection_root_hex)?,
        challenge: parse_32(&req.challenge_hex)?,
    };
    let proof = hex::decode(&req.proof_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad proof_hex: {e}")))?;
    let state_bytes = req
        .nft_state
        .to_bytes()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let mut guard = state.lock().unwrap();
    let listing = guard
        .submit_listing(&ovk, &verify_req, &proof, &state_bytes, req.reserve_zatoshis)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok((StatusCode::CREATED, Json(listing)))
}

async fn submit_bid(
    State(state): State<SharedGallery>,
    Path(id): Path<u64>,
    Json(bid): Json<SealedBid>,
) -> impl IntoResponse {
    let mut guard = state.lock().unwrap();
    match guard.submit_sealed_bid(id, bid) {
        Ok(()) => (StatusCode::ACCEPTED, "bid accepted".to_string()),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn clear_auction(
    State(state): State<SharedGallery>,
    Path(id): Path<u64>,
) -> Result<Json<AuctionClearResult>, (StatusCode, String)> {
    let mut guard = state.lock().unwrap();
    guard
        .clear_auction(id)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

fn parse_32(s: &str) -> Result<[u8; 32], (StatusCode, String)> {
    let bytes = hex::decode(s).map_err(|e| (StatusCode::BAD_REQUEST, format!("bad hex: {e}")))?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("expected 32 bytes, got {}", bytes.len()),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use zyoza_core::{AssetDesc, OwnershipProofRequest, ProofEngine};
    use zyoza_profile_nft::{CollectionPolicy, MediaManifest, ProvenanceEvent};
    use zyoza_proofs::Halo2ProofEngine;
    use std::collections::BTreeMap;
    use tower::ServiceExt;

    #[tokio::test]
    async fn http_api_listing_bid_and_clear_roundtrip() {
        let state = Arc::new(Mutex::new(GalleryService::default()));
        let app = gallery_router(state);

        // 1. GET / returns HTML
        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 2. POST /api/listings with real Halo2 proof
        let asset_id = AssetId::derive(
            &[0x01; 32],
            &AssetDesc {
                namespace: "zyoza".into(),
                collection: "http".into(),
                item_id: "1".into(),
            }
            .to_canonical_bytes(),
        );
        let ovk = ObjectViewingKey::derive(asset_id, &[0xAA; 32]);
        let collection_root = [0x11; 32];
        let challenge = [0x22; 32];
        let proof = Halo2ProofEngine
            .prove_ownership(&OwnershipProofRequest {
                asset_id,
                collection_root,
                secret_witness: b"http-sk".to_vec(),
                challenge,
            })
            .unwrap();
        let nft_state = NftState {
            asset_id,
            title: "HTTP Zyoza #1".into(),
            description: "Axum test".into(),
            creator: "alice".into(),
            media: MediaManifest {
                mime: "image/png".into(),
                sha256_hex: "a".repeat(64),
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

        let body = serde_json::json!({
            "asset_id_hex": asset_id.to_hex(),
            "ovk_hex": hex::encode(ovk.key_bytes),
            "collection_root_hex": hex::encode(collection_root),
            "challenge_hex": hex::encode(challenge),
            "proof_hex": hex::encode(proof),
            "nft_state": nft_state,
            "reserve_zatoshis": 50_000_000u64,
        });

        let create_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/listings")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);

        // 3. Submit bid & clear
        let bid_body = serde_json::json!({
            "bidder_id": "bob",
            "shielded_zec_commitment": vec![7u8; 32],
            "bid_zatoshis": 75_000_000u64,
        });
        let bid_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/listings/1/bids")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&bid_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bid_resp.status(), StatusCode::ACCEPTED);

        let clear_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/listings/1/clear")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clear_resp.status(), StatusCode::OK);
    }
}
