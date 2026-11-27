use crate::demo_engine::{
    DemoDecryptReq, DemoFoldReq, DemoListReq, DemoMintReq, DemoWorkbench, SessionReq,
};
use crate::{AuctionClearResult, GalleryListing, GalleryService, SealedBid};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Mutex};
use zyoza_core::{AssetId, ObjectViewingKey, OwnershipVerifyRequest};
use zyoza_profile_nft::NftState;

#[derive(Default)]
pub struct AppState {
    pub gallery: GalleryService,
    pub demo: DemoWorkbench,
}

pub type SharedGallery = Arc<Mutex<GalleryService>>;
pub type SharedApp = Arc<Mutex<AppState>>;

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

/// Builds the full Axum `Router` (Japanese Landing Page, Interactive Demo Studio, Whitepaper, and Gallery API).
pub fn gallery_router(gallery: SharedGallery) -> Router {
    let app_state = Arc::new(Mutex::new((gallery, DemoWorkbench::default())));
    Router::new()
        .route("/", get(index_page))
        .route("/demo", get(demo_page))
        .route("/whitepaper", get(whitepaper_page))
        .route("/api/listings", get(list_listings).post(create_listing))
        .route("/api/listings/{id}/bids", post(submit_bid))
        .route("/api/listings/{id}/clear", post(clear_auction))
        .route("/api/demo/mint", post(demo_mint))
        .route("/api/demo/transfer", post(demo_transfer))
        .route("/api/demo/decrypt", post(demo_decrypt))
        .route("/api/demo/fold", post(demo_fold))
        .route("/api/demo/list", post(demo_list))
        .route("/api/demo/crystallize", post(demo_crystallize))
        .with_state(app_state)
}

type CombinedState = Arc<Mutex<(SharedGallery, DemoWorkbench)>>;

async fn index_page() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn demo_page() -> Html<&'static str> {
    Html(include_str!("demo.html"))
}

async fn whitepaper_page() -> Html<&'static str> {
    Html(include_str!("whitepaper.html"))
}

async fn list_listings(State(state): State<CombinedState>) -> Json<Vec<GalleryListing>> {
    let outer = state.lock().unwrap();
    let guard = outer.0.lock().unwrap();
    Json(guard.list_listings())
}

async fn create_listing(
    State(state): State<CombinedState>,
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

    let outer = state.lock().unwrap();
    let mut guard = outer.0.lock().unwrap();
    let listing = guard
        .submit_listing(&ovk, &verify_req, &proof, &state_bytes, req.reserve_zatoshis)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok((StatusCode::CREATED, Json(listing)))
}

async fn submit_bid(
    State(state): State<CombinedState>,
    Path(id): Path<u64>,
    Json(bid): Json<SealedBid>,
) -> impl IntoResponse {
    let outer = state.lock().unwrap();
    let mut guard = outer.0.lock().unwrap();
    match guard.submit_sealed_bid(id, bid) {
        Ok(()) => (StatusCode::ACCEPTED, "bid accepted".to_string()),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn clear_auction(
    State(state): State<CombinedState>,
    Path(id): Path<u64>,
) -> Result<Json<AuctionClearResult>, (StatusCode, String)> {
    let outer = state.lock().unwrap();
    let mut guard = outer.0.lock().unwrap();
    guard
        .clear_auction(id)
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

async fn demo_mint(
    State(state): State<CombinedState>,
    Json(req): Json<DemoMintReq>,
) -> impl IntoResponse {
    let mut outer = state.lock().unwrap();
    match outer.1.mint(req) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_transfer(
    State(state): State<CombinedState>,
    Json(req): Json<SessionReq>,
) -> impl IntoResponse {
    let mut outer = state.lock().unwrap();
    match outer.1.transfer(req) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_decrypt(
    State(state): State<CombinedState>,
    Json(req): Json<DemoDecryptReq>,
) -> impl IntoResponse {
    let outer = state.lock().unwrap();
    match outer.1.decrypt(req) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::FORBIDDEN, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_fold(
    State(state): State<CombinedState>,
    Json(req): Json<DemoFoldReq>,
) -> impl IntoResponse {
    let mut outer = state.lock().unwrap();
    match outer.1.fold(req) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_list(
    State(state): State<CombinedState>,
    Json(req): Json<DemoListReq>,
) -> impl IntoResponse {
    let outer = state.lock().unwrap();
    let mut gal = outer.0.lock().unwrap();
    match outer.1.list_on_gallery(req, &mut gal) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_crystallize(
    State(state): State<CombinedState>,
    Json(req): Json<SessionReq>,
) -> impl IntoResponse {
    let mut outer = state.lock().unwrap();
    match outer.1.crystallize(req) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
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
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::collections::BTreeMap;
    use tower::ServiceExt;
    use zyoza_core::{AssetDesc, OwnershipProofRequest, ProofEngine};
    use zyoza_profile_nft::{CollectionPolicy, MediaManifest, ProvenanceEvent};
    use zyoza_proofs::Halo2ProofEngine;

    #[tokio::test]
    async fn http_api_listing_bid_and_clear_roundtrip() {
        let state = Arc::new(Mutex::new(GalleryService::default()));
        let app = gallery_router(state);

        // Landing, Demo & Whitepaper routes return 200 OK
        for uri in ["/", "/demo", "/whitepaper"] {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Full interactive demo lifecycle via HTTP endpoints!
        let mint_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/mint")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"preset":"nounz-venetian","token_index":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mint_resp.status(), StatusCode::OK);
        let mint_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(mint_resp.into_body(), 65536).await.unwrap()).unwrap();
        let sid = mint_json["session_id"].as_str().unwrap();

        // Duplicate mint rejected
        let dup_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/mint")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"preset":"nounz-venetian","token_index":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dup_resp.status(), StatusCode::BAD_REQUEST);

        // Transfer Alice -> Bob, fold Ragu PCD, and Crystallize ZSA
        for (uri, payload) in [
            ("/api/demo/transfer", json!({ "session_id": sid })),
            (
                "/api/demo/fold",
                json!({ "session_id": sid, "step_kind": "TicketCheckInStep", "profile_id": "TKT1" }),
            ),
            ("/api/demo/crystallize", json!({ "session_id": sid })),
        ] {
            let r = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::OK);
        }

        // Direct Gallery listing + bid + clear
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
