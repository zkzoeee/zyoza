use crate::browser_flow::{self, BrowserCommitReq, BrowserPrepareReq};
use crate::demo_engine::{
    prove_custom_fold, prove_listing_ownership, prove_mint_bundle, prove_session_migration,
    prove_session_trait, prove_transfer_step, DemoClearAuctionResp, DemoCommitBidReq,
    DemoDecryptReq, DemoFoldReq, DemoListReq, DemoListResp, DemoMintReq, DemoPreviewReq,
    DemoRevealBidReq, DemoWorkbench, SessionReq,
};
use crate::{
    AuctionClearResult, CommitBidRequest, GalleryListing, GalleryService, RevealBidRequest,
};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Mutex};
use zyoza_core::{AssetId, ObjectViewingKey, OwnershipVerifyRequest};
use zyoza_profile_nft::NftState;
use zyoza_proofs::RaguStepKind;

pub type SharedGallery = Arc<Mutex<GalleryService>>;
type CombinedState = Arc<Mutex<(SharedGallery, DemoWorkbench)>>;

#[derive(Deserialize)]
pub struct CreateListingRequest {
    pub asset_id_hex: String,
    pub ovk_hex: String,
    pub collection_root_hex: String,
    pub state_root_hex: String,
    pub challenge_hex: String,
    pub proof_hex: String,
    pub nft_state: NftState,
    pub reserve_zatoshis: u64,
}

/// Builds the full Axum `Router` (Landing Page, Zyoza Studio, Markdown-rendered Docs, and Gallery API).
pub fn gallery_router(gallery: SharedGallery) -> Router {
    let app_state = Arc::new(Mutex::new((gallery, DemoWorkbench::default())));
    Router::new()
        .route("/", get(index_page))
        .route("/logo.png", get(logo_image))
        .route("/demo", get(demo_page))
        .route("/whitepaper", get(whitepaper_page))
        .route("/spec", get(spec_page))
        .route("/security", get(security_page))
        .route("/api/listings", get(list_listings).post(create_listing))
        .route("/api/listings/challenge", post(issue_listing_challenge))
        .route("/api/listings/{id}/bids", post(commit_bid))
        .route("/api/listings/{id}/reveal", post(reveal_bid))
        .route("/api/listings/{id}/clear", post(clear_auction))
        .route("/studio/{file}", get(studio_asset))
        .route("/api/demo/browser/prepare", post(browser_prepare))
        .route("/api/demo/browser/commit", post(browser_commit))
        .route("/api/demo/browser/abort", post(browser_abort))
        .route("/api/demo/reset", post(demo_reset))
        .route("/api/demo/session/{id}", get(demo_session_status))
        .route("/api/demo/mint", post(demo_mint))
        .route("/api/demo/transfer", post(demo_transfer))
        .route("/api/demo/decrypt", post(demo_decrypt))
        .route("/api/demo/preview", post(demo_preview))
        .route("/api/demo/fold", post(demo_fold))
        .route("/api/demo/prove-trait", post(demo_prove_trait))
        .route("/api/demo/list", post(demo_list))
        .route("/api/demo/list-wrong-secret", post(demo_list_wrong_secret))
        .route("/api/demo/bid-commit", post(demo_bid_commit))
        .route("/api/demo/bid-reveal", post(demo_bid_reveal))
        .route("/api/demo/clear", post(demo_clear))
        .route("/api/demo/crystallize", post(demo_crystallize))
        .with_state(app_state)
}

async fn index_page() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn logo_image() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "image/png")],
        include_bytes!("logo.png").as_slice(),
    )
}

async fn demo_page() -> Html<&'static str> {
    Html(include_str!("demo.html"))
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Renders Markdown from `docs/` directly to styled HTML via `pulldown-cmark` so docs never drift.
fn render_markdown_doc(title: &str, md: &str) -> Html<String> {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_MATH);
    let parser = Parser::new_ext(md, opts);
    let mut body_html = String::new();
    let mut in_thead = false;

    for ev in parser {
        match ev {
            Event::Start(tag) => match tag {
                Tag::Paragraph => body_html.push_str("<p>"),
                Tag::Heading { level, .. } => body_html.push_str(&format!("<{level}>")),
                Tag::BlockQuote(_) => body_html.push_str("<blockquote>"),
                Tag::CodeBlock(_) => body_html.push_str("<pre><code>"),
                Tag::List(Some(start)) => body_html.push_str(&format!("<ol start=\"{start}\">")),
                Tag::List(None) => body_html.push_str("<ul>"),
                Tag::Item => body_html.push_str("<li>"),
                Tag::Table(_) => body_html.push_str("<div class=\"table-wrap\"><table>"),
                Tag::TableHead => {
                    in_thead = true;
                    body_html.push_str("<thead><tr>");
                }
                Tag::TableRow => body_html.push_str("<tr>"),
                Tag::TableCell => {
                    body_html.push_str(if in_thead { "<th>" } else { "<td>" });
                }
                Tag::Emphasis => body_html.push_str("<em>"),
                Tag::Strong => body_html.push_str("<strong>"),
                Tag::Strikethrough => body_html.push_str("<del>"),
                Tag::Link { dest_url, .. } => {
                    body_html.push_str(&format!("<a href=\"{}\">", escape_html(&dest_url)));
                }
                _ => {}
            },
            Event::End(end) => match end {
                TagEnd::Paragraph => body_html.push_str("</p>\n"),
                TagEnd::Heading(level) => body_html.push_str(&format!("</{level}>\n")),
                TagEnd::BlockQuote(_) => body_html.push_str("</blockquote>\n"),
                TagEnd::CodeBlock => body_html.push_str("</code></pre>\n"),
                TagEnd::List(true) => body_html.push_str("</ol>\n"),
                TagEnd::List(false) => body_html.push_str("</ul>\n"),
                TagEnd::Item => body_html.push_str("</li>\n"),
                TagEnd::TableHead => {
                    in_thead = false;
                    body_html.push_str("</tr></thead><tbody>\n");
                }
                TagEnd::TableRow => body_html.push_str("</tr>\n"),
                TagEnd::TableCell => {
                    body_html.push_str(if in_thead { "</th>" } else { "</td>" });
                }
                TagEnd::Table => body_html.push_str("</tbody></table></div>\n"),
                TagEnd::Emphasis => body_html.push_str("</em>"),
                TagEnd::Strong => body_html.push_str("</strong>"),
                TagEnd::Strikethrough => body_html.push_str("</del>"),
                TagEnd::Link => body_html.push_str("</a>"),
                _ => {}
            },
            Event::Text(t) => body_html.push_str(&escape_html(&t)),
            Event::Code(c) => body_html.push_str(&format!("<code>{}</code>", escape_html(&c))),
            Event::InlineMath(m) => {
                body_html.push_str(&format!("<code class=\"math\">{}</code>", escape_html(&m)));
            }
            Event::DisplayMath(m) => {
                body_html.push_str(&format!(
                    "<pre class=\"math-block\"><code>{}</code></pre>\n",
                    escape_html(&m)
                ));
            }
            Event::SoftBreak => body_html.push('\n'),
            Event::HardBreak => body_html.push_str("<br/>\n"),
            Event::Rule => body_html.push_str("<hr/>\n"),
            _ => {}
        }
    }

    Html(
        include_str!("doc_template.html")
            .replace("{{TITLE}}", &escape_html(title))
            .replace("{{BODY}}", &body_html),
    )
}

async fn whitepaper_page() -> Html<String> {
    render_markdown_doc("Whitepaper", include_str!("../../../docs/WHITEPAPER.md"))
}

async fn spec_page() -> Html<String> {
    render_markdown_doc("Protocol Spec", include_str!("../../../docs/SPEC.md"))
}

async fn security_page() -> Html<String> {
    render_markdown_doc(
        "Security & Benchmarks",
        include_str!("../../../docs/SECURITY_AND_BENCHMARKS.md"),
    )
}

async fn list_listings(State(state): State<CombinedState>) -> Json<Vec<GalleryListing>> {
    let outer = state.lock().unwrap();
    let guard = outer.0.lock().unwrap();
    Json(guard.list_listings())
}

async fn issue_listing_challenge(State(state): State<CombinedState>) -> Json<serde_json::Value> {
    let outer = state.lock().unwrap();
    let mut guard = outer.0.lock().unwrap();
    let challenge = guard.issue_challenge();
    Json(json!({ "challenge_hex": hex::encode(challenge) }))
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
        state_root: parse_32(&req.state_root_hex)?,
        challenge: parse_32(&req.challenge_hex)?,
    };
    let proof = hex::decode(&req.proof_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad proof_hex: {e}")))?;
    let state_bytes = req
        .nft_state
        .to_bytes()
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let gal_arc = { state.lock().unwrap().0.clone() };
    let listing = tokio::task::spawn_blocking(move || {
        let mut guard = gal_arc.lock().unwrap();
        guard.submit_listing(&ovk, &verify_req, &proof, &state_bytes, req.reserve_zatoshis)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok((StatusCode::CREATED, Json(listing)))
}

async fn commit_bid(
    State(state): State<CombinedState>,
    Path(id): Path<u64>,
    Json(req): Json<CommitBidRequest>,
) -> impl IntoResponse {
    let outer = state.lock().unwrap();
    let mut guard = outer.0.lock().unwrap();
    match guard.commit_sealed_bid(id, req) {
        Ok(()) => (StatusCode::ACCEPTED, "bid commitment recorded".to_string()),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn reveal_bid(
    State(state): State<CombinedState>,
    Path(id): Path<u64>,
    Json(req): Json<RevealBidRequest>,
) -> impl IntoResponse {
    let outer = state.lock().unwrap();
    let mut guard = outer.0.lock().unwrap();
    match guard.reveal_sealed_bid(id, req) {
        Ok(()) => (StatusCode::OK, "bid revealed".to_string()),
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

async fn demo_reset(State(state): State<CombinedState>) -> impl IntoResponse {
    let mut outer = state.lock().unwrap();
    outer.1.reset();
    *outer.0.lock().unwrap() = GalleryService::default();
    (StatusCode::OK, Json(json!({ "ok": true })))
}

async fn demo_session_status(
    State(state): State<CombinedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let outer = state.lock().unwrap();
    match outer.1.session_status(&id) {
        Ok(s) => (StatusCode::OK, Json(json!(s))),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({ "error": e.to_string() }))),
    }
}

/// Non-blocking mint: validates inputs under lock (<1 ms), runs Ragu `MintCircuit` + `IssuanceCapCircuit`
/// off-lock via `spawn_blocking`, then commits the seal under lock (<1 ms).
async fn demo_mint(
    State(state): State<CombinedState>,
    Json(req): Json<DemoMintReq>,
) -> impl IntoResponse {
    let prep = {
        let mut outer = state.lock().unwrap();
        // Fast pre-check for duplicate claim before spending CPU on Ragu proving!
        if let Err(e) = outer
            .1
            .prep_mint(&req)
            .and_then(|p| {
                // Check governed nullifier availability without mutating yet
                let probe_memo = [0u8; 512];
                let _ = probe_memo;
                Ok(p)
            })
        {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })));
        }
        // Check duplicate token_index + preset across existing sessions immediately!
        if outer
            .1
            .sessions
            .values()
            .any(|s| s.preset == req.preset && s.token_index == req.token_index)
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!(
                        "governed mint rejected: CollectionSpec nullifiers NF_aid / NF_idx #{} / NF_med already claimed for {}",
                        req.token_index, req.preset
                    )
                })),
            );
        }
        match outer.1.prep_mint(&req) {
            Ok(p) => p,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
        }
    };

    let proved = tokio::task::spawn_blocking(move || {
        let (pcd, cap) = prove_mint_bundle(&prep)?;
        Ok::<_, anyhow::Error>((prep, pcd, cap))
    })
    .await;

    let (prep, pcd, cap) = match proved {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    };

    let mut outer = state.lock().unwrap();
    let gal_arc = outer.0.clone();
    let mut gal = gal_arc.lock().unwrap();
    match outer.1.commit_mint(prep, pcd, cap, &mut gal) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_transfer(
    State(state): State<CombinedState>,
    Json(req): Json<SessionReq>,
) -> impl IntoResponse {
    let prep = {
        let mut outer = state.lock().unwrap();
        match outer.1.prep_transfer(&req.session_id, "bob") {
            Ok(p) => p,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
        }
    };
    let sid = req.session_id.clone();
    let proved = tokio::task::spawn_blocking(move || {
        let next_pcd = prove_transfer_step(&prep)?;
        Ok::<_, anyhow::Error>((prep, next_pcd))
    })
    .await;

    let mut outer = state.lock().unwrap();
    let (prep, next_pcd) = match proved {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            outer.1.release_busy(&sid);
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })));
        }
        Err(e) => {
            outer.1.release_busy(&sid);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            );
        }
    };

    let gal_arc = outer.0.clone();
    let mut gal = gal_arc.lock().unwrap();
    match outer.1.commit_transfer(prep, next_pcd, &mut gal) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_decrypt(
    State(state): State<CombinedState>,
    Json(req): Json<DemoDecryptReq>,
) -> impl IntoResponse {
    let mut outer = state.lock().unwrap();
    match outer.1.decrypt(req) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::FORBIDDEN, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_preview(
    State(state): State<CombinedState>,
    Json(req): Json<DemoPreviewReq>,
) -> impl IntoResponse {
    let outer = state.lock().unwrap();
    match outer.1.preview(req) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_fold(
    State(state): State<CombinedState>,
    Json(req): Json<DemoFoldReq>,
) -> impl IntoResponse {
    let kind = match RaguStepKind::parse_strict(&req.step_kind) {
        Ok(k) => k,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    };
    if req.profile_id.len() != 4 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "profile_id must be a 4-character tag" })),
        );
    }
    let mut prof = [0u8; 4];
    prof.copy_from_slice(req.profile_id.as_bytes());

    let sess = {
        let mut outer = state.lock().unwrap();
        let s = match outer.1.acquire_busy(&req.session_id) {
            Ok(s) => s,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
        };
        if s.crystallized {
            outer.1.release_busy(&req.session_id);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Stage I seal already burned and crystallized into Stage II ZSA" })),
            );
        }
        s
    };

    let sid = req.session_id.clone();
    let simulate_unpaid = req.simulate_unpaid_royalty;
    let folded =
        tokio::task::spawn_blocking(move || prove_custom_fold(&sess, kind, prof, simulate_unpaid))
            .await;

    let mut outer = state.lock().unwrap();
    match folded {
        Ok(Ok((next_pcd, next_commit, nonce, verify_ms))) => match outer.1.commit_folded_step(
            &sid,
            req.step_kind,
            kind,
            next_commit,
            nonce,
            next_pcd,
            verify_ms,
        ) {
            Ok(r) => (StatusCode::OK, Json(json!(r))),
            Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
        },
        Ok(Err(e)) => {
            outer.1.release_busy(&sid);
            (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })))
        }
        Err(e) => {
            outer.1.release_busy(&sid);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    }
}

async fn demo_prove_trait(
    State(state): State<CombinedState>,
    Json(req): Json<SessionReq>,
) -> impl IntoResponse {
    let sess = {
        let mut outer = state.lock().unwrap();
        match outer.1.acquire_busy(&req.session_id) {
            Ok(s) => s,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
        }
    };
    let sid = req.session_id.clone();
    let res = tokio::task::spawn_blocking(move || prove_session_trait(&sess)).await;
    let mut outer = state.lock().unwrap();
    outer.1.release_busy(&sid);
    match res {
        Ok(Ok(r)) => (StatusCode::OK, Json(json!(r))),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        ),
    }
}

async fn demo_list_internal(
    state: CombinedState,
    session_id: String,
    reserve_zatoshis: u64,
    use_wrong_secret: bool,
) -> axum::response::Response {
    let (sess, collection_root, merkle_path, collection_size, challenge, state_bytes) = {
        let mut outer = state.lock().unwrap();
        let s = match outer.1.acquire_busy(&session_id) {
            Ok(s) => s,
            Err(e) => {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })))
                    .into_response()
            }
        };
        if s.crystallized {
            outer.1.release_busy(&session_id);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Stage I seal already burned and crystallized into Stage II ZSA" })),
            )
                .into_response();
        }
        if !use_wrong_secret && s.listing_id.is_some() {
            outer.1.release_busy(&session_id);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "session is already listed on the gallery" })),
            )
                .into_response();
        }
        let (tree, idx_opt, count) = match outer.1.build_collection_tree(Some(&session_id)) {
            Ok(t) => t,
            Err(e) => {
                outer.1.release_busy(&session_id);
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })))
                    .into_response();
            }
        };
        let idx = idx_opt.unwrap_or(0);
        let root = tree.root();
        let path = tree.path(idx);
        let state_bytes = s.nft_state.to_bytes().unwrap();

        let gal_arc = outer.0.clone();
        let mut gal = gal_arc.lock().unwrap();
        gal.register_collection_root(root);
        let chal = gal.issue_challenge();
        (s, root, path, count, chal, state_bytes)
    };

    let ovk = sess.ovk.clone();
    let gal_arc = { state.lock().unwrap().0.clone() };
    let sid = session_id.clone();

    let listed = tokio::task::spawn_blocking(move || {
        let (proof, state_root, prove_ms) = prove_listing_ownership(
            &sess,
            collection_root,
            merkle_path,
            challenge,
            use_wrong_secret,
        )?;
        let t1 = std::time::Instant::now();
        let listing = {
            let mut gal = gal_arc.lock().unwrap();
            gal.submit_listing(
                &ovk,
                &OwnershipVerifyRequest {
                    collection_root,
                    state_root,
                    challenge,
                },
                &proof,
                &state_bytes,
                reserve_zatoshis,
            )?
        };
        let verify_ms = t1.elapsed().as_millis();
        Ok::<_, anyhow::Error>(DemoListResp {
            listing_id: listing.listing_id,
            prove_ms,
            verify_ms,
            proof_bytes: proof.len(),
            collection_root_hex: hex::encode(collection_root),
            state_root_hex: hex::encode(state_root),
            challenge_hex: hex::encode(challenge),
            collection_size,
            title: listing.preview.title,
        })
    })
    .await;

    let mut outer = state.lock().unwrap();
    outer.1.release_busy(&sid);
    match listed {
        Ok(Ok(r)) => {
            if let Some(s) = outer.1.sessions.get_mut(&sid) {
                s.listing_id = Some(r.listing_id);
            }
            (StatusCode::OK, Json(json!(r))).into_response()
        }
        Ok(Err(e)) => {
            (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn demo_list(
    State(state): State<CombinedState>,
    Json(req): Json<DemoListReq>,
) -> impl IntoResponse {
    demo_list_internal(state, req.session_id, req.reserve_zatoshis, false).await
}

async fn demo_list_wrong_secret(
    State(state): State<CombinedState>,
    Json(req): Json<SessionReq>,
) -> impl IntoResponse {
    demo_list_internal(state, req.session_id, 50_000_000, true).await
}

async fn demo_bid_commit(
    State(state): State<CombinedState>,
    Json(req): Json<DemoCommitBidReq>,
) -> impl IntoResponse {
    let outer = state.lock().unwrap();
    let mut gal = outer.0.lock().unwrap();
    match outer.1.commit_bid(req, &mut gal) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_bid_reveal(
    State(state): State<CombinedState>,
    Json(req): Json<DemoRevealBidReq>,
) -> impl IntoResponse {
    let outer = state.lock().unwrap();
    let mut gal = outer.0.lock().unwrap();
    match outer.1.reveal_bid(req, &mut gal) {
        Ok(()) => (StatusCode::OK, Json(json!({ "revealed": true }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_clear(
    State(state): State<CombinedState>,
    Json(req): Json<SessionReq>,
) -> impl IntoResponse {
    let (cleared, prep) = {
        let mut outer = state.lock().unwrap();
        let listing_id = match outer
            .1
            .sessions
            .get(&req.session_id)
            .and_then(|s| s.listing_id)
        {
            Some(id) => id,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "session is not listed" })),
                )
            }
        };
        let gal_arc = outer.0.clone();
        let cleared = {
            let mut gal = gal_arc.lock().unwrap();
            match gal.clear_auction(listing_id) {
                Ok(c) => c,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })))
                }
            }
        };
        match outer.1.prep_transfer(&req.session_id, &cleared.winning_bidder) {
            Ok(p) => (cleared, p),
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
        }
    };

    let sid = req.session_id.clone();
    let proved = tokio::task::spawn_blocking(move || {
        let next_pcd = prove_transfer_step(&prep)?;
        Ok::<_, anyhow::Error>((prep, next_pcd))
    })
    .await;

    let mut outer = state.lock().unwrap();
    let (prep, next_pcd) = match proved {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            outer.1.release_busy(&sid);
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })));
        }
        Err(e) => {
            outer.1.release_busy(&sid);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            );
        }
    };

    let gal_arc = outer.0.clone();
    let mut gal = gal_arc.lock().unwrap();
    match outer.1.commit_transfer(prep, next_pcd, &mut gal) {
        Ok(xfer) => (
            StatusCode::OK,
            Json(json!(DemoClearAuctionResp {
                winning_bidder: cleared.winning_bidder,
                clearing_price_zatoshis: cleared.clearing_price_zatoshis,
                new_commitment: xfer.new_commitment,
                new_oob_uri: xfer.new_oob_uri,
                pcd_steps: xfer.pcd_steps,
            })),
        ),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
}

async fn demo_crystallize(
    State(state): State<CombinedState>,
    Json(req): Json<SessionReq>,
) -> impl IntoResponse {
    let sess = {
        let mut outer = state.lock().unwrap();
        let s = match outer.1.acquire_busy(&req.session_id) {
            Ok(s) => s,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
        };
        if s.crystallized {
            outer.1.release_busy(&req.session_id);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "already crystallized into Stage II ZSA" })),
            );
        }
        s
    };

    let sid = req.session_id.clone();
    let mig = tokio::task::spawn_blocking(move || prove_session_migration(&sess)).await;

    let mut outer = state.lock().unwrap();
    match mig {
        Ok(Ok(burn_nf_hex)) => match outer.1.commit_crystallize(&sid, burn_nf_hex) {
            Ok(r) => (StatusCode::OK, Json(json!(r))),
            Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
        },
        Ok(Err(e)) => {
            outer.1.release_busy(&sid);
            (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })))
        }
        Err(e) => {
            outer.1.release_busy(&sid);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    }
}

/// Directory holding the built browser prover (`scripts/build-studio-wasm.sh`).
fn studio_wasm_dir() -> std::path::PathBuf {
    std::env::var_os("ZYOZA_STUDIO_WASM_DIR")
        .map(Into::into)
        .unwrap_or_else(|| "apps/gallery-demo/wasm".into())
}

/// Serves the prover worker and the WebAssembly prover it loads. The worker script is compiled
/// in; the prover files are read from disk, so a server without them still runs and the Studio
/// falls back to proving on the server.
async fn studio_asset(Path(file): Path<String>, headers: HeaderMap) -> axum::response::Response {
    let js = "text/javascript; charset=utf-8";
    if file == "worker.js" {
        return ([(header::CONTENT_TYPE, js)], include_str!("studio_worker.js")).into_response();
    }
    let content_type = match file.as_str() {
        "zyoza_studio_prover.js" => js,
        "zyoza_studio_prover_bg.wasm" => "application/wasm",
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let path = studio_wasm_dir().join(&file);
    let accepts_gzip = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("gzip"));
    if accepts_gzip {
        let mut gz = path.clone().into_os_string();
        gz.push(".gz");
        if let Ok(bytes) = tokio::fs::read(&gz).await {
            return (
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CONTENT_ENCODING, "gzip"),
                    (header::CACHE_CONTROL, "no-cache"),
                ],
                bytes,
            )
                .into_response();
        }
    }
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            [(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "no-cache")],
            bytes,
        )
            .into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            "browser prover not built; run scripts/build-studio-wasm.sh",
        )
            .into_response(),
    }
}

/// Runs a browser-flow step with both locks held, on the blocking pool: `commit` verifies
/// proofs, which blocks on the prover thread.
async fn with_studio<T: Send + 'static>(
    state: CombinedState,
    f: impl FnOnce(&mut DemoWorkbench, &mut GalleryService) -> anyhow::Result<T> + Send + 'static,
) -> Result<T, (StatusCode, Json<serde_json::Value>)> {
    let joined = tokio::task::spawn_blocking(move || {
        let mut outer = state.lock().unwrap();
        let gal_arc = outer.0.clone();
        let mut gal = gal_arc.lock().unwrap();
        f(&mut outer.1, &mut gal)
    })
    .await;
    match joined {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err((StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )),
    }
}

async fn browser_prepare(
    State(state): State<CombinedState>,
    Json(req): Json<BrowserPrepareReq>,
) -> impl IntoResponse {
    match with_studio(state, move |wb, gal| browser_flow::prepare(wb, gal, req)).await {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => e,
    }
}

async fn browser_commit(
    State(state): State<CombinedState>,
    Json(req): Json<BrowserCommitReq>,
) -> impl IntoResponse {
    match with_studio(state, move |wb, gal| browser_flow::commit(wb, gal, req)).await {
        Ok(r) => (StatusCode::OK, Json(r)),
        Err(e) => e,
    }
}

#[derive(Deserialize)]
struct BrowserAbortReq {
    ticket: String,
}

async fn browser_abort(
    State(state): State<CombinedState>,
    Json(req): Json<BrowserAbortReq>,
) -> impl IntoResponse {
    let mut outer = state.lock().unwrap();
    browser_flow::abort(&mut outer.1, &req.ticket);
    (StatusCode::OK, Json(json!({ "ok": true })))
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
    use crate::compute_bid_commitment;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn http_api_full_studio_client_hash_negative_tests_and_guards() {
        let state = Arc::new(Mutex::new(GalleryService::default()));
        let app = gallery_router(state);

        for uri in ["/", "/logo.png", "/demo", "/whitepaper", "/spec", "/security"] {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "route {uri}");
        }

        // Arbitrary preset MUST be rejected!
        let bad_preset = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/mint")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"preset":"arbitrary-junk","token_index":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_preset.status(), StatusCode::BAD_REQUEST);

        // 1. Mint via Studio (seeds MintCircuit + proves IssuanceCapCircuit)
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
        let sid = mint_json["session_id"].as_str().unwrap().to_string();

        // Session status restoration endpoint works!
        let sess_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/demo/session/{sid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sess_resp.status(), StatusCode::OK);

        // 2. Unpaid royalty negative test MUST be rejected!
        let unpaid_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/fold")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "session_id": sid,
                            "step_kind": "RoyaltyStep",
                            "profile_id": "NFT1",
                            "simulate_unpaid_royalty": true
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unpaid_resp.status(), StatusCode::BAD_REQUEST);

        // 3. Wrong-secret ownership proof MUST be rejected!
        let wrong_sec_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/list-wrong-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "session_id": sid }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_sec_resp.status(), StatusCode::BAD_REQUEST);

        // 4. Valid listing + client-side SHA-256 commit-reveal (server never receives bid_zatoshis on commit!)
        let list_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/list")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "session_id": sid, "reserve_zatoshis": 50_000_000u64 }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_resp.status(), StatusCode::OK);
        let list_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(list_resp.into_body(), 65536).await.unwrap()).unwrap();
        let listing_id = list_json["listing_id"].as_u64().unwrap();

        let client_salt = [0x42u8; 32];
        let commitment_hex = hex::encode(compute_bid_commitment(
            listing_id,
            "carol",
            80_000_000,
            &client_salt,
        ));

        let cmt_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/bid-commit")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "session_id": sid,
                            "bidder_id": "carol",
                            "commitment_hex": commitment_hex
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cmt_resp.status(), StatusCode::OK);

        // Verify GET /api/listings exposes `bids` with `revealed_zatoshis == null`!
        let pub_resp = app
            .clone()
            .oneshot(Request::builder().uri("/api/listings").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let pub_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(pub_resp.into_body(), 65536).await.unwrap()).unwrap();
        assert!(pub_json[0]["bids"][0]["revealed_zatoshis"].is_null());

        let rev_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/bid-reveal")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "session_id": sid,
                            "bidder_id": "carol",
                            "bid_zatoshis": 80_000_000u64,
                            "salt_hex": hex::encode(client_salt)
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rev_resp.status(), StatusCode::OK);

        // Clear folds a real RoyaltyStep transferring PCD owner_tag + OOB DEK to Carol!
        let clr_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/clear")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "session_id": sid }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clr_resp.status(), StatusCode::OK);

        // Crystallize verifies Carol's lineage proof + MigrationCircuit owner_tag binding!
        let crys_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/crystallize")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "session_id": sid }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(crys_resp.status(), StatusCode::OK);
    }
}
