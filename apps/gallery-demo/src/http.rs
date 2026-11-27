use crate::demo_engine::{
    DemoCommitBidReq, DemoDecryptReq, DemoFoldReq, DemoListReq, DemoMintReq, DemoPreviewReq,
    DemoRevealBidReq, DemoWorkbench, SessionReq,
};
use crate::{
    AuctionClearResult, CommitBidRequest, GalleryListing, GalleryService, RevealBidRequest,
};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Mutex};
use zyoza_core::{AssetId, ObjectViewingKey, OwnershipVerifyRequest};
use zyoza_profile_nft::NftState;

pub type SharedGallery = Arc<Mutex<GalleryService>>;
type CombinedState = Arc<Mutex<(SharedGallery, DemoWorkbench)>>;

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
        .route("/api/listings/{id}/bids", post(commit_bid))
        .route("/api/listings/{id}/reveal", post(reveal_bid))
        .route("/api/listings/{id}/clear", post(clear_auction))
        .route("/api/demo/reset", post(demo_reset))
        .route("/api/demo/mint", post(demo_mint))
        .route("/api/demo/transfer", post(demo_transfer))
        .route("/api/demo/decrypt", post(demo_decrypt))
        .route("/api/demo/preview", post(demo_preview))
        .route("/api/demo/fold", post(demo_fold))
        .route("/api/demo/list", post(demo_list))
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

    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="icon" href="/logo.png" />
  <title>{title} — Zyoza</title>
  <style>
    :root {{
      --paper: #F7F4ED; --paper-alt: #EFEBE1; --card: #FAF8F3;
      --ink: #171614; --muted: #5C5852; --line: #DDD7C9; --accent: #C53D2F;
      --serif: "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, serif;
      --sans: -apple-system, BlinkMacSystemFont, "Inter", sans-serif;
      --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--paper); color: var(--ink); font-family: var(--sans); line-height: 1.72; }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    a:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
    header {{ border-bottom: 1px solid var(--line); background: var(--card); padding: 1rem 1.5rem; position: sticky; top: 0; }}
    .nav {{ max-width: 860px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.75rem; }}
    .brand {{ display: flex; align-items: center; gap: 0.6rem; font-family: var(--serif); font-size: 1.15rem; font-weight: 600; color: var(--ink); }}
    .brand img {{ width: 32px; height: 32px; border-radius: 6px; border: 1px solid var(--line); }}
    .links {{ display: flex; gap: 1.15rem; font-size: 0.88rem; flex-wrap: wrap; }}
    article {{ max-width: 860px; margin: 0 auto; padding: 2.75rem 1.5rem 4.5rem; }}
    h1, h2, h3 {{ font-family: var(--serif); font-weight: 600; line-height: 1.25; }}
    h1 {{ font-size: clamp(1.85rem, 3.5vw, 2.5rem); margin-bottom: 0.75rem; }}
    h2 {{ font-size: 1.4rem; margin-top: 2.4rem; padding-top: 1.4rem; border-top: 1px solid var(--line); }}
    h3 {{ font-size: 1.1rem; margin-top: 1.4rem; }}
    blockquote {{ margin: 1rem 0; padding: 0.75rem 1rem; background: var(--card); border-left: 3px solid var(--accent); color: var(--muted); }}
    hr {{ border: none; border-top: 1px solid var(--line); margin: 1.75rem 0; }}
    code {{ font-family: var(--mono); font-size: 0.84em; background: var(--paper-alt); padding: 0.1rem 0.32rem; border: 1px solid var(--line); }}
    pre {{ background: var(--card); border: 1px solid var(--line); padding: 1rem; overflow-x: auto; }}
    pre code {{ background: none; border: none; padding: 0; }}
    .math-block {{ background: #F2EEE4; border-left: 3px solid var(--ink); }}
    .table-wrap {{ width: 100%; overflow-x: auto; margin: 1rem 0 1.4rem; border: 1px solid var(--line); background: var(--card); }}
    table {{ width: 100%; min-width: 540px; border-collapse: collapse; font-size: 0.88rem; }}
    th, td {{ text-align: left; padding: 0.65rem 0.8rem; border-bottom: 1px solid var(--line); }}
    tr:last-child td {{ border-bottom: none; }}
    th {{ background: var(--paper-alt); font-family: var(--mono); font-size: 0.74rem; text-transform: uppercase; color: var(--muted); }}
  </style>
</head>"#,
        title = escape_html(title)
    ) + &format!(
        r#"
<body>
  <header>
    <div class="nav">
      <a href="/" class="brand"><img src="/logo.png" alt="Zyoza" /><span>Zyoza</span></a>
      <nav class="links">
        <a href="/">Overview</a>
        <a href="/whitepaper">Whitepaper</a>
        <a href="/spec">Protocol Spec</a>
        <a href="/security">Security &amp; Benchmarks</a>
        <a href="/demo"><strong>Zyoza Studio →</strong></a>
      </nav>
    </div>
  </header>
  <article>{body_html}</article>
</body>
</html>"#
    ))
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
    let mut outer = state.lock().unwrap();
    let gallery_arc = outer.0.clone();
    let mut gal = gallery_arc.lock().unwrap();
    match outer.1.list_on_gallery(req, &mut gal) {
        Ok(r) => (StatusCode::OK, Json(json!(r))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))),
    }
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
    let mut outer = state.lock().unwrap();
    let gallery_arc = outer.0.clone();
    let mut gal = gallery_arc.lock().unwrap();
    match outer.1.clear_and_settle(req, &mut gal) {
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
    use tower::ServiceExt;

    #[tokio::test]
    async fn http_api_full_studio_commit_reveal_and_guards() {
        let state = Arc::new(Mutex::new(GalleryService::default()));
        let app = gallery_router(state);

        // 1. Landing, Logo & Markdown-rendered Docs return 200 OK
        for uri in ["/", "/logo.png", "/demo", "/whitepaper", "/spec", "/security"] {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "route {uri}");
        }

        // 2. Mint via Studio
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

        // 3. Bogus Ragu step MUST be rejected!
        let bogus_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/fold")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "session_id": sid, "step_kind": "Bogus", "profile_id": "NFT1" })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bogus_resp.status(), StatusCode::BAD_REQUEST);

        // 4. Valid Ragu fold + server-side OVK preview + Gallery listing + Commit-Reveal auction!
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

        // Commit Carol's bid -> amount hidden until revealed -> clear transfers ownership to Carol!
        let cmt_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/bid-commit")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "session_id": sid, "bidder_id": "carol", "bid_zatoshis": 80_000_000u64 })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cmt_resp.status(), StatusCode::OK);
        let cmt_json: serde_json::Value =
            serde_json::from_slice(&to_bytes(cmt_resp.into_body(), 65536).await.unwrap()).unwrap();
        let salt_hex = cmt_json["salt_hex"].as_str().unwrap();

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
                            "salt_hex": salt_hex
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rev_resp.status(), StatusCode::OK);

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

        // Carol can now decrypt; Alice cannot!
        let dec_carol = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/decrypt")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "session_id": sid, "actor": "carol" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dec_carol.status(), StatusCode::OK);

        let dec_alice = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/decrypt")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "session_id": sid, "actor": "alice" }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dec_alice.status(), StatusCode::FORBIDDEN);

        // 5. Crystallize -> subsequent Stage I fold MUST be rejected!
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

        let post_crys_fold = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/demo/fold")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "session_id": sid, "step_kind": "RoyaltyStep", "profile_id": "NFT1" })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_crys_fold.status(), StatusCode::BAD_REQUEST);
    }
}
