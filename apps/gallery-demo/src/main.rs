use anyhow::Result;
use zyoza_gallery_demo::http::gallery_router;
use zyoza_gallery_demo::GalleryService;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> Result<()> {
    let addr = std::env::var("ZYOZA_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let state = Arc::new(Mutex::new(GalleryService::default()));
    let app = gallery_router(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("🥟 Zyoza Gallery Demo listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
