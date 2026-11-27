use anyhow::Result;
use std::sync::{Arc, Mutex};
use zyoza_gallery_demo::http::gallery_router;
use zyoza_gallery_demo::GalleryService;

#[tokio::main]
async fn main() -> Result<()> {
    // Warm up the single dedicated Ragu prover thread in the background immediately on boot.
    std::thread::spawn(zyoza_proofs::warmup_prover);

    let addr = std::env::var("ZYOZA_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let state = Arc::new(Mutex::new(GalleryService::default()));
    let app = gallery_router(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("Zyoza Gallery & Studio listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
