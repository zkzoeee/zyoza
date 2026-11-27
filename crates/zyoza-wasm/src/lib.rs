//! Browser/WASM bindings for Zyoza cross-profile previews, memo parsing, and Ragu verification.

use zyoza_core::{AssetId, ObjectViewingKey, ORCHARD_MEMO_LEN};
use zyoza_sdk::portable::{
    parse_memo_seal_json, render_profile_preview_json, verify_ownership_proof_hex,
};
use wasm_bindgen::prelude::*;

/// Renders a JSON `ProfilePreview` for any Zyoza profile (`NFT1`, `TKT1`, `CRD1`).
#[wasm_bindgen]
pub fn render_preview(
    profile_tag: &str,
    state_json: &[u8],
    asset_id_hex: Option<String>,
    ovk_hex: Option<String>,
) -> Result<String, JsValue> {
    let ovk = match (asset_id_hex, ovk_hex) {
        (Some(aid), Some(k)) => Some(ObjectViewingKey {
            asset_id: AssetId(parse_32(&aid)?),
            key_bytes: parse_32(&k)?,
        }),
        _ => None,
    };
    render_profile_preview_json(profile_tag, state_json, ovk.as_ref())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Parses a 512-byte Orchard memo seal and returns a JSON summary.
#[wasm_bindgen]
pub fn parse_memo_seal(memo_bytes: &[u8]) -> Result<String, JsValue> {
    if memo_bytes.len() != ORCHARD_MEMO_LEN {
        return Err(JsValue::from_str("memo must be exactly 512 bytes"));
    }
    let mut arr = [0u8; ORCHARD_MEMO_LEN];
    arr.copy_from_slice(memo_bytes);
    parse_memo_seal_json(&arr).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verifies a Ragu Pasta Poseidon-Merkle ownership proof from hex-encoded public inputs.
#[wasm_bindgen]
pub fn verify_ownership_proof(
    collection_root_hex: &str,
    challenge_hex: &str,
    proof_bytes: &[u8],
) -> Result<bool, JsValue> {
    verify_ownership_proof_hex(collection_root_hex, challenge_hex, proof_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

fn parse_32(s: &str) -> Result<[u8; 32], JsValue> {
    let bytes = hex::decode(s).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("expected 32-byte hex"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
