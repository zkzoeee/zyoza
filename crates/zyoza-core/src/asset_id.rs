use blake2b_simd::Params;
use group::GroupEncoding;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

/// ZIP 227-aligned personalization for hashing the asset description.
const PERSONAL_ASSET_DESC: &[u8; 16] = b"ZSA-AssetDesc___";

/// ZIP 227-aligned personalization for deriving the 32-byte `AssetId`.
const PERSONAL_ASSET_ID: &[u8; 16] = b"ZSA-AssetId_____";

/// Domain separator for hashing `AssetId` onto the Pallas curve (`AssetBase`).
const DOMAIN_ASSET_BASE: &str = "z.cash:OrchardZSA";

/// Canonical asset description used to derive a deterministic ZIP 227 `AssetId`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetDesc {
    pub namespace: String,
    pub collection: String,
    pub item_id: String,
}

impl AssetDesc {
    /// Serializes the asset description into canonical length-prefixed bytes.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        format!("{}:{}:{}", self.namespace, self.collection, self.item_id).into_bytes()
    }
}

/// 32-byte ZIP 227-compatible Asset Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId(pub [u8; 32]);

impl AssetId {
    /// Derives a deterministic 32-byte `AssetId` from an issuer verification key and
    /// canonical asset description bytes, following ZIP 227's domain-separated pattern.
    pub fn derive(issuer_vk: &[u8], asset_desc: &[u8]) -> Self {
        let desc_hash = Params::new()
            .hash_length(32)
            .personal(PERSONAL_ASSET_DESC)
            .hash(asset_desc);

        let mut state = Params::new()
            .hash_length(32)
            .personal(PERSONAL_ASSET_ID)
            .to_state();
        state.update(issuer_vk);
        state.update(desc_hash.as_bytes());

        let mut out = [0u8; 32];
        out.copy_from_slice(state.finalize().as_bytes());
        Self(out)
    }

    /// Derives the corresponding Pallas curve `AssetBase` for OrchardZSA compatibility.
    pub fn to_asset_base(&self) -> AssetBase {
        AssetBase::from_asset_id(self)
    }

    /// Returns the `AssetId` as lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Pallas curve point (`[u8; 32]` compressed) representing an OrchardZSA Asset Base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetBase(pub [u8; 32]);

impl AssetBase {
    /// Maps an `AssetId` onto the Pallas curve using `hash_to_curve("z.cash:OrchardZSA")`.
    pub fn from_asset_id(asset_id: &AssetId) -> Self {
        let hasher = pallas::Point::hash_to_curve(DOMAIN_ASSET_BASE);
        let point = hasher(&asset_id.0);
        Self(point.to_bytes())
    }

    /// Returns the compressed Pallas point bytes as lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}
