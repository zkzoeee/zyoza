use blake2b_simd::Params;
use group::GroupEncoding;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

/// ZIP 227 personalization for hashing the asset description (`assetDescHash`).
const PERSONAL_ASSET_DESC_CRH: &[u8; 16] = b"ZSA-AssetDescCRH";

/// ZIP 227 personalization for deriving the 64-byte `AssetDigest` (` BLAKE2b-512("ZSA-Asset-Digest", EncodeAssetId)`).
const PERSONAL_ASSET_DIGEST: &[u8; 16] = b"ZSA-Asset-Digest";

/// ZIP 227 domain separator for mapping `AssetDigest` onto the Pallas curve (`AssetBase`).
const DOMAIN_ASSET_BASE: &str = "z.cash:OrchardZSA";

/// Canonical asset description used to derive a deterministic ZIP 227 `AssetDigest` / `AssetId`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetDesc {
    pub namespace: String,
    pub collection: String,
    pub item_id: String,
}

impl AssetDesc {
    /// Serializes the asset description into canonical colon-delimited UTF-8 bytes.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        format!("{}:{}:{}", self.namespace, self.collection, self.item_id).into_bytes()
    }
}

/// 64-byte ZIP 227 `AssetDigest` (`BLAKE2b-512("ZSA-Asset-Digest", [0x00] || ik || assetDescHash)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssetDigest(pub [u8; 64]);

impl AssetDigest {
    /// Computes the 64-byte ZIP 227 `AssetDigest` from an issuer key `ik` and `asset_desc`.
    pub fn derive(issuer_vk: &[u8], asset_desc: &[u8]) -> Self {
        let desc_hash = Params::new()
            .hash_length(32)
            .personal(PERSONAL_ASSET_DESC_CRH)
            .hash(asset_desc);

        // ZIP 227 EncodeAssetId := [0x00] || ik || assetDescHash
        let mut state = Params::new()
            .hash_length(64)
            .personal(PERSONAL_ASSET_DIGEST)
            .to_state();
        state.update(&[0x00]);
        state.update(issuer_vk);
        state.update(desc_hash.as_bytes());

        let mut out = [0u8; 64];
        out.copy_from_slice(state.finalize().as_bytes());
        Self(out)
    }

    /// Maps the 64-byte `AssetDigest` onto Pallas via `GroupHash("z.cash:OrchardZSA", AssetDigest)`.
    pub fn to_asset_base(&self) -> AssetBase {
        let hasher = pallas::Point::hash_to_curve(DOMAIN_ASSET_BASE);
        let point = hasher(&self.0);
        AssetBase(point.to_bytes())
    }
}

/// Compact 32-byte Asset Identifier (first 32 bytes of the 64-byte ZIP 227 `AssetDigest`)
/// carried inside 512-byte Stage I memo seals and indexing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId(pub [u8; 32]);

impl AssetId {
    /// Derives the 32-byte `AssetId` from the first 32 bytes of ZIP 227's 64-byte `AssetDigest`.
    pub fn derive(issuer_vk: &[u8], asset_desc: &[u8]) -> Self {
        let digest = AssetDigest::derive(issuer_vk, asset_desc);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest.0[..32]);
        Self(out)
    }

    /// Derives both the compact 32-byte `AssetId` and exact ZIP 227 Pallas `AssetBase`
    /// (from the full 64-byte `AssetDigest`).
    pub fn derive_with_base(issuer_vk: &[u8], asset_desc: &[u8]) -> (Self, AssetBase) {
        let digest = AssetDigest::derive(issuer_vk, asset_desc);
        let mut id = [0u8; 32];
        id.copy_from_slice(&digest.0[..32]);
        (Self(id), digest.to_asset_base())
    }

    /// Maps this 32-byte `AssetId` onto Pallas when the full 64-byte `AssetDigest` is not supplied;
    /// callers performing full ZIP 227 issuance should prefer `AssetId::derive_with_base` / `AssetDigest::to_asset_base`.
    pub fn to_asset_base(&self) -> AssetBase {
        let hasher = pallas::Point::hash_to_curve(DOMAIN_ASSET_BASE);
        AssetBase(hasher(&self.0).to_bytes())
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
    /// Maps a 32-byte `AssetId` onto Pallas (`GroupHash("z.cash:OrchardZSA")`).
    pub fn from_asset_id(asset_id: &AssetId) -> Self {
        asset_id.to_asset_base()
    }

    /// Maps a full 64-byte ZIP 227 `AssetDigest` onto Pallas (`GroupHash("z.cash:OrchardZSA")`).
    pub fn from_digest(digest: &AssetDigest) -> Self {
        digest.to_asset_base()
    }

    /// Returns the compressed Pallas point bytes as lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}
