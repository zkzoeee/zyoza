use crate::asset_id::AssetId;
use crate::error::ZyozaError;
use blake2b_simd::Params;
use serde::{Deserialize, Serialize};

/// 4-byte magic prefix for Zyoza Orchard memo seals (`"ZYOZ"`).
pub const SEAL_MAGIC: [u8; 4] = *b"ZYOZ";

/// Current Zyoza binary protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Exact byte length of an Orchard encrypted memo field.
pub const ORCHARD_MEMO_LEN: usize = 512;

/// Maximum UTF-8 byte length of the out-of-band pointer URI inside an Orchard memo seal.
pub const MAX_OOB_URI_LEN: usize = 372;

const PERSONAL_STATE_COMMIT: &[u8; 16] = b"ZYOZA-COMMIT-v1_";

/// 4-byte vertical profile identifier (e.g. `b"NFT1"`, `b"TKT1"`, `b"CRD1"`).
pub type ProfileId = [u8; 4];

/// Vertical-agnostic state envelope for a Zyoza Shielded State Object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZyozaEnvelope {
    pub version: u16,
    pub profile_id: ProfileId,
    pub asset_id: AssetId,
    pub state_root: [u8; 32],
    pub prev_commitment: Option<[u8; 32]>,
    pub nonce: [u8; 32],
}

impl ZyozaEnvelope {
    /// Computes the deterministic 32-byte commitment anchored into L1 settlement.
    pub fn state_commitment(&self) -> [u8; 32] {
        let mut state = Params::new()
            .hash_length(32)
            .personal(PERSONAL_STATE_COMMIT)
            .to_state();
        state.update(&self.version.to_be_bytes());
        state.update(&self.profile_id);
        state.update(&self.asset_id.0);
        state.update(&self.state_root);
        match self.prev_commitment {
            Some(prev) => {
                state.update(&[1]);
                state.update(&prev);
            }
            None => {
                state.update(&[0]);
            }
        }
        state.update(&self.nonce);

        let mut out = [0u8; 32];
        out.copy_from_slice(state.finalize().as_bytes());
        out
    }
}

/// Canonical 512-byte Orchard memo seal layout.
///
/// Layout:
/// - `0..4`: `magic` (`b"ZYOZ"`)
/// - `4..6`: `version` (`u16` big-endian)
/// - `6..10`: `profile_id` (`[u8; 4]`)
/// - `10..42`: `asset_id` (`[u8; 32]`)
/// - `42..74`: `state_root` (`[u8; 32]`)
/// - `74..106`: `nonce` (`[u8; 32]`)
/// - `106..138`: `oob_pointer_hash` (`[u8; 32]`)
/// - `138..140`: `oob_uri_len` (`u16` big-endian, `<= 372`)
/// - `140..512`: `oob_uri_bytes` (UTF-8 URI/CID, zero-padded)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrchardMemoSeal {
    pub version: u16,
    pub profile_id: ProfileId,
    pub asset_id: AssetId,
    pub state_root: [u8; 32],
    pub nonce: [u8; 32],
    pub oob_pointer_hash: [u8; 32],
    pub oob_uri: String,
}

impl OrchardMemoSeal {
    /// Serializes the seal into an exact 512-byte Orchard memo payload.
    pub fn to_bytes(&self) -> Result<[u8; ORCHARD_MEMO_LEN], ZyozaError> {
        let uri_bytes = self.oob_uri.as_bytes();
        if uri_bytes.len() > MAX_OOB_URI_LEN {
            return Err(ZyozaError::OobUriTooLong {
                len: uri_bytes.len(),
                max: MAX_OOB_URI_LEN,
            });
        }

        let mut buf = [0u8; ORCHARD_MEMO_LEN];
        buf[0..4].copy_from_slice(&SEAL_MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_be_bytes());
        buf[6..10].copy_from_slice(&self.profile_id);
        buf[10..42].copy_from_slice(&self.asset_id.0);
        buf[42..74].copy_from_slice(&self.state_root);
        buf[74..106].copy_from_slice(&self.nonce);
        buf[106..138].copy_from_slice(&self.oob_pointer_hash);
        buf[138..140].copy_from_slice(&(uri_bytes.len() as u16).to_be_bytes());
        buf[140..140 + uri_bytes.len()].copy_from_slice(uri_bytes);
        Ok(buf)
    }

    /// Parses a 512-byte Orchard memo payload into an `OrchardMemoSeal`.
    pub fn from_bytes(buf: &[u8; ORCHARD_MEMO_LEN]) -> Result<Self, ZyozaError> {
        if buf[0..4] != SEAL_MAGIC {
            return Err(ZyozaError::InvalidSealHeader(
                "missing ZYOZ magic bytes".to_string(),
            ));
        }

        let version = u16::from_be_bytes([buf[4], buf[5]]);
        if version != PROTOCOL_VERSION {
            return Err(ZyozaError::InvalidSealHeader(format!(
                "unsupported version {version}"
            )));
        }

        let mut profile_id = [0u8; 4];
        profile_id.copy_from_slice(&buf[6..10]);

        let mut asset_id = [0u8; 32];
        asset_id.copy_from_slice(&buf[10..42]);

        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&buf[42..74]);

        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&buf[74..106]);

        let mut oob_pointer_hash = [0u8; 32];
        oob_pointer_hash.copy_from_slice(&buf[106..138]);

        let uri_len = u16::from_be_bytes([buf[138], buf[139]]) as usize;
        if uri_len > MAX_OOB_URI_LEN {
            return Err(ZyozaError::OobUriTooLong {
                len: uri_len,
                max: MAX_OOB_URI_LEN,
            });
        }

        let oob_uri = std::str::from_utf8(&buf[140..140 + uri_len])
            .map_err(|e| ZyozaError::InvalidEncoding(format!("invalid UTF-8 oob_uri: {e}")))?
            .to_string();

        Ok(Self {
            version,
            profile_id,
            asset_id: AssetId(asset_id),
            state_root,
            nonce,
            oob_pointer_hash,
            oob_uri,
        })
    }
}

/// Publicly renderable preview returned by an `AssetProfile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePreview {
    pub profile_id: ProfileId,
    pub title: String,
    pub summary: String,
    pub attributes_json: String,
}

/// Receipt returned by a `SettlementAdapter` after anchoring a mint or transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub backend: String,
    pub tx_id: [u8; 32],
    pub commitment: [u8; 32],
    pub block_height: Option<u64>,
}

/// Opaque serialized zero-knowledge proof bytes.
pub type ProofBytes = Vec<u8>;

/// Request to prove ownership of an unspent Zyoza object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipProofRequest {
    pub asset_id: AssetId,
    pub collection_root: [u8; 32],
    pub secret_witness: Vec<u8>,
    pub challenge: [u8; 32],
}

/// Public inputs required to verify an ownership proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipVerifyRequest {
    pub collection_root: [u8; 32],
    pub challenge: [u8; 32],
}
