use crate::asset_id::AssetId;
use crate::error::ZyozaError;
use blake2b_simd::Params;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};

const PERSONAL_OVK: &[u8; 16] = b"ZYOZA-OVK-v1____";

/// Per-object viewing key enabling selective disclosure without exposing wallet keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectViewingKey {
    pub asset_id: AssetId,
    pub key_bytes: [u8; 32],
}

impl ObjectViewingKey {
    /// Derives a per-object viewing key from an owner's secret and the `AssetId`.
    pub fn derive(asset_id: AssetId, owner_secret: &[u8; 32]) -> Self {
        let mut state = Params::new()
            .hash_length(32)
            .personal(PERSONAL_OVK)
            .to_state();
        state.update(&asset_id.0);
        state.update(owner_secret);

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(state.finalize().as_bytes());
        Self {
            asset_id,
            key_bytes,
        }
    }
}

/// Encrypted selective-disclosure bundle readable only with the matching `ObjectViewingKey`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureBundle {
    pub asset_id: AssetId,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl DisclosureBundle {
    /// Encrypts `plaintext` using `ChaCha20Poly1305` under `ovk`, binding `asset_id` as AAD.
    pub fn seal(
        ovk: &ObjectViewingKey,
        nonce: [u8; 12],
        plaintext: &[u8],
    ) -> Result<Self, ZyozaError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&ovk.key_bytes));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &ovk.asset_id.0,
                },
            )
            .map_err(|e| ZyozaError::Disclosure(format!("seal failed: {e}")))?;

        Ok(Self {
            asset_id: ovk.asset_id,
            nonce,
            ciphertext,
        })
    }

    /// Decrypts the selective-disclosure bundle using the matching `ObjectViewingKey`.
    pub fn open(&self, ovk: &ObjectViewingKey) -> Result<Vec<u8>, ZyozaError> {
        if self.asset_id != ovk.asset_id {
            return Err(ZyozaError::Disclosure(
                "viewing key asset_id mismatch".to_string(),
            ));
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&ovk.key_bytes));
        cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &self.asset_id.0,
                },
            )
            .map_err(|e| ZyozaError::Disclosure(format!("open failed: {e}")))
    }
}
