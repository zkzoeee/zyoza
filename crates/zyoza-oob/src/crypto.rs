use crate::error::OobError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blake2b_simd::Params;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ff::{Field, FromUniformBytes};
use group::{Curve, Group, GroupEncoding};
use zyoza_core::{AssetId, ZyozaEnvelope, ProfileId, PROTOCOL_VERSION};
use hkdf::Hkdf;
use pasta_curves::pallas;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const HKDF_INFO_WRAP: &[u8] = b"zyoza-oob-keywrap-v1";
const PERSONAL_BACKUP: &[u8; 16] = b"ZYOZA-BACKUP-v1_";
const PERSONAL_OOB_HASH: &[u8; 16] = b"ZYOZA-OOB-HASH1_";

/// Pallas ECDH keypair for out-of-band key encapsulation.
#[derive(Clone)]
pub struct OobKeypair {
    pub secret: pallas::Scalar,
    pub public: pallas::Point,
}

impl OobKeypair {
    /// Generates a fresh random Pallas keypair.
    pub fn generate<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        // Derive non-zero scalar from 64 uniform bytes via Blake2b + from_raw/reduce.
        let hash = Params::new().hash_length(32).hash(&seed);
        let mut wide = [0u8; 32];
        wide.copy_from_slice(hash.as_bytes());
        Self::from_seed_bytes(&wide)
    }

    /// Deterministically derives a Pallas keypair from 32 seed bytes.
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        let mut cur = *seed;
        let secret = loop {
            let h = Params::new()
                .hash_length(64)
                .personal(b"ZYOZA-OOB-KEY1__")
                .hash(&cur);
            let mut wide = [0u8; 64];
            wide.copy_from_slice(h.as_bytes());
            let s = pallas::Scalar::from_uniform_bytes(&wide);
            if !bool::from(s.is_zero()) {
                break s;
            }
            cur[0] ^= 0xff;
        };
        let public = pallas::Point::generator() * secret;
        Self { secret, public }
    }

    /// Returns the compressed 32-byte public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}

/// Ephemeral ECDH key encapsulation block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    pub scheme: String,
    pub ephemeral_pk: String,
    pub wrap_nonce: String,
    pub ciphertext_b64: String,
}

/// Out-of-band encrypted payload envelope matching `docs/SPEC.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OobEnvelope {
    pub version: u16,
    pub profile_id: String,
    pub asset_id: String,
    pub state_root: String,
    pub nonce: String,
    pub cipher: String,
    pub cipher_nonce: String,
    pub encrypted_payload_b64: String,
    pub wrapped_key: WrappedKey,
    pub integrity_hash: String,
}

impl OobEnvelope {
    /// Computes the canonical 32-byte pointer hash stored in `OrchardMemoSeal::oob_pointer_hash`.
    pub fn pointer_hash(&self) -> Result<[u8; 32], OobError> {
        let bytes = serde_json::to_vec(self)?;
        let hash = Params::new()
            .hash_length(32)
            .personal(PERSONAL_OOB_HASH)
            .hash(&bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        Ok(out)
    }

    /// Encrypts `plaintext` with a fresh DEK and wraps the DEK for `recipient_pk`.
    pub fn seal<R: Rng + ?Sized>(
        rng: &mut R,
        env: &ZyozaEnvelope,
        recipient_pk: &pallas::Point,
        plaintext: &[u8],
    ) -> Result<Self, OobError> {
        let mut dek = [0u8; 32];
        let mut cipher_nonce = [0u8; 12];
        rng.fill_bytes(&mut dek);
        rng.fill_bytes(&mut cipher_nonce);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&dek));
        let encrypted_payload = cipher
            .encrypt(
                Nonce::from_slice(&cipher_nonce),
                Payload {
                    msg: plaintext,
                    aad: &env.asset_id.0,
                },
            )
            .map_err(|e| OobError::Crypto(format!("payload encrypt: {e}")))?;

        let wrapped_key = wrap_dek(rng, recipient_pk, &dek, &env.asset_id)?;
        let integrity_hash = compute_integrity_hash(&env.asset_id, &env.state_root, plaintext);

        Ok(Self {
            version: PROTOCOL_VERSION,
            profile_id: profile_to_string(env.profile_id),
            asset_id: env.asset_id.to_hex(),
            state_root: hex::encode(env.state_root),
            nonce: hex::encode(env.nonce),
            cipher: "chacha20poly1305".to_string(),
            cipher_nonce: hex::encode(cipher_nonce),
            encrypted_payload_b64: B64.encode(encrypted_payload),
            wrapped_key,
            integrity_hash: hex::encode(integrity_hash),
        })
    }

    /// Unwraps the DEK using `recipient_sk` and decrypts + verifies the payload.
    pub fn open(&self, recipient_sk: &pallas::Scalar) -> Result<Vec<u8>, OobError> {
        let asset_id = parse_hex_32(&self.asset_id)?;
        let state_root = parse_hex_32(&self.state_root)?;
        let dek = unwrap_dek(&self.wrapped_key, recipient_sk, &AssetId(asset_id))?;

        let nonce_bytes = hex::decode(&self.cipher_nonce)
            .map_err(|e| OobError::InvalidKey(format!("bad cipher_nonce hex: {e}")))?;
        if nonce_bytes.len() != 12 {
            return Err(OobError::InvalidKey("cipher_nonce must be 12 bytes".into()));
        }

        let ciphertext = B64
            .decode(&self.encrypted_payload_b64)
            .map_err(|e| OobError::Crypto(format!("bad base64 payload: {e}")))?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&dek));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad: &asset_id,
                },
            )
            .map_err(|e| OobError::Crypto(format!("payload decrypt: {e}")))?;

        let expected = compute_integrity_hash(&AssetId(asset_id), &state_root, &plaintext);
        if hex::encode(expected) != self.integrity_hash {
            return Err(OobError::IntegrityMismatch);
        }

        Ok(plaintext)
    }

    /// Re-wraps the existing DEK for a new recipient without re-encrypting the payload blob.
    pub fn rewrap_for_recipient<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        current_sk: &pallas::Scalar,
        new_recipient_pk: &pallas::Point,
        new_nonce: [u8; 32],
    ) -> Result<Self, OobError> {
        let asset_id = AssetId(parse_hex_32(&self.asset_id)?);
        let dek = unwrap_dek(&self.wrapped_key, current_sk, &asset_id)?;
        let wrapped_key = wrap_dek(rng, new_recipient_pk, &dek, &asset_id)?;

        let mut next = self.clone();
        next.nonce = hex::encode(new_nonce);
        next.wrapped_key = wrapped_key;
        Ok(next)
    }
}

/// Encrypts local wallet/CSV state using a seed-derived key for resilient backup.
pub fn encrypt_backup<R: Rng + ?Sized>(
    rng: &mut R,
    wallet_seed: &[u8; 32],
    state_bytes: &[u8],
) -> Result<Vec<u8>, OobError> {
    let key = derive_backup_key(wallet_seed);
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), state_bytes)
        .map_err(|e| OobError::Crypto(format!("backup encrypt: {e}")))?;

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypts a seed-derived encrypted state backup.
pub fn decrypt_backup(wallet_seed: &[u8; 32], backup: &[u8]) -> Result<Vec<u8>, OobError> {
    if backup.len() < 12 {
        return Err(OobError::Crypto("backup too short".into()));
    }
    let key = derive_backup_key(wallet_seed);
    let (nonce, ct) = backup.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|e| OobError::Crypto(format!("backup decrypt: {e}")))
}

fn derive_backup_key(wallet_seed: &[u8; 32]) -> [u8; 32] {
    let h = Params::new()
        .hash_length(32)
        .personal(PERSONAL_BACKUP)
        .hash(wallet_seed);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

fn wrap_dek<R: Rng + ?Sized>(
    rng: &mut R,
    recipient_pk: &pallas::Point,
    dek: &[u8; 32],
    asset_id: &AssetId,
) -> Result<WrappedKey, OobError> {
    let eph = OobKeypair::generate(rng);
    let shared = (*recipient_pk * eph.secret).to_affine();
    let kek = derive_kek(&shared.to_bytes(), &eph.public_bytes(), asset_id)?;

    let mut wrap_nonce = [0u8; 12];
    rng.fill_bytes(&mut wrap_nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload {
                msg: dek,
                aad: &asset_id.0,
            },
        )
        .map_err(|e| OobError::Crypto(format!("key wrap: {e}")))?;

    Ok(WrappedKey {
        scheme: "ecdh-pallas-hkdf-sha256".to_string(),
        ephemeral_pk: hex::encode(eph.public_bytes()),
        wrap_nonce: hex::encode(wrap_nonce),
        ciphertext_b64: B64.encode(ct),
    })
}

fn unwrap_dek(
    wrapped: &WrappedKey,
    recipient_sk: &pallas::Scalar,
    asset_id: &AssetId,
) -> Result<[u8; 32], OobError> {
    let eph_bytes = parse_hex_32(&wrapped.ephemeral_pk)?;
    let eph_pk = Option::<pallas::Point>::from(pallas::Point::from_bytes(&eph_bytes))
        .ok_or_else(|| OobError::InvalidKey("invalid ephemeral Pallas point".into()))?;

    let shared = (eph_pk * *recipient_sk).to_affine();
    let kek = derive_kek(&shared.to_bytes(), &eph_bytes, asset_id)?;

    let nonce_bytes = hex::decode(&wrapped.wrap_nonce)
        .map_err(|e| OobError::InvalidKey(format!("bad wrap_nonce hex: {e}")))?;
    if nonce_bytes.len() != 12 {
        return Err(OobError::InvalidKey("wrap_nonce must be 12 bytes".into()));
    }

    let ct = B64
        .decode(&wrapped.ciphertext_b64)
        .map_err(|e| OobError::Crypto(format!("bad wrapped_key base64: {e}")))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let dek_vec = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ct,
                aad: &asset_id.0,
            },
        )
        .map_err(|e| OobError::Crypto(format!("key unwrap: {e}")))?;

    if dek_vec.len() != 32 {
        return Err(OobError::InvalidKey("unwrapped DEK must be 32 bytes".into()));
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_vec);
    Ok(dek)
}

fn derive_kek(
    shared_bytes: &[u8; 32],
    eph_pk_bytes: &[u8; 32],
    asset_id: &AssetId,
) -> Result<[u8; 32], OobError> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pk_bytes);
    salt.extend_from_slice(&asset_id.0);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_bytes);
    let mut kek = [0u8; 32];
    hk.expand(HKDF_INFO_WRAP, &mut kek)
        .map_err(|e| OobError::Crypto(format!("hkdf expand: {e}")))?;
    Ok(kek)
}

fn compute_integrity_hash(
    asset_id: &AssetId,
    state_root: &[u8; 32],
    plaintext: &[u8],
) -> [u8; 32] {
    let mut state = Params::new()
        .hash_length(32)
        .personal(b"ZYOZA-INTEGRITY1")
        .to_state();
    state.update(&asset_id.0);
    state.update(state_root);
    state.update(plaintext);
    let mut out = [0u8; 32];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

fn profile_to_string(p: ProfileId) -> String {
    String::from_utf8_lossy(&p).to_string()
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], OobError> {
    let bytes = hex::decode(s).map_err(|e| OobError::InvalidKey(format!("bad hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(OobError::InvalidKey(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
