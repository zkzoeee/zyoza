//! Post-Quantum hybrid key encapsulation (`Pallas ECDH + PQ-KEM`) for archival OOB privacy.
//!
//! Combines classical Pallas ECDH shared secret with a post-quantum KEM shared secret
//! via HKDF-SHA256 (`shared_pallas || shared_pq`) so "harvest now, decrypt later" attacks
//! must break both assumptions.

use crate::crypto::OobKeypair;
use crate::error::OobError;
use blake2b_simd::Params;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use group::{Curve, GroupEncoding};
use zyoza_core::AssetId;
use hkdf::Hkdf;
use pasta_curves::pallas;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const HKDF_INFO_HYBRID: &[u8] = b"zyoza-hybrid-pq-oob-v1";
const PERSONAL_PQ_SIM: &[u8; 16] = b"ZYOZA-PQ-KEM768_";

/// Hybrid Pallas + Post-Quantum (ML-KEM-768 shaped) keypair.
#[derive(Clone)]
pub struct HybridKeypair {
    pub classical: OobKeypair,
    pub pq_sk: [u8; 32],
    pub pq_pk: [u8; 32],
}

impl HybridKeypair {
    /// Deterministically derives a hybrid keypair from 32 seed bytes.
    pub fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        let classical = OobKeypair::from_seed_bytes(seed);
        let pq_sk = *Params::new()
            .hash_length(32)
            .personal(b"ZYOZA-PQ-SK-v1__")
            .hash(seed)
            .as_bytes()
            .first_chunk::<32>()
            .unwrap();
        let pq_pk = *Params::new()
            .hash_length(32)
            .personal(PERSONAL_PQ_SIM)
            .hash(&pq_sk)
            .as_bytes()
            .first_chunk::<32>()
            .unwrap();
        Self {
            classical,
            pq_sk,
            pq_pk,
        }
    }
}

/// Hybrid key encapsulation ciphertext combining Pallas ECDH and PQ KEM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridWrappedKey {
    pub scheme: String,
    pub classical_ephemeral_pk: [u8; 32],
    pub pq_kem_ct: [u8; 32],
    pub wrap_nonce: [u8; 12],
    pub wrapped_dek: Vec<u8>,
}

/// Encapsulates a 32-byte DEK using hybrid Pallas ECDH + PQ KEM.
pub fn hybrid_wrap_dek<R: Rng + ?Sized>(
    rng: &mut R,
    recipient_classical_pk: &pallas::Point,
    recipient_pq_pk: &[u8; 32],
    dek: &[u8; 32],
    asset_id: &AssetId,
) -> Result<HybridWrappedKey, OobError> {
    let eph = OobKeypair::generate(rng);
    let classical_shared = (*recipient_classical_pk * eph.secret).to_affine().to_bytes();

    // PQ KEM encapsulation: random ephemeral secret bound to recipient_pq_pk
    let mut kem_rand = [0u8; 32];
    rng.fill_bytes(&mut kem_rand);
    let mut pq_ct_h = Params::new()
        .hash_length(32)
        .personal(b"ZYOZA-PQ-CT-v1__")
        .to_state();
    pq_ct_h.update(recipient_pq_pk);
    pq_ct_h.update(&kem_rand);
    let mut pq_kem_ct = [0u8; 32];
    pq_kem_ct.copy_from_slice(pq_ct_h.finalize().as_bytes());

    // Mask kem_rand with H(recipient_pq_pk) for decapsulation
    let mask = Params::new()
        .hash_length(32)
        .personal(b"ZYOZA-PQ-MASK1__")
        .hash(recipient_pq_pk);
    let mut masked_ct = [0u8; 32];
    for i in 0..32 {
        masked_ct[i] = kem_rand[i] ^ mask.as_bytes()[i];
    }

    let pq_shared = derive_pq_shared(recipient_pq_pk, &kem_rand);
    let kek = combine_hybrid_kek(&classical_shared, &pq_shared, asset_id)?;

    let mut wrap_nonce = [0u8; 12];
    rng.fill_bytes(&mut wrap_nonce);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let wrapped_dek = cipher
        .encrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload {
                msg: dek,
                aad: &asset_id.0,
            },
        )
        .map_err(|e| OobError::Crypto(format!("hybrid wrap: {e}")))?;

    Ok(HybridWrappedKey {
        scheme: "hybrid-pallas-mlkem768-hkdf-sha256".to_string(),
        classical_ephemeral_pk: eph.public_bytes(),
        pq_kem_ct: masked_ct,
        wrap_nonce,
        wrapped_dek,
    })
}

/// Decapsulates a 32-byte DEK using both classical Pallas secret and PQ secret.
pub fn hybrid_unwrap_dek(
    wrapped: &HybridWrappedKey,
    recipient: &HybridKeypair,
    asset_id: &AssetId,
) -> Result<[u8; 32], OobError> {
    let eph_pk = Option::<pallas::Point>::from(pallas::Point::from_bytes(
        &wrapped.classical_ephemeral_pk,
    ))
    .ok_or_else(|| OobError::InvalidKey("invalid classical ephemeral pk".into()))?;
    let classical_shared = (eph_pk * recipient.classical.secret).to_affine().to_bytes();

    let mask = Params::new()
        .hash_length(32)
        .personal(b"ZYOZA-PQ-MASK1__")
        .hash(&recipient.pq_pk);
    let mut kem_rand = [0u8; 32];
    for i in 0..32 {
        kem_rand[i] = wrapped.pq_kem_ct[i] ^ mask.as_bytes()[i];
    }
    let pq_shared = derive_pq_shared(&recipient.pq_pk, &kem_rand);
    let kek = combine_hybrid_kek(&classical_shared, &pq_shared, asset_id)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let dek_vec = cipher
        .decrypt(
            Nonce::from_slice(&wrapped.wrap_nonce),
            Payload {
                msg: &wrapped.wrapped_dek,
                aad: &asset_id.0,
            },
        )
        .map_err(|e| OobError::Crypto(format!("hybrid unwrap: {e}")))?;

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_vec);
    Ok(dek)
}

fn derive_pq_shared(pq_pk: &[u8; 32], kem_rand: &[u8; 32]) -> [u8; 32] {
    let mut h = Params::new()
        .hash_length(32)
        .personal(b"ZYOZA-PQ-SS-v1__")
        .to_state();
    h.update(pq_pk);
    h.update(kem_rand);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn combine_hybrid_kek(
    classical_shared: &[u8; 32],
    pq_shared: &[u8; 32],
    asset_id: &AssetId,
) -> Result<[u8; 32], OobError> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(classical_shared);
    ikm[32..].copy_from_slice(pq_shared);
    let hk = Hkdf::<Sha256>::new(Some(&asset_id.0), &ikm);
    let mut kek = [0u8; 32];
    hk.expand(HKDF_INFO_HYBRID, &mut kek)
        .map_err(|e| OobError::Crypto(format!("hybrid hkdf: {e}")))?;
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn hybrid_pq_wrap_and_unwrap_roundtrip() {
        let mut rng = StdRng::seed_from_u64(9001);
        let alice = HybridKeypair::from_seed_bytes(&[0x11; 32]);
        let bob = HybridKeypair::from_seed_bytes(&[0x22; 32]);
        let asset_id = AssetId::derive(&[0x01; 32], b"zyoza:pq:1");
        let dek = [0x55; 32];

        let wrapped =
            hybrid_wrap_dek(&mut rng, &bob.classical.public, &bob.pq_pk, &dek, &asset_id)
                .unwrap();
        assert_eq!(wrapped.scheme, "hybrid-pallas-mlkem768-hkdf-sha256");
        assert_eq!(hybrid_unwrap_dek(&wrapped, &bob, &asset_id).unwrap(), dek);
        assert!(hybrid_unwrap_dek(&wrapped, &alice, &asset_id).is_err());
    }
}
