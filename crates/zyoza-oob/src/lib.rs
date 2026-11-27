//! Out-of-band encrypted payload, Pallas ECDH key handover, and backup storage for Zyoza.

pub mod crypto;
pub mod error;
pub mod storage;

pub use crypto::{decrypt_backup, encrypt_backup, OobEnvelope, OobKeypair, WrappedKey};
pub use error::OobError;
pub use storage::{InMemoryStorage, LocalFsStorage, OobStorage};

#[cfg(test)]
mod tests {
    use super::*;
    use zyoza_core::{AssetId, ZyozaEnvelope, PROTOCOL_VERSION};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn seal_open_rewrap_and_backup_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let alice = OobKeypair::from_seed_bytes(&[0x11; 32]);
        let bob = OobKeypair::from_seed_bytes(&[0x22; 32]);
        let carol = OobKeypair::from_seed_bytes(&[0x33; 32]);

        let asset_id = AssetId::derive(&[0xAA; 32], b"zyoza:nft:1");
        let env = ZyozaEnvelope {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id,
            state_root: [0x55; 32],
            prev_commitment: None,
            nonce: [0x66; 32],
        };

        let secret_media = b"encrypted-zyoza-high-res-artwork-payload";
        let oob = OobEnvelope::seal(&mut rng, &env, &alice.public, secret_media).unwrap();

        // Bob cannot open Alice's envelope.
        assert!(oob.open(&bob.secret).is_err());
        assert_eq!(oob.open(&alice.secret).unwrap(), secret_media);

        // Alice re-wraps DEK for Bob.
        let bob_oob = oob
            .rewrap_for_recipient(&mut rng, &alice.secret, &bob.public, [0x77; 32])
            .unwrap();
        assert!(bob_oob.open(&alice.secret).is_err());
        assert!(bob_oob.open(&carol.secret).is_err());
        assert_eq!(bob_oob.open(&bob.secret).unwrap(), secret_media);

        // Store and fetch via InMemoryStorage.
        let store = InMemoryStorage::default();
        let uri = store.put(&bob_oob).unwrap();
        let fetched = store.get(&uri).unwrap();
        assert_eq!(fetched.open(&bob.secret).unwrap(), secret_media);

        // Seed-derived backup roundtrip.
        let wallet_seed = [0x99; 32];
        let backup = encrypt_backup(&mut rng, &wallet_seed, secret_media).unwrap();
        assert_eq!(decrypt_backup(&wallet_seed, &backup).unwrap(), secret_media);
        assert!(decrypt_backup(&[0x00; 32], &backup).is_err());
    }
}
