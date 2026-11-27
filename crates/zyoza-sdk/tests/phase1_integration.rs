use zyoza_core::{
    AssetDesc, AssetId, DisclosureBundle, ZyozaEnvelope, ObjectViewingKey, OrchardMemoSeal,
    SettlementAdapter, PROTOCOL_VERSION,
};
use zyoza_oob::{
    decrypt_backup, encrypt_backup, InMemoryStorage, OobEnvelope, OobKeypair, OobStorage,
};
use zyoza_settlement::OrchardSealAdapter;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn alice_bob_carol_phase1_lifecycle_and_double_spend_rejection() {
    let mut rng = StdRng::seed_from_u64(2026);

    let alice = OobKeypair::from_seed_bytes(&[0xA1; 32]);
    let bob = OobKeypair::from_seed_bytes(&[0xB2; 32]);
    let carol = OobKeypair::from_seed_bytes(&[0xC3; 32]);

    // 1. Derive ZIP 227-compatible AssetId + AssetBase
    let desc = AssetDesc {
        namespace: "zyoza".to_string(),
        collection: "genesis".to_string(),
        item_id: "0007".to_string(),
    };
    let asset_id = AssetId::derive(&[0x01; 32], &desc.to_canonical_bytes());
    let _asset_base = asset_id.to_asset_base();

    let storage = InMemoryStorage::default();
    let settlement = OrchardSealAdapter::new();

    // 2. Alice mints Zyoza #0007 with encrypted OOB payload
    let mint_env = ZyozaEnvelope {
        version: PROTOCOL_VERSION,
        profile_id: *b"NFT1",
        asset_id,
        state_root: [0x10; 32],
        prev_commitment: None,
        nonce: [0x01; 32],
    };
    let mint_commitment = mint_env.state_commitment();

    let payload = br#"{"title":"Genesis Zyoza #0007","media":"ipfs://bafybeig..."}"#;
    let alice_oob = OobEnvelope::seal(&mut rng, &mint_env, &alice.public, payload).unwrap();
    let alice_uri = storage.put(&alice_oob).unwrap();
    let alice_memo = OrchardMemoSeal {
        version: PROTOCOL_VERSION,
        profile_id: *b"NFT1",
        asset_id,
        state_root: mint_env.state_root,
        nonce: mint_env.nonce,
        oob_pointer_hash: alice_oob.pointer_hash().unwrap(),
        oob_uri: alice_uri.clone(),
    }
    .to_bytes()
    .unwrap();

    let mint_rcpt = settlement
        .anchor_mint(&asset_id, mint_commitment, &alice_memo)
        .unwrap();
    assert!(settlement.verify_seal(&mint_rcpt).unwrap());
    assert_eq!(storage.get(&alice_uri).unwrap().open(&alice.secret).unwrap(), payload);

    // 3. Alice transfers to Bob (key re-wrap + Orchard single-use seal)
    let bob_env = ZyozaEnvelope {
        version: PROTOCOL_VERSION,
        profile_id: *b"NFT1",
        asset_id,
        state_root: [0x20; 32],
        prev_commitment: Some(mint_commitment),
        nonce: [0x02; 32],
    };
    let bob_commitment = bob_env.state_commitment();
    let bob_oob = alice_oob
        .rewrap_for_recipient(&mut rng, &alice.secret, &bob.public, bob_env.nonce)
        .unwrap();
    let bob_uri = storage.put(&bob_oob).unwrap();
    let bob_memo = OrchardMemoSeal {
        version: PROTOCOL_VERSION,
        profile_id: *b"NFT1",
        asset_id,
        state_root: bob_env.state_root,
        nonce: bob_env.nonce,
        oob_pointer_hash: bob_oob.pointer_hash().unwrap(),
        oob_uri: bob_uri.clone(),
    }
    .to_bytes()
    .unwrap();

    let bob_rcpt = settlement
        .anchor_transfer(&asset_id, mint_commitment, bob_commitment, &bob_memo)
        .unwrap();
    assert!(!settlement.verify_seal(&mint_rcpt).unwrap());
    assert!(settlement.verify_seal(&bob_rcpt).unwrap());

    let scanned = OrchardSealAdapter::scan_memo(&bob_memo).unwrap();
    assert_eq!(scanned.oob_uri, bob_uri);
    assert_eq!(storage.get(&scanned.oob_uri).unwrap().open(&bob.secret).unwrap(), payload);
    assert!(storage.get(&scanned.oob_uri).unwrap().open(&alice.secret).is_err());

    // 4. Bob transfers to Carol
    let carol_env = ZyozaEnvelope {
        version: PROTOCOL_VERSION,
        profile_id: *b"NFT1",
        asset_id,
        state_root: [0x30; 32],
        prev_commitment: Some(bob_commitment),
        nonce: [0x03; 32],
    };
    let carol_commitment = carol_env.state_commitment();
    let carol_oob = bob_oob
        .rewrap_for_recipient(&mut rng, &bob.secret, &carol.public, carol_env.nonce)
        .unwrap();
    let carol_uri = storage.put(&carol_oob).unwrap();
    let carol_memo = OrchardMemoSeal {
        version: PROTOCOL_VERSION,
        profile_id: *b"NFT1",
        asset_id,
        state_root: carol_env.state_root,
        nonce: carol_env.nonce,
        oob_pointer_hash: carol_oob.pointer_hash().unwrap(),
        oob_uri: carol_uri.clone(),
    }
    .to_bytes()
    .unwrap();

    let carol_rcpt = settlement
        .anchor_transfer(&asset_id, bob_commitment, carol_commitment, &carol_memo)
        .unwrap();
    assert!(!settlement.verify_seal(&bob_rcpt).unwrap());
    assert!(settlement.verify_seal(&carol_rcpt).unwrap());
    assert_eq!(storage.get(&carol_uri).unwrap().open(&carol.secret).unwrap(), payload);

    // 5. Alice attempts to double-spend mint_commitment -> MUST FAIL
    assert!(settlement
        .anchor_transfer(&asset_id, mint_commitment, [0x99; 32], &alice_memo)
        .is_err());

    // 6. Carol selectively discloses metadata via ObjectViewingKey + backs up state
    let carol_ovk = ObjectViewingKey::derive(asset_id, &[0xC3; 32]);
    let disclosure = DisclosureBundle::seal(&carol_ovk, [0x09; 12], payload).unwrap();
    assert_eq!(disclosure.open(&carol_ovk).unwrap(), payload);

    let backup = encrypt_backup(&mut rng, &[0xC3; 32], payload).unwrap();
    assert_eq!(decrypt_backup(&[0xC3; 32], &backup).unwrap(), payload);
}
