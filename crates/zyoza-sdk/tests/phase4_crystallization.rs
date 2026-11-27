use zyoza_core::{AssetDesc, OrchardMemoSeal, SettlementAdapter, PROTOCOL_VERSION};
use zyoza_oob::{InMemoryStorage, OobKeypair};
use zyoza_profile_nft::{CollectionPolicy, ProvenanceEvent};
use zyoza_proofs::Halo2ProofEngine;
use zyoza_sdk::ZyozaNftClient;
use zyoza_settlement::{
    aggregate_signatures, keygen_dealer, round1_commit, round2_sign, verify_frost_signature,
    OrchardSealAdapter, OrchardZsaAdapter,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::BTreeMap;

#[test]
fn burn_phase1_seal_and_crystallize_into_native_zsa_with_frost() {
    let mut rng = StdRng::seed_from_u64(4040);
    let alice = OobKeypair::from_seed_bytes(&[0xA1; 32]);
    let bob = OobKeypair::from_seed_bytes(&[0xB2; 32]);

    // 1. Mint NFT on Phase 1 OrchardSealAdapter
    let p1_client = ZyozaNftClient::new(
        InMemoryStorage::default(),
        OrchardSealAdapter::new(),
        Halo2ProofEngine,
    );
    let desc = AssetDesc {
        namespace: "zyoza".into(),
        collection: "genesis".into(),
        item_id: "0099".into(),
    };
    let minted = p1_client
        .mint_nft(
            &mut rng,
            &[0x01; 32],
            &desc,
            "Crystallized Zyoza #99".into(),
            "Phase 1 -> Phase 4 ZSA".into(),
            "alice".into(),
            "ipfs://bafy99".into(),
            BTreeMap::from([("stage".into(), "phase1".into())]),
            CollectionPolicy {
                royalty_bps: 500,
                lockup_until_unix: None,
            },
            &alice,
            &[0xA1; 32],
            1_700_000_000,
        )
        .unwrap();

    // 2. Prove burn/migration via Halo2
    let mig_proof = Halo2ProofEngine
        .prove_migration(&minted.asset_id, minted.commitment, b"alice-phase1-sk")
        .unwrap();
    assert!(Halo2ProofEngine
        .verify_migration(&minted.asset_id, minted.commitment, &mig_proof)
        .unwrap());

    // Burn Phase 1 seal by transferring to a terminal burn commitment
    let burn_memo = OrchardMemoSeal {
        version: PROTOCOL_VERSION,
        profile_id: *b"NFT1",
        asset_id: minted.asset_id,
        state_root: [0xFF; 32],
        nonce: [0xEE; 32],
        oob_pointer_hash: [0xDD; 32],
        oob_uri: "burn://zsa-crystallize".into(),
    }
    .to_bytes()
    .unwrap();
    p1_client
        .settlement
        .anchor_transfer(&minted.asset_id, minted.commitment, [0xFF; 32], &burn_memo)
        .unwrap();
    assert!(!p1_client.settlement.verify_seal(&minted.receipt).unwrap());

    // 3. Authorize ZSA issuance via 2-of-3 FROST threshold issuer signature
    let (group_pk, shares) = keygen_dealer(&mut rng, 2, 3).unwrap();
    let issuance_bundle = minted.asset_id.0;
    let c1 = round1_commit(&mut rng, &shares[0]);
    let c2 = round1_commit(&mut rng, &shares[1]);
    let commits = vec![c1.clone(), c2.clone()];
    let p1 = round2_sign(&shares[0], &c1, &commits, &issuance_bundle);
    let p2 = round2_sign(&shares[1], &c2, &commits, &issuance_bundle);
    let frost_sig = aggregate_signatures(&commits, &[p1, p2]).unwrap();
    assert!(verify_frost_signature(&group_pk, &issuance_bundle, &frost_sig).unwrap());

    // 4. Crystallize onto OrchardZsaAdapter with identical AssetId & AssetBase
    let zsa_adapter = OrchardZsaAdapter::new();
    let mut zsa_state = minted.state.clone();
    zsa_state.provenance.push(ProvenanceEvent {
        step: 1,
        kind: "crystallize_zsa".into(),
        commitment_hex: hex::encode(minted.commitment),
        timestamp_unix: 1_700_000_200,
    });
    let zsa_state_root = zsa_state.state_root().unwrap();
    let zsa_memo = OrchardMemoSeal {
        version: PROTOCOL_VERSION,
        profile_id: *b"NFT1",
        asset_id: minted.asset_id,
        state_root: zsa_state_root,
        nonce: [0x77; 32],
        oob_pointer_hash: minted.oob_envelope.pointer_hash().unwrap(),
        oob_uri: minted.oob_uri.clone(),
    }
    .to_bytes()
    .unwrap();

    let zsa_mint = zsa_adapter
        .anchor_mint(&minted.asset_id, zsa_state_root, &zsa_memo)
        .unwrap();
    assert!(zsa_adapter.verify_seal(&zsa_mint).unwrap());

    let note = zsa_adapter.get_note(&zsa_state_root).unwrap();
    assert_eq!(note.asset_id, minted.asset_id);
    assert_eq!(note.asset_base, minted.asset_id.to_asset_base());
    assert_eq!(note.value, 1);
    assert!(note.finalized_supply);

    // 5. Transfer crystallized ZSA note to Bob
    let zsa_xfer = zsa_adapter
        .anchor_transfer(&minted.asset_id, zsa_state_root, [0x88; 32], &zsa_memo)
        .unwrap();
    assert!(!zsa_adapter.verify_seal(&zsa_mint).unwrap());
    assert!(zsa_adapter.verify_seal(&zsa_xfer).unwrap());
    let _ = bob;
}
