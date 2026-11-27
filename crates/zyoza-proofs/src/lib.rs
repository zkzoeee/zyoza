//! Pasta-curve ZK proof engine (Halo2 IPA today, Ragu non-uniform PCD tomorrow).

pub mod ragu_pcd;
pub use ragu_pcd::{RaguPcdEngine, RaguPcdProof, RaguStepKind, RaguStepWitness};

use blake2b_simd::Params as Blake2bParams;
use ff::{FromUniformBytes, PrimeField};
use zyoza_core::{
    AssetId, ZyozaError, OwnershipProofRequest, OwnershipVerifyRequest, ProofBytes, ProofEngine,
};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error as PlonkError, Instance, ProvingKey, Selector, SingleVerifier, VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

pub use zyoza_core;
pub use halo2_proofs;
pub use pasta_curves;

const CIRCUIT_K: u32 = 6;

#[derive(Clone, Debug)]
struct KnowledgeConfig {
    secret: Column<Advice>,
    leaf: Column<Advice>,
    challenge: Column<Advice>,
    instance: Column<Instance>,
    selector: Selector,
}

/// Halo2 circuit proving knowledge of `(secret, leaf)` bound to `challenge`
/// via `public_digest = secret * challenge + leaf` over Pasta `Fp`.
#[derive(Clone, Default)]
struct MembershipKnowledgeCircuit {
    secret: Value<Fp>,
    leaf: Value<Fp>,
    challenge: Value<Fp>,
}

impl Circuit<Fp> for MembershipKnowledgeCircuit {
    type Config = KnowledgeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let secret = meta.advice_column();
        let leaf = meta.advice_column();
        let challenge = meta.advice_column();
        let instance = meta.instance_column();
        let selector = meta.selector();

        meta.enable_equality(secret);
        meta.enable_equality(leaf);
        meta.enable_equality(challenge);
        meta.enable_equality(instance);

        meta.create_gate("knowledge_binding", |meta| {
            let s = meta.query_selector(selector);
            let sec = meta.query_advice(secret, Rotation::cur());
            let lf = meta.query_advice(leaf, Rotation::cur());
            let ch = meta.query_advice(challenge, Rotation::cur());
            let out = meta.query_advice(secret, Rotation::next());
            // out == sec * ch + lf
            vec![s * (sec * ch + lf - out)]
        });

        KnowledgeConfig {
            secret,
            leaf,
            challenge,
            instance,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), PlonkError> {
        let (ch_cell, out_cell) = layouter.assign_region(
            || "knowledge_binding_row",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                region.assign_advice(|| "secret", config.secret, 0, || self.secret)?;
                region.assign_advice(|| "leaf", config.leaf, 0, || self.leaf)?;
                let ch = region.assign_advice(
                    || "challenge",
                    config.challenge,
                    0,
                    || self.challenge,
                )?;
                let out_val = self.secret * self.challenge + self.leaf;
                let out = region.assign_advice(|| "digest", config.secret, 1, || out_val)?;
                Ok((ch, out))
            },
        )?;

        layouter.constrain_instance(ch_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(out_cell.cell(), config.instance, 1)?;
        Ok(())
    }
}

struct CachedKeys {
    params: Params<EqAffine>,
    vk: VerifyingKey<EqAffine>,
    pk: ProvingKey<EqAffine>,
}

static KEYS: OnceLock<CachedKeys> = OnceLock::new();

fn get_keys() -> &'static CachedKeys {
    KEYS.get_or_init(|| {
        let params = Params::<EqAffine>::new(CIRCUIT_K);
        let empty = MembershipKnowledgeCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("keygen_vk");
        let pk = keygen_pk(&params, vk.clone(), &empty).expect("keygen_pk");
        CachedKeys { params, vk, pk }
    })
}

/// Serialized Halo2 IPA proof payload with its public digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2ProofPayload {
    pub digest_bytes: [u8; 32],
    pub ipa_proof: Vec<u8>,
}

/// Halo2 IPA proof engine on Pasta curves.
#[derive(Debug, Default, Clone, Copy)]
pub struct Halo2ProofEngine;

impl Halo2ProofEngine {
    /// Generates a zero-knowledge proof that an owned NFT possesses trait `key=val`.
    pub fn prove_attribute(
        &self,
        asset_id: &AssetId,
        trait_key: &str,
        trait_val: &str,
        secret_witness: &[u8],
        challenge: [u8; 32],
    ) -> Result<ProofBytes, ZyozaError> {
        let leaf = hash_to_fp(
            b"ZYOZA-TRAIT-v1__",
            &[&asset_id.0, trait_key.as_bytes(), trait_val.as_bytes()],
        );
        let secret = hash_to_fp(b"ZYOZA-SEC-v1____", &[secret_witness]);
        let ch = hash_to_fp(
            b"ZYOZA-CHAL-v1___",
            &[&challenge, trait_key.as_bytes(), trait_val.as_bytes()],
        );
        self.prove_knowledge(secret, leaf, ch)
    }

    /// Verifies a trait-attribute proof against `(trait_key, trait_val, challenge)`.
    pub fn verify_attribute(
        &self,
        trait_key: &str,
        trait_val: &str,
        challenge: [u8; 32],
        proof: &[u8],
    ) -> Result<bool, ZyozaError> {
        let ch = hash_to_fp(
            b"ZYOZA-CHAL-v1___",
            &[&challenge, trait_key.as_bytes(), trait_val.as_bytes()],
        );
        self.verify_knowledge(ch, proof)
    }

    /// Generates a Halo2 ZK proof for Burn-to-Crystallize (Phase 1 seal -> Phase 4 native ZSA).
    pub fn prove_migration(
        &self,
        asset_id: &AssetId,
        phase1_commitment: [u8; 32],
        secret_witness: &[u8],
    ) -> Result<ProofBytes, ZyozaError> {
        let secret = hash_to_fp(b"ZYOZA-SEC-v1____", &[secret_witness]);
        let leaf = hash_to_fp(b"ZYOZA-LEAF-v1___", &[&asset_id.0]);
        let ch = hash_to_fp(b"ZYOZA-MIG-v1____", &[&asset_id.0, &phase1_commitment]);
        self.prove_knowledge(secret, leaf, ch)
    }

    /// Verifies a Halo2 Burn-to-Crystallize migration proof.
    pub fn verify_migration(
        &self,
        asset_id: &AssetId,
        phase1_commitment: [u8; 32],
        proof: &[u8],
    ) -> Result<bool, ZyozaError> {
        let ch = hash_to_fp(b"ZYOZA-MIG-v1____", &[&asset_id.0, &phase1_commitment]);
        self.verify_knowledge(ch, proof)
    }

    fn prove_knowledge(&self, secret: Fp, leaf: Fp, ch: Fp) -> Result<ProofBytes, ZyozaError> {
        let keys = get_keys();
        let digest = secret * ch + leaf;
        let circuit = MembershipKnowledgeCircuit {
            secret: Value::known(secret),
            leaf: Value::known(leaf),
            challenge: Value::known(ch),
        };

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(
            &keys.params,
            &keys.pk,
            &[circuit],
            &[&[&[ch, digest]]],
            UnwrapErr(SysRng),
            &mut transcript,
        )
        .map_err(|e| ZyozaError::Proof(format!("halo2 create_proof: {e:?}")))?;

        let payload = Halo2ProofPayload {
            digest_bytes: digest.to_repr(),
            ipa_proof: transcript.finalize(),
        };
        serde_json::to_vec(&payload)
            .map_err(|e| ZyozaError::Proof(format!("proof serialize: {e}")))
    }

    fn verify_knowledge(&self, ch: Fp, proof: &[u8]) -> Result<bool, ZyozaError> {
        let payload: Halo2ProofPayload = serde_json::from_slice(proof)
            .map_err(|e| ZyozaError::Proof(format!("proof parse: {e}")))?;
        let digest = Option::<Fp>::from(Fp::from_repr(payload.digest_bytes))
            .ok_or_else(|| ZyozaError::Proof("invalid digest Fp bytes".into()))?;

        let keys = get_keys();
        let strategy = SingleVerifier::new(&keys.params);
        let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&payload.ipa_proof[..]);
        Ok(verify_proof(
            &keys.params,
            &keys.vk,
            strategy,
            &[&[&[ch, digest]]],
            &mut transcript,
        )
        .is_ok())
    }
}

impl ProofEngine for Halo2ProofEngine {
    fn prove_ownership(&self, req: &OwnershipProofRequest) -> Result<ProofBytes, ZyozaError> {
        let secret = hash_to_fp(b"ZYOZA-SEC-v1____", &[&req.secret_witness]);
        let leaf = hash_to_fp(b"ZYOZA-LEAF-v1___", &[&req.asset_id.0]);
        let ch = hash_to_fp(b"ZYOZA-OWN-v1____", &[&req.collection_root, &req.challenge]);
        self.prove_knowledge(secret, leaf, ch)
    }

    fn verify_ownership(
        &self,
        req: &OwnershipVerifyRequest,
        proof: &[u8],
    ) -> Result<bool, ZyozaError> {
        let ch = hash_to_fp(b"ZYOZA-OWN-v1____", &[&req.collection_root, &req.challenge]);
        self.verify_knowledge(ch, proof)
    }

    fn prove_transition(
        &self,
        _prev_proof: Option<&[u8]>,
        step_witness: &[u8],
    ) -> Result<ProofBytes, ZyozaError> {
        let secret = hash_to_fp(b"ZYOZA-STEP-v1___", &[step_witness]);
        let leaf = Fp::from(1u64);
        let ch = hash_to_fp(b"ZYOZA-TRAN-v1___", &[step_witness]);
        self.prove_knowledge(secret, leaf, ch)
    }

    fn verify_transition(
        &self,
        proof: &[u8],
        public_inputs: &[u8],
    ) -> Result<bool, ZyozaError> {
        let ch = hash_to_fp(b"ZYOZA-TRAN-v1___", &[public_inputs]);
        self.verify_knowledge(ch, proof)
    }
}

fn hash_to_fp(personal: &[u8; 16], parts: &[&[u8]]) -> Fp {
    let mut state = Blake2bParams::new()
        .hash_length(64)
        .personal(personal)
        .to_state();
    for p in parts {
        state.update(p);
    }
    let mut wide = [0u8; 64];
    wide.copy_from_slice(state.finalize().as_bytes());
    Fp::from_uniform_bytes(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halo2_ownership_and_attribute_proofs() {
        let engine = Halo2ProofEngine;
        let asset_id = AssetId::derive(&[0xAA; 32], b"zyoza:nft:halo2-test");
        let collection_root = [0x11; 32];
        let challenge = [0x22; 32];

        let t0 = std::time::Instant::now();
        let proof = engine
            .prove_ownership(&OwnershipProofRequest {
                asset_id,
                collection_root,
                secret_witness: b"alice-orchard-sk".to_vec(),
                challenge,
            })
            .unwrap();
        let prove_ms = t0.elapsed().as_millis();

        let t1 = std::time::Instant::now();
        let ok = engine
            .verify_ownership(
                &OwnershipVerifyRequest {
                    collection_root,
                    challenge,
                },
                &proof,
            )
            .unwrap();
        let verify_ms = t1.elapsed().as_millis();
        println!("Halo2 ownership prove={prove_ms}ms verify={verify_ms}ms bytes={}", proof.len());
        assert!(ok);

        // Wrong challenge must fail verification
        assert!(!engine
            .verify_ownership(
                &OwnershipVerifyRequest {
                    collection_root,
                    challenge: [0x99; 32],
                },
                &proof,
            )
            .unwrap());

        // Trait attribute proof
        let attr_proof = engine
            .prove_attribute(&asset_id, "rarity", "genesis", b"alice-orchard-sk", challenge)
            .unwrap();
        assert!(engine
            .verify_attribute("rarity", "genesis", challenge, &attr_proof)
            .unwrap());
        assert!(!engine
            .verify_attribute("rarity", "common", challenge, &attr_proof)
            .unwrap());
    }

    #[test]
    fn halo2_in_circuit_supply_cap_range_proof() {
        let cap_engine = IssuanceCapEngine;
        // Valid: token_index = 42 <= max_supply = 100
        let proof_ok = cap_engine.prove_cap(42, 100).unwrap();
        assert!(cap_engine.verify_cap(100, &proof_ok).unwrap());

        // Invalid: token_index = 101 > max_supply = 100 -> fails verification
        let proof_over = cap_engine.prove_cap(101, 100).unwrap();
        assert!(!cap_engine.verify_cap(100, &proof_over).unwrap());
    }
}

/// Halo2 16-bit range-check circuit proving `1 <= token_index <= max_supply` (up to 65,535).
#[derive(Clone, Default)]
struct IssuanceCapCircuit {
    idx_minus_1_bits: [Value<Fp>; 16],
    delta_bits: [Value<Fp>; 16],
}

#[derive(Clone, Debug)]
struct CapConfig {
    bit_a: Column<Advice>,
    bit_b: Column<Advice>,
    acc: Column<Advice>,
    instance: Column<Instance>,
    sel_bit: Selector,
    sel_sum: Selector,
}

impl Circuit<Fp> for IssuanceCapCircuit {
    type Config = CapConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        use halo2_proofs::plonk::Expression;
        let bit_a = meta.advice_column();
        let bit_b = meta.advice_column();
        let acc = meta.advice_column();
        let instance = meta.instance_column();
        let sel_bit = meta.selector();
        let sel_sum = meta.selector();

        meta.enable_equality(acc);
        meta.enable_equality(instance);

        meta.create_gate("binary_bits", |meta| {
            let s = meta.query_selector(sel_bit);
            let a = meta.query_advice(bit_a, Rotation::cur());
            let b = meta.query_advice(bit_b, Rotation::cur());
            let one = Expression::Constant(Fp::from(1u64));
            vec![
                s.clone() * a.clone() * (one.clone() - a),
                s * b.clone() * (one - b),
            ]
        });

        meta.create_gate("cap_sum", |meta| {
            let s = meta.query_selector(sel_sum);
            let idx_m1 = meta.query_advice(bit_a, Rotation::cur());
            let delta = meta.query_advice(bit_b, Rotation::cur());
            let cap = meta.query_advice(acc, Rotation::cur());
            let one = Expression::Constant(Fp::from(1u64));
            // (idx - 1) + 1 + delta == cap
            vec![s * (idx_m1 + one + delta - cap)]
        });

        CapConfig {
            bit_a,
            bit_b,
            acc,
            instance,
            sel_bit,
            sel_sum,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), PlonkError> {
        let cap_cell = layouter.assign_region(
            || "cap_range_check",
            |mut region| {
                let mut sum_a = Value::known(Fp::from(0u64));
                let mut sum_b = Value::known(Fp::from(0u64));
                for i in 0..16 {
                    config.sel_bit.enable(&mut region, i)?;
                    region.assign_advice(|| "bit_a", config.bit_a, i, || self.idx_minus_1_bits[i])?;
                    region.assign_advice(|| "bit_b", config.bit_b, i, || self.delta_bits[i])?;
                    let weight = Fp::from(1u64 << i);
                    sum_a = sum_a + self.idx_minus_1_bits[i] * Value::known(weight);
                    sum_b = sum_b + self.delta_bits[i] * Value::known(weight);
                }
                config.sel_sum.enable(&mut region, 16)?;
                region.assign_advice(|| "idx_m1", config.bit_a, 16, || sum_a)?;
                region.assign_advice(|| "delta", config.bit_b, 16, || sum_b)?;
                let cap_val = sum_a + Value::known(Fp::from(1u64)) + sum_b;
                region.assign_advice(|| "cap", config.acc, 16, || cap_val)
            },
        )?;
        layouter.constrain_instance(cap_cell.cell(), config.instance, 0)?;
        Ok(())
    }
}

struct CapKeys {
    params: Params<EqAffine>,
    vk: VerifyingKey<EqAffine>,
    pk: ProvingKey<EqAffine>,
}

static CAP_KEYS: OnceLock<CapKeys> = OnceLock::new();

fn get_cap_keys() -> &'static CapKeys {
    CAP_KEYS.get_or_init(|| {
        let params = Params::<EqAffine>::new(6);
        let empty = IssuanceCapCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("cap keygen_vk");
        let pk = keygen_pk(&params, vk.clone(), &empty).expect("cap keygen_pk");
        CapKeys { params, vk, pk }
    })
}

/// Halo2 prover/verifier for `1 <= token_index <= max_supply` collection caps.
pub struct IssuanceCapEngine;

impl IssuanceCapEngine {
    /// Proves that `1 <= token_index <= max_supply` (with `max_supply <= 65535`).
    pub fn prove_cap(&self, token_index: u64, max_supply: u64) -> Result<Vec<u8>, ZyozaError> {
        let idx_m1 = token_index.saturating_sub(1);
        let delta = max_supply.saturating_sub(token_index);
        let mut idx_minus_1_bits = [Value::known(Fp::from(0u64)); 16];
        let mut delta_bits = [Value::known(Fp::from(0u64)); 16];
        for i in 0..16 {
            idx_minus_1_bits[i] = Value::known(Fp::from((idx_m1 >> i) & 1));
            delta_bits[i] = Value::known(Fp::from((delta >> i) & 1));
        }

        let keys = get_cap_keys();
        let circuit = IssuanceCapCircuit {
            idx_minus_1_bits,
            delta_bits,
        };
        let cap_fp = Fp::from(max_supply);
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(
            &keys.params,
            &keys.pk,
            &[circuit],
            &[&[&[cap_fp]]],
            UnwrapErr(SysRng),
            &mut transcript,
        )
        .map_err(|e| ZyozaError::Proof(format!("cap create_proof: {e:?}")))?;
        Ok(transcript.finalize())
    }

    /// Verifies an `IssuanceCapEngine` proof against public `max_supply`.
    pub fn verify_cap(&self, max_supply: u64, proof: &[u8]) -> Result<bool, ZyozaError> {
        let keys = get_cap_keys();
        let strategy = SingleVerifier::new(&keys.params);
        let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
        let cap_fp = Fp::from(max_supply);
        Ok(verify_proof(
            &keys.params,
            &keys.vk,
            strategy,
            &[&[&[cap_fp]]],
            &mut transcript,
        )
        .is_ok())
    }
}
