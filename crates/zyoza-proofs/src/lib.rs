//! Pure `tachyon-zcash/ragu` zero-knowledge proof crate for Zyoza.
//!
//! All recursive lineage folds, Poseidon-Merkle ownership proofs, 16-bit supply-cap
//! range checks, committed trait proofs, and Stage I -> Stage II ZSA migration proofs
//! execute inside a single unified `ragu::Application<'static, Pasta, WalletRank, 12>`
//! hosted on one dedicated prover thread.

pub mod ragu_pcd;

pub use ragu;
pub use ragu_pcd::{
    bytes_to_ragu_fp, compressed_proof_len, derive_creator_tag, derive_owner_tag, poseidon_1,
    poseidon_2, warmup_prover, AttributeHeader, CapHeader, CollectionMerkleTree, IssuanceCapEngine,
    LineageHeader, MigrationHeader, OwnershipHeader, RaguCapProof, RaguMigrationProof,
    RaguPcdEngine, RaguPcdProof, RaguStepKind, RaguStepWitness, TraitMerkleTree, LINEAGE_SLOTS,
    MERKLE_DEPTH,
};
pub use zyoza_core;
