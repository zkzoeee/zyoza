//! Pure `tachyon-zcash/ragu` zero-knowledge proof crate for Zyoza.
//!
//! All recursive lineage folds, Poseidon-Merkle ownership proofs, 16-bit supply-cap
//! range checks, selective trait proofs, and Stage I -> Stage II ZSA migration proofs
//! execute inside a single unified `ragu::Application<'static, Pasta, WalletRank, 5>`.

pub mod ragu_pcd;

pub use ragu;
pub use ragu_pcd::{
    bytes_to_ragu_fp, compressed_proof_len, poseidon_1, poseidon_2, AttributeHeader, CapHeader,
    CollectionMerkleTree, IssuanceCapEngine, LineageHeader, MigrationHeader, OwnershipHeader,
    RaguAttributeProof, RaguMigrationProof, RaguPcdEngine, RaguPcdProof, RaguStepKind,
    RaguStepWitness, MERKLE_DEPTH,
};
pub use zyoza_core;
