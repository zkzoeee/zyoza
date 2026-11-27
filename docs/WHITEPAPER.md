# Zyoza: Proof-Carrying Shielded State Objects for Zcash

**Author:** `zkzoeee`  
**Date:** November 2026 · **Version:** 2.0  
**Status:** *Research prototype — real `tachyon-zcash/ragu` recursive PCD (`7,168 B` constant `CompressedProof<Pasta>`), Halo2 IPA, Pallas ECDH, and ChaCha20-Poly1305 cryptography running over a simulated in-memory settlement ledger. Not audited.*

---

## Abstract
Public blockchains expose the entire ownership graph, bid history, and metadata of non-fungible assets. Conversely, Zcash’s shielded protocols—**Orchard**, **Zcash Shielded Assets (ZSA, ZIP 226/227)**, and **Project Tachyon**—preserve financial privacy by keeping consensus intentionally minimal, omitting on-chain media storage, arbitrary state machines, and public indexers.

**Zyoza** bridges this gap without adding permanent state bloat to Zcash L1. Encrypted payloads travel out-of-band (`zyoza-oob`), heterogeneous lifecycle rules fold recursively via **`tachyon-zcash/ragu`** non-uniform Proof-Carrying Data (`zyoza-proofs`), and anti-double-spend commitments anchor to Zcash (`zyoza-settlement`). Every Zyoza object derives a **ZIP 227-aligned `AssetDigest` / `AssetBase`** from day one, enabling Stage I single-use seals to upgrade 1:1 into native Stage II ZSA notes and Stage III Tachyon bundles.

---

## 1. Implementation Status Matrix

To distinguish implemented cryptography from simulated ledger components and future design targets, the reference workspace (`./zyoza`, 13 Rust crates) maintains the following boundaries:

| Component | Status | What Runs in the Reference Code |
| :--- | :--- | :--- |
| **Ragu Non-Uniform Recursive PCD** (`zyoza-proofs`) | **Implemented** | Real `tachyon-zcash/ragu` (`Application<Pasta, WalletRank, 5>`) with 7 registered `Step<Pasta>` circuits (`seed`, `fuse`, `compress`, `verify_compressed`) and in-circuit state contiguity. |
| **Poseidon-Merkle Ownership Proofs** (`zyoza-proofs`) | **Implemented** | Ragu `OwnershipMerkleCircuit` proving depth-4 Poseidon Merkle inclusion + owner secret preimage + fresh verifier challenge. |
| **Supply-Cap Range Proof** (`zyoza-proofs`) | **Implemented** | Halo2 (`k = 6`, Pasta) 16-bit binary decomposition proving $1 \le \text{token\_index} \le \text{max\_supply}$. |
| **ZIP 302 Binary Memo Codec & ZIP 227 Digest** (`zyoza-core`) | **Implemented** | 512-byte `[0xFF, 'Z', 'Y', 'O', 'Z', ...]` codec, `BLAKE2b-512("ZSA-Asset-Digest")`, Pallas `GroupHash("z.cash:OrchardZSA")`, and `CollectionSpec` nullifiers. |
| **Out-of-Band AEAD & Pallas ECDH Re-Wrap** (`zyoza-oob`) | **Implemented** | `ChaCha20Poly1305` payload encryption + ephemeral Pallas ECDH + HKDF-SHA256 32-byte DEK re-wrapping + seed-derived backups. |
| **Commit-Reveal Sealed Bids** (`apps/gallery-demo`) | **Implemented** | `BLAKE2b-256` salted bid commitments; bid amounts remain hidden until the reveal phase. |
| **Threshold Schnorr Issuer Signing** (`zyoza-settlement`) | **Implemented (Trusted Dealer)** | 2-round `t-of-n` Lagrange-interpolated Schnorr signing on Pallas; uses `keygen_dealer` (interactive DKG is a design target). |
| **Orchard / ZSA / Tachyon Ledgers** (`zyoza-settlement`) | **Simulated** | Real `orchard` key/address derivation paired with in-memory commitment/nullifier ledgers and a JSON-RPC mock transport; not yet wired to `zebrad`/`lightwalletd`. |
| **Post-Quantum Hybrid KEM (`ML-KEM-768`)** | **Design Target** | Planned hybrid HKDF combiner alongside Pallas ECDH for multi-decade archival objects; not yet wired to an `ml-kem` crate. |
| **Trustless PCZT ZEC <-> Zyoza Atomic Swap** | **Design Target** | Planned 2-party Partially Constructed Zcash Transaction flow; Studio currently executes post-clear handoff in memory. |

---

## 2. Verification & Enforcement Model: Who Checks What?

A central question in any client-side validated (CSV) protocol on a shielded chain is **who enforces uniqueness and retirement when consensus nodes know nothing about Zyoza** and memos are encrypted to recipients.

### 2.1 How a Buyer Verifies Lineage Across Encrypted Memos
Zcash validators only verify Orchard note validity and Orchard nullifier non-reuse—they never inspect the 512-byte memo. Enforcement therefore happens at the **recipient / verifier boundary** before a buyer accepts an asset or co-signs payment:
1. **Recursive Ragu PCD Proof (`zyoza-proofs`):** Rather than revealing raw historical notes or prior owners’ viewing keys, the seller hands the buyer a succinct `CompressedProof<Pasta>` from `RaguPcdEngine` attesting that every transition from `MintCircuit` through intermediate `TransferCircuit` / `RoyaltyCircuit` steps satisfied the registered subcircuit constraints.
2. **Current Unspent Seal Opening:** For the *current* tip, the seller reveals the opening witness linking the live Orchard note to the 512-byte seal commitment, and transfers the object by spending that exact Orchard note (publishing its L1 Orchard nullifier) while creating the buyer’s new note. Once that transaction mines, Zcash consensus itself prevents the seller from spending the retired Orchard note again.

### 2.2 Who Enforces `CollectionSpec` Mint Nullifiers (`NF_aid`, `NF_idx`, `NF_med`)?
While spending an existing Orchard note prevents transfer double-spends, **minting** requires preventing a creator from silently issuing two genesis notes for slot `#42`.
* **In Stage I (Pre-ZSA):** Because Orchard memos are private, `NF_aid`, `NF_idx`, and `NF_med` **cannot** remain hidden inside encrypted memos if buyers want global uniqueness guarantees. Stage I deployments must anchor these 32-byte deterministic mint nullifiers into a **publicly auditable bulletin stream** (e.g., transparent Zcash `OP_RETURN` outputs or a shared indexer log) so every buyer’s client can verify that slot `#42` was claimed exactly once and matches the creator’s `CollectionSpec`. *(In our prototype, `OrchardSealAdapter` simulates this shared nullifier set in memory.)*
* **In Stage II (Native ZSA, ZIP 226/227):** Supply enforcement moves **directly into Zcash L1 consensus**. ZIP 227 Issuance Bundles publicly commit total issued supply per `AssetDigest` and support `finalize = true`, so every Zcash full node rejects duplicate `1/1` mints natively without an external indexer.

---

## 3. Identity, ZIP 302 Memo Layout, and Out-of-Band Wrapping

### 3.1 ZIP 227-Aligned `AssetDigest` and `AssetBase`
Following ZIP 227, Zyoza hashes the description with `BLAKE2b-256("ZSA-AssetDescCRH")`, prefixes version byte `0x00` and the issuer key, hashes the canonical encoding with `BLAKE2b-512("ZSA-Asset-Digest")` to obtain the 64-byte `AssetDigest`, and maps it onto Pallas:
$$\text{assetDescHash} = \text{BLAKE2b-256}_{\text{"ZSA-AssetDescCRH"}}(\text{asset\_desc})$$
$$\text{AssetDigest} = \text{BLAKE2b-512}_{\text{"ZSA-Asset-Digest"}}([0\text{x}00] \parallel \text{ik} \parallel \text{assetDescHash})$$
$$\text{AssetBase} = \text{GroupHash}^{\mathbb{P}}_{\text{"z.cash:OrchardZSA"}}(\text{AssetDigest})$$
Stage I memo seals carry `AssetId = AssetDigest[0..32]` as a compact 32-byte key while preserving the full derivation for Stage II ZSA crystallization.

### 3.2 ZIP 302 Binary Memo Layout (`0xFF` Prefix)
Per **ZIP 302**, memos beginning with bytes `< 0xF5` are interpreted by Zcash wallets as UTF-8 text, whereas **`0xFF` designates arbitrary application binary data**. Zyoza’s 512-byte seal begins with `[0xFF, 'Z', 'Y', 'O', 'Z']` so standard wallets never display raw binary seals as garbled text:

| Bytes | Size | Field | Purpose |
| :--- | :--- | :--- | :--- |
| `0..5` | `5 B` | `magic` | `[0xFF, 'Z', 'Y', 'O', 'Z']` (ZIP 302 arbitrary binary marker + tag) |
| `5..7` | `2 B` | `version` | `0x0001` (`u16` big-endian) |
| `7..11` | `4 B` | `profile_id` | Vertical tag (`NFT1`, `TKT1`, `CRD1`, `GAM1`, `RWA1`) |
| `11..43` | `32 B` | `asset_id` | `AssetDigest[0..32]` |
| `43..75` | `32 B` | `state_root` | `SHA-256` commitment to canonical profile state |
| `75..107` | `32 B` | `nonce` | Per-transition randomness |
| `107..139` | `32 B` | `oob_pointer_hash` | `BLAKE2b-256` integrity hash of the `OobEnvelope` |
| `139..141` | `2 B` | `oob_uri_len` | UTF-8 byte length (`0..=371`) |
| `141..512` | `371 B` | `oob_uri_bytes` | Off-chain URI/CID (zero-padded) |

### 3.3 O(1) Bandwidth DEK Re-Wrapping & Data Availability
Payloads are encrypted once under a random 256-bit `ChaCha20Poly1305` Data Encryption Key (`DEK`) with `AAD = AssetId`. Transfers (`rewrap_for_recipient`) unwrap the 32-byte `DEK` and re-encapsulate it via ephemeral Pallas ECDH + `HKDF-SHA256` to the recipient’s public key—moving large media files without re-uploading ciphertext.
* **Data Availability Assumption:** Because Zcash L1 stores no payload data, losing the `OobEnvelope` renders an asset unspendable in CSV workflows (analogous to RGB). Zyoza mitigates this via content-addressed pinning (IPFS/Arweave) plus `encrypt_backup(wallet_seed, state)` snapshots recoverable from the holder’s seed phrase.

---

## 4. Ragu Non-Uniform Recursive PCD (`zyoza-proofs`)

Zyoza integrates **`tachyon-zcash/ragu`** (`Application<'static, Pasta, WalletRank, 5>` at `WalletRank = R<13>`, no trusted setup) to turn static tokens into proof-carrying state objects:

1. **Non-Uniform Registered Subcircuits & Contiguity Header:** Rather than one monolithic circuit, Zyoza registers specialized `Step<Pasta>` implementations over a 4-element `LineageHeader` (`[asset_id, genesis_commitment, latest_commitment, lineage_acc]`):
   * `MintCircuit` (`Index 1`): Seeds `LineageHeader` via Ragu’s in-circuit Poseidon `Sponge` over `(profile, asset_id, commitment, secret)`.
   * `TransferCircuit` (`Index 2`): Enforces in-circuit asset invariance (`left.asset == witness.asset`) and state contiguity (`left.latest == witness.prev_commit`) before fusing `Pcd<Pasta, WalletRank, LineageHeader>`.
   * `RoyaltyCircuit` (`Index 3`): Allocates `royalty_required` and `royalty_paid` via `ragu::primitives::Boolean`, enforces `royalty_required && !royalty_paid == 0` in-circuit, and fuses the prior lineage proof.
   * `TicketCheckInCircuit` (`Index 4`) & `UpgradeCircuit` (`Index 5`): Compute in-circuit Poseidon event check-in nullifiers (`TKT1`) and item upgrades (`GAM1`), enabling cross-profile folding on a single asset.
2. **Poseidon-Merkle ZK Ownership (`OwnershipMerkleCircuit`, `Index 6`):** Proves in zero knowledge that `leaf = Poseidon(asset_id, Poseidon(secret))` resolves via a depth-4 Merkle path to a public `collection_root`, bound to a fresh verifier `challenge` (`OwnershipHeader = Poseidon(root, challenge)`). Unlisted assets, wrong secrets, or replayed challenges fail `verify_compressed`.

---

## 5. Stage III (Tachyon): What Replaces the Stage I Memo?

Project Tachyon achieves planetary scale in part by **removing in-band secret distribution (eliminating 512-byte on-chain encrypted memos)** in favor of out-of-band note transmission and compact 32-byte **tachygrams** (uniform field elements representing commitments and nullifiers).

Because Zyoza *already* delivers encrypted payloads and Ragu proofs out-of-band in Stage I (`zyoza-oob`), transitioning to Tachyon requires **no application-layer redesign**:
* The 9-field header previously serialized into the 512-byte Orchard memo simply moves inside the out-of-band `OobEnvelope` transmitted peer-to-peer (e.g., via encrypted relay or URI).
* On-chain consensus receives **only** the 32-byte `Tachygram = Poseidon/BLAKE2b(asset_id, state_commitment)`, aggregated into 32-byte epoch `Tachystamp` roots and verified by mobile wallets via prunable $O(\log N)$ Merkle paths (`TachyonAdapter`).

---

## 6. Trust Assumptions & Threat Model

1. **FROST Crystallization Committee:** Upgrading a Stage I seal into a Stage II native ZSA note requires signing a ZIP 227 Issuance Bundle under the collection’s `issuer_key`. To avoid a single hot-key rug-pull, Zyoza splits `issuer_key` across a `t-of-n` (`2-of-3`) Pallas threshold committee—typically *(1) the collection creator, (2) an independent crystallization relayer, and (3) a community/auditor cosigner*—which co-signs issuance only upon verifying `prove_migration` and Stage I burn confirmation. *(Prototype note: `frost_issuer.rs` currently uses trusted-dealer Shamir setup `keygen_dealer`; production deployments require interactive FROST DKG.)*
2. **Marketplace Privacy & Front-Running:** `ObjectViewingKey` (`OVK`) scopes metadata disclosure to a single `AssetId` rather than the seller’s wallet viewing key. Sealed bids use salted `BLAKE2b-256` commitments (`commit -> reveal -> clear`), hiding bid values during the bidding window, though revealed bids become visible to the gallery operator at clearing time unless paired with MPC/FHE or blind escrow.
3. **Host vs. Circuit Completeness:** While `RoyaltyCircuit`, `OwnershipMerkleCircuit`, and `IssuanceCapEngine` enforce their core predicates in-circuit, complex string/JSON schema checks in `zyoza-profile-*` currently execute in Rust host code and remain future candidates for full Ragu gadget compilation.

---

## 7. Related Work

* **RGB & Taproot Assets (Bitcoin CSV):** Pioneered anchoring off-chain asset state to L1 single-use seals, but require linear $O(H)$ client-side DAG history validation that leaks past state transitions to subsequent recipients. Zyoza replaces DAG replay with constant-size recursive Ragu PCD proofs.
* **Shielded CSV (Nick, Eagen, Linus — ePrint 2025/085):** Formalized combining L1 nullifiers with recursive PCD to eliminate history leakage in client-side validation. Zyoza adapts this paradigm specifically to Zcash’s Pasta curves, ZIP 227 asset identity, and Tachyon roadmap.
* **ZIP 226 & ZIP 227 (OrchardZSA):** Provide consensus-enforced custom asset balances and atomic swaps on Zcash, which Zyoza complements with out-of-band encrypted media, per-object viewing keys, and programmable multi-vertical rules.

---

## 8. References

1. Sean Bowe, Jack Grigg, Daira-Emma Hopwood. *Halo: Recursive Proof Composition without a Trusted Setup.* IACR ePrint 2019/1021.
2. Sean Bowe et al. *Ragu: Proof-Carrying Data Framework for Project Tachyon.* `https://github.com/tachyon-zcash/ragu` (2025–2026).
3. Sean Bowe. *Project Tachyon: Planetary-Scale Shielded Zcash.* Electric Coin Company / Tachyon ResearchPosts (2025–2026).
4. Pablo Kogan, Vivek Arte, Daniel Benarroch, Jack Grigg, Daira-Emma Hopwood, Str4d. *ZIP 226: Transfer and Burn of Zcash Shielded Assets* & *ZIP 227: Issuance of Zcash Shielded Assets.* `https://zips.z.cash/`.
5. Brad Miller, Jack Grigg. *ZIP 302: Standardized Memo Field Format.* `https://zips.z.cash/zip-0302`.
6. Chelsea Komlo, Ian Goldberg. *FROST: Flexible Round-Optimized Schnorr Threshold Signatures.* SAC 2020 / RFC 9591.
7. Jonas Nick, Liam Eagen, Robin Linus. *Shielded CSV: Private and Efficient Client-Side Validation.* IACR ePrint 2025/085.
