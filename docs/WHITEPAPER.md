# Zyoza: Proof-Carrying Shielded State Objects for Zcash

**Author:** `zkzoeee`  
**Date:** November 2026 · **Version:** 2.1  
**Status:** *Research prototype — unified 10-circuit `tachyon-zcash/ragu` PCD & ZK suite (`6,208 B` `CompressedProof<Pasta>`), Pallas ECDH, and ChaCha20-Poly1305 cryptography running over a simulated in-memory settlement ledger. Not audited.*

---

## Abstract
Public blockchains expose the entire ownership graph, bid history, and metadata of non-fungible assets. Conversely, Zcash’s shielded protocols—**Orchard**, **Zcash Shielded Assets (ZSA, ZIP 226/227)**, and **Project Tachyon**—preserve financial privacy by keeping consensus intentionally minimal, omitting on-chain media storage, arbitrary state machines, and public indexers.

**Zyoza** bridges this gap without adding permanent state bloat to Zcash L1. Encrypted payloads travel out-of-band (`zyoza-oob`), heterogeneous lifecycle rules fold recursively via **`tachyon-zcash/ragu`** non-uniform Proof-Carrying Data (`zyoza-proofs`), and anti-double-spend commitments anchor to Zcash (`zyoza-settlement`). Every Zyoza object derives a **ZIP 227-aligned `AssetDigest` / `AssetBase`** from genesis, enabling Stage I single-use seals to upgrade 1:1 into native Stage II ZSA notes and Stage III Tachyon bundles.

---

## 1. Implementation & Statement-Binding Matrix

To separate **circuit existence** from **end-to-end statement binding** and **simulated settlement**, the 13-crate workspace (`./zyoza`) maintains the following boundaries:

| Component | Circuit / Code Exists | Statement Binding & Remaining Prototype Limits |
| :--- | :--- | :--- |
| **Recursive Lineage (`LineageHeader`)** | **Yes** (`Index 1..5`, 10-slot header) | **Bound to owner & header metadata:** Every fold checks `Poseidon(secret) == prior.owner_tag`, enforces commitment contiguity, verifies `step_count`/`last_step`/`last_profile` in-header, and exposes `event_nullifier = Poseidon(asset, event_id)` on ticket check-ins. The nullifier depends only on the object and the event, so a ticket yields one nullifier per event whoever holds it; a gate recomputes it for its own event and refuses one it has seen. *Limit:* Owner tags use off-chain secrets rather than Orchard spend-auth keys; uncompressed fold proofs are not yet unlinkable in upstream Ragu (§4.2). |
| **Royalty Gate (`RoyaltyCircuit`)** | **Yes** (`Index 3` + sticky `SLOT_ROYALTY_REQ`) | **Sticky routing + creator receipt preimage:** `TransferCircuit` enforces `royalty_req == 0` so royalty-bearing assets cannot skip `RoyaltyCircuit`, which requires `Poseidon(ack_secret) == creator_tag`. *Limit:* Proves creator/escrow receipt co-authorization, **not** trustless L1 ZEC movement (which requires Stage II PCZT atomic swaps). |
| **Supply Cap (`IssuanceCapCircuit`)** | **Yes** (`Index 7`, `enforce_le::<16>`) | **Bound to `(collection_id, asset_id)`:** Outputs `[col_id, asset_id, slot_commitment, max_supply]` and runs on every Studio mint. *Limit:* Prevents out-of-range indices (`0` or `> cap`); global slot uniqueness across distinct mints still relies on the Stage I `NF_idx` log (or Stage II ZSA consensus). |
| **Poseidon-Merkle Ownership (`OwnershipMerkleCircuit`)** | **Yes** (`Index 6`, depth-4 Merkle) | **Bound to `(collection_root, state_root, challenge)`:** `GalleryService` checks authoritative multi-holder roots, binds the listed `NftState::state_root()`, and consumes one-time server CSPRNG challenges on `submit_listing`. |
| **Selective Trait (`AttributeCircuit`)** | **Yes** (`Index 8`, depth-4 `TraitMerkleTree`) | **Bound to `(asset_id, traits_root, owner_tag, challenge)`:** Proves `(key, val)` resolves to a committed `traits_root`. *Limit:* Verifier must obtain `traits_root` from an issuer-signed manifest or registered state root. |
| **ZSA Burn Migration (`MigrationCircuit`)** | **Yes** (`Index 9`) | **Bound to `(asset_id, phase1_commitment, owner_tag)`:** Enforces `Poseidon(secret) == owner_tag` from the verified lineage proof before deriving `burn_nullifier`. |
| **Browser-Hashed Commit-Reveal Bids** | **Yes** (`SHA-256` WebCrypto + `GalleryService`) | **Client-side commitment:** Browser hashes `(listing_id, bidder, zats, salt)` locally and sends only the 32B hash on commit; amount & salt remain local until reveal. |
| **Orchard Note <-> Seal Opening** | **Design Target** (Not in code) | Linking an on-chain Orchard note commitment `cm_x` to Zyoza’s 512B memo seal inside a circuit is a future design target; current adapters track commitments in memory. |
| **Orchard / ZSA / Tachyon Ledgers & FROST** | **Simulated** (`zyoza-settlement`) | Real `orchard` address derivation and 2-of-3 Pallas Schnorr signing (`keygen_dealer` trusted dealer; DKG is a design target) over in-memory nullifier/commitment maps. |
| **Post-Quantum Hybrid KEM (`ML-KEM-768`)** | **Design Target** (Not in code) | Planned hybrid HKDF combiner alongside Pallas ECDH; current `zyoza-oob` uses classical Pallas ECDH + `HKDF-SHA256`. |

---

## 2. Verification & Enforcement Model: Who Checks What?

### 2.1 Buyer & Gallery Verification Across Encrypted Memos
Zcash validators verify Orchard note validity and nullifiers without inspecting 512-byte memos. Verification therefore occurs at the **recipient / gallery boundary**:
1. **Lineage & Current Commitment Check:** Before listing (`Step 04`) or crystallizing (`Step 06`), the verifier runs `RaguPcdEngine::verify_pcd` over the `6,208 B` `CompressedProof<Pasta>` (verifying all 10 `LineageHeader` slots) and checks that `latest_commitment` matches the active ledger seal commitment.
2. **Orchard Note Opening *(Design Target)*:** In a live mainnet wallet integration, the seller must also prove that an unspent Orchard note they are spending in the transfer transaction commits to the 512-byte Zyoza memo seal (either by revealing the note/memo viewing opening to the buyer over a private channel or via a future Orchard-action linkage gadget). In the current prototype, `OrchardSealAdapter` simulates this single-use seal retirement in memory.

### 2.2 Who Enforces `CollectionSpec` Mint Nullifiers (`NF_aid`, `NF_idx`, `NF_med`)?
* **Stage I (Pre-ZSA):** Because Orchard memos are private, `NF_aid`, `NF_idx`, and `NF_med` cannot remain hidden inside encrypted memos if buyers want global uniqueness guarantees. Stage I deployments must publish these 32-byte deterministic nullifiers to a **publicly auditable bulletin / indexer stream** so clients verify that slot `#k` was claimed once under `CollectionSpec`, paired with `IssuanceCapCircuit` proving $1 \le k \le \text{max\_supply}$.
* **Stage II (Native ZSA, ZIP 226/227):** Supply caps and `finalize = true` move **directly into Zcash L1 consensus**.

---

## 3. Identity, ZIP 302 Memo Layout, and Out-of-Band Wrapping

### 3.1 ZIP 227-Aligned `AssetDigest` and `AssetBase`
$$\text{assetDescHash} = \text{BLAKE2b-256}_{\text{"ZSA-AssetDescCRH"}}(\text{asset\_desc})$$
$$\text{AssetDigest} = \text{BLAKE2b-512}_{\text{"ZSA-Asset-Digest"}}([0\text{x}00] \parallel \text{ik} \parallel \text{assetDescHash})$$
$$\text{AssetBase} = \text{GroupHash}^{\mathbb{P}}_{\text{"z.cash:OrchardZSA"}}(\text{AssetDigest})$$
Stage I memo seals store `AssetId = AssetDigest[0..32]` while preserving the full 64-byte `AssetDigest` derivation for Stage II ZSA crystallization.

### 3.2 ZIP 302 Binary Memo Layout (`0xFF` Prefix)
Per **ZIP 302**, a leading `0xFF` marks arbitrary application binary data so Zcash wallets never parse binary seals as UTF-8 text:

| Bytes | Size | Field | Purpose |
| :--- | :--- | :--- | :--- |
| `0..5` | `5 B` | `magic` | `[0xFF, 'Z', 'Y', 'O', 'Z']` |
| `5..7` | `2 B` | `version` | `0x0001` (`u16` BE) |
| `7..11` | `4 B` | `profile_id` | Vertical tag (`NFT1`, `TKT1`, `CRD1`, `GAM1`, `RWA1`) |
| `11..43` | `32 B` | `asset_id` | `AssetDigest[0..32]` |
| `43..75` | `32 B` | `state_root` | `SHA-256` commitment to canonical profile state |
| `75..107` | `32 B` | `nonce` | Fresh CSPRNG per-transition randomness |
| `107..139` | `32 B` | `oob_pointer_hash` | `BLAKE2b-256` integrity hash of the `OobEnvelope` |
| `139..141` | `2 B` | `oob_uri_len` | UTF-8 byte length (`0..=371`) |
| `141..512` | `371 B` | `oob_uri_bytes` | Off-chain URI/CID (zero-padded) |

### 3.3 O(1) DEK Re-Wrapping & Data Availability
Payloads encrypt once under a 256-bit `ChaCha20Poly1305` `DEK` (`AAD = AssetId`). Transfers (`rewrap_for_recipient`) unwrap only the 32-byte `DEK` and re-encapsulate it via fresh OS-random ephemeral Pallas ECDH + `HKDF-SHA256`. Off-chain availability relies on IPFS/Arweave pinning plus `encrypt_backup(wallet_seed, state)` snapshots.

---

## 4. Ragu Architecture & Upstream Privacy Caveat (`zyoza-proofs`)

### 4.1 Single Dedicated Prover Thread + Multi-Core Rayon
`ragu::Application<'static, Pasta, WalletRank, 12>` synthesizes baked Pallas/Vesta recursion tables (`~4.8 s` cold initialization). Rather than rebuilding `Application` per async worker thread, `zyoza-proofs` hosts a single long-lived prover thread (`zyoza-ragu-prover`) warmed on boot and invoked via `tokio::task::spawn_blocking`, while Ragu’s native `multicore` (`rayon`) feature parallelizes polynomial arithmetic across CPU cores.

### 4.2 Important Privacy Caveat: Compressed vs. Uncompressed Ragu Proofs
Upstream **`tachyon-zcash/ragu`** distinguishes two proof representations:
1. **`CompressedProof<Pasta>` (`6,208 bytes`):** Presented to terminal verifiers (galleries, ticket gates, crystallization committees) and verified via `Application::verify_compressed`. Third-party verifiers learn **only** the public `Header` elements (§5) and nothing about intermediate witnesses.
2. **Uncompressed `Proof<Pasta, WalletRank>`:** Required as an input to `Application::fuse` when a subsequent owner extends the lineage. **As documented in upstream Ragu today, uncompressed `Proof` objects are not zero-knowledge and `rerandomize` is not yet unlinkable.** Consequently, Zyoza does **not** yet claim unlinkable history hiding against *future* downstream owners who receive the uncompressed proof to continue folding; full inter-owner unlinkability awaits upstream Ragu’s zero-knowledge rerandomization layer.

---

## 5. Public Statements: Exact Verifier Guarantee Per Proof

Every proof verified by `Application::verify_compressed` checks a typed `Header<Fp>` (`Suffix 0..4`). A verifier learns and checks **exact** public slots—nothing more and nothing less:

| Header (`Suffix`) | Public Inputs Checked by Verifier | Private Witness | Exact In-Circuit Statement Proven |
| :--- | :--- | :--- | :--- |
| **`LineageHeader` (`0`)** *(10 $\mathbb{F}_p$ slots)* | `[asset, genesis_cmt, latest_cmt, owner_tag, step_count, last_kind, last_prof, royalty_req, creator_tag, event_nf]` | `owner_secret`, `prev_cmt` opening, optional `creator_ack_secret` | Valid chain of `step_count` registered steps from `genesis_cmt` to `latest_cmt` for `asset`; every hop proved knowledge of prior `owner_tag` preimage; `TransferCircuit` allowed iff `royalty_req == 0`; `RoyaltyCircuit` checked `Poseidon(ack_secret) == creator_tag` when `royalty_req == 1`; `TicketCheckInCircuit` exposed `event_nf = Poseidon(Poseidon(asset, secret), event_cmt)`. |
| **`OwnershipHeader` (`1`)** *(3 $\mathbb{F}_p$ slots)* | `[collection_root, state_root, challenge]` | `asset_id`, `owner_secret`, 4 Merkle siblings | $\text{Poseidon}(\text{Poseidon}(\text{asset}, \text{state\_root}), \text{Poseidon}(\text{secret}))$ is a leaf in `collection_root`. Stateful verifiers (`GalleryService`) enforce authoritative `collection_root`s and consume `challenge` once so replays fail; stateless verifiers must track challenge nonces externally. |
| **`CapHeader` (`2`)** *(4 $\mathbb{F}_p$ slots)* | `[collection_id, asset_id, slot_cmt, max_supply]` | `idx - 1`, `max_supply - idx`, `blinding` | `slot_cmt` commits `(collection_id, asset_id, idx, blinding)` with $0 \le \text{idx}-1 < 2^{16}$, $0 \le \text{max\_supply}-\text{idx} < 2^{16}$, and $(\text{idx}-1)+1+\Delta = \text{max\_supply}$, proving $1 \le \text{idx} \le \text{max\_supply}$. |
| **`AttributeHeader` (`3`)** *(4 $\mathbb{F}_p$ slots)* | `[asset_id, traits_root, owner_tag, Poseidon(trait, challenge)]` | `owner_secret`, 4 trait Merkle siblings | Prover knows `secret` for `owner_tag` and `(trait_key, trait_val)` is committed inside `traits_root`. |
| **`MigrationHeader` (`4`)** *(4 $\mathbb{F}_p$ slots)* | `[asset_id, phase1_cmt, owner_tag, burn_nf]` | `owner_secret` | Prover knows `secret` matching `owner_tag` and `burn_nf == Poseidon(Poseidon(asset_id, phase1_cmt), secret)`. |

---

## 6. Stage III (Tachyon): What Replaces the Stage I Memo?

Project Tachyon removes 512-byte on-chain encrypted memos in favor of out-of-band payload transmission and 32-byte **tachygrams**. Because Zyoza already transmits encrypted state and Ragu proofs out-of-band (`zyoza-oob`), the 9-field seal header simply moves inside the P2P `OobEnvelope`, while consensus receives only the 32-byte `Tachygram` aggregated into epoch `Tachystamp` roots (`TachyonAdapter`).

---

## 7. Related Work & References

* **RGB & Taproot Assets (Bitcoin CSV):** Anchor off-chain state to single-use seals via $O(H)$ client-side DAG traversal.
* **Shielded CSV (Nick, Eagen, Linus — IACR ePrint 2025/085):** Formalizes combining L1 nullifiers with recursive PCD.
* **References:**
  1. Sean Bowe, Jack Grigg, Daira-Emma Hopwood. *Halo: Recursive Proof Composition without a Trusted Setup.* IACR ePrint 2019/1021.
  2. Sean Bowe et al. *Ragu: Proof-Carrying Data Framework for Project Tachyon.* `https://github.com/tachyon-zcash/ragu` (2025–2026).
  3. Sean Bowe. *Project Tachyon: Planetary-Scale Shielded Zcash.* (2025–2026).
  4. Pablo Kogan et al. *ZIP 226 & ZIP 227: Zcash Shielded Assets.* `https://zips.z.cash/`.
  5. Brad Miller, Jack Grigg. *ZIP 302: Standardized Memo Field Format.* `https://zips.z.cash/zip-0302`.
  6. Chelsea Komlo, Ian Goldberg. *FROST: Flexible Round-Optimized Schnorr Threshold Signatures.* RFC 9591.
  7. Jonas Nick, Liam Eagen, Robin Linus. *Shielded CSV: Private and Efficient Client-Side Validation.* IACR ePrint 2025/085.
