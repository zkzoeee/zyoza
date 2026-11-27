# Zyoza (🥟): Proof-Carrying Shielded State Objects for Zcash

**Version 1.0 — November 2026**

## Abstract
Public blockchains expose the complete ownership graph, price history, and metadata of non-fungible assets, turning collectors and credential holders into targets. Conversely, Zcash’s shielded protocols—**Orchard**, **Zcash Shielded Assets (ZSA, ZIP 226/227)**, and **Project Tachyon**—preserve financial privacy by keeping the base layer intentionally minimal, omitting on-chain media storage, arbitrary state machines, and public indexability.

**Zyoza** bridges this gap without bloating Zcash L1. Named after folded, sealed dumplings—a nod to Zcash’s *Pasta*, *Ragu*, and *Udon* lineage—Zyoza wraps encrypted out-of-band state (`zyoza-oob`) inside constant-size recursive **Ragu non-uniform Proof-Carrying Data (PCD)** (`zyoza-proofs`) and anchors anti-double-spend commitments onto Zcash (`zyoza-settlement`). Every Zyoza object derives a **ZIP 227-compatible `AssetId`** from day one, allowing assets minted today via Orchard single-use seals to **crystallize 1:1** into native L1 ZSA notes and scale to **Tachyon** aggregated bundles with zero broken identifiers.

---

## 1. Architectural Principles

Zyoza separates a digital object into three orthogonal layers:

| Layer | Responsibility | Implementation |
| :--- | :--- | :--- |
| **1. Identity & Supply (`zyoza-core`)** | Canonical asset ID, declarative supply caps, selective viewing keys | ZIP 227 `AssetId` / Pallas `AssetBase`, `CollectionSpec`, `ObjectViewingKey` |
| **2. Out-of-Band Payload (`zyoza-oob`)** | Encrypted media, state blobs, key handover, seed backups | `ChaCha20Poly1305` + Pallas ECDH / hybrid PQ KEM (`mlkem768`) |
| **3. Lineage & Settlement (`zyoza-proofs`, `zyoza-settlement`)** | Programmable transition rules, provenance, double-spend prevention | Halo2 IPA & `RaguPcdEngine`; `OrchardSeal` $\to$ `OrchardZSA` $\to$ `Tachyon` |

By keeping media and rich state out-of-band, Zyoza directly aligns with **Project Tachyon’s** removal of in-band secret distribution while remaining usable on Zcash mainnet today.

---

## 2. Cryptographic Identity & Declarative Issuance

### 2.1 ZIP 227-Aligned Identity
Every Zyoza object derives its 32-byte `AssetId` and Pallas curve `AssetBase` identically across all settlement eras:
$$\text{desc\_hash} = \text{BLAKE2b-256}_{\text{"ZSA-AssetDesc\_\_\_"}}(\text{asset\_desc})$$
$$\text{AssetId} = \text{BLAKE2b-256}_{\text{"ZSA-AssetId\_\_\_\_\_"}}(\text{issuer\_vk} \parallel \text{desc\_hash})$$
$$\text{AssetBase} = \text{HashToCurve}_{\text{"z.cash:OrchardZSA"}}(\text{AssetId}) \in \mathbb{G}_{\text{Pallas}}$$

### 2.2 Uniform Anti-Duplicate & Supply-Cap Guarantees (`CollectionSpec`)
On a shielded ledger, observers cannot call `totalSupply()`. To prevent silent duplicate minting, slot collisions, or over-minting without revealing owners, each collection declares a `CollectionSpec(issuer_vk, slug, max_supply, unique_media, mint_window)`. Minting requires:
1. **Deterministic Mint Nullifiers:** Atomically revealing up to three domain-separated nullifiers per mint:
   * $\text{NF}_{\text{aid}} = H(\text{col\_id} \parallel \text{AssetId})$ — blocks minting the same `AssetId` twice with a fresh nonce.
   * $\text{NF}_{\text{idx}} = H(\text{col\_id} \parallel \text{token\_index})$ — blocks two assets from claiming the same edition slot $i \in [1, N]$.
   * $\text{NF}_{\text{med}} = H(\text{col\_id} \parallel \text{SHA256}(\text{media}))$ — blocks copy-minting identical artwork inside the collection.
2. **In-Circuit Supply-Cap Proof (`IssuanceCapEngine`):** A Halo2 circuit over $\mathbb{F}_p$ decomposes $(i - 1)$ and $(N - i)$ into 16 binary-constrained bits and enforces $(i - 1) + 1 + (N - i) = N$, proving $1 \le i \le N$ in zero knowledge.

---

## 3. Out-of-Band Encryption & Post-Quantum Key Handover

Heavy payloads never touch Zcash consensus. On mint, the creator encrypts the payload under a fresh 256-bit Data Encryption Key (DEK) using `ChaCha20Poly1305` with $\text{AAD} = \text{AssetId}$.
* **Key Re-Wrapping (`rewrap_for_recipient`):** During a transfer from Alice to Bob, Alice unwraps the DEK and re-encapsulates it for Bob’s public key—avoiding re-uploading large encrypted media blobs on IPFS/Arweave.
* **Hybrid Post-Quantum Mode:** For long-lived archival art and RWA deeds, `zyoza-oob::pq_kem` derives the key-encryption key from both classical Pallas ECDH and a post-quantum KEM secret via HKDF-SHA256:
  $$\text{KEK} = \text{HKDF-SHA256}_{\text{AssetId}}(\text{SS}_{\text{Pallas}} \parallel \text{SS}_{\text{PQ}})$$

---

## 4. Ragu Non-Uniform PCD: Living, Composable Objects

Traditional NFTs rely on public indexers replaying every historical transaction—exposing every prior holder—or monolithic zkVM circuits that pay worst-case proving cost on every transfer.

Zyoza adopts **Ragu’s non-uniform Proof-Carrying Data (PCD)** paradigm over Zcash’s Pasta curves (`Pallas` / `Vesta`, no trusted setup):
1. **Specialized Step Subcircuits (`RaguStepKind`):** Each lifecycle event—`MintStep`, `TransferStep`, `RoyaltyStep`, `TicketCheckInStep`, `AttributeUpgradeStep`—executes only the constraints relevant to that transition (e.g., `RaguRuleCircuit` enforcing $\text{royalty\_req} \cdot (1 - \text{royalty\_paid}) = 0$).
2. **Constant-Size Recursive Lineage:** Step $k$ folds the prior accumulator $\text{acc}_{k-1}$ into $\text{acc}_k = \text{acc}_{k-1} + H_{\text{step}}(\text{profile\_id}, \text{AssetId}, C_k)$ and produces a single constant-size proof ($\approx 6.2\text{ KB}$). A buyer verifies a 12-hop history of transfers, royalty payments, event check-ins, and item upgrades in $\approx 16\text{ ms}$ **without learning any previous owner’s identity**.
3. **Multi-Vertical Composability:** Because step circuits are non-uniform, a single Zyoza core powers five vertical profiles—collectibles (`NFT1`), anonymous event tickets (`TKT1`), soulbound credentials (`CRD1`), mutable game items (`GAM1`), and credential-gated real-world deeds (`RWA1`)—and can fold steps across profiles on the same asset.

---

## 5. Selective Disclosure & Sealed-Bid Markets

In an oblivious-sync world, marketplaces cannot scrape wallets. Zyoza introduces two primitives for private commerce:
* **Per-Object Viewing Keys (`ObjectViewingKey`):** Derived as $H_{\text{"ZYOZA-OVK-v1"}}(\text{AssetId} \parallel \text{secret})$, allowing a collector to unlock *one* object’s preview metadata on a gallery without exposing their Zcash wallet viewing key.
* **ZK Ownership & Trait Badges (`Halo2ProofEngine`):** Sellers prove knowledge of an unspent Zyoza secret bound to a collection root or specific trait (`glasses = "Venetian-3"`) against a fresh marketplace challenge, enabling **ZK-verified listings** and **sealed-bid shielded ZEC auctions** free from front-running.

---

## 6. Three-Stage Settlement Evolution

```
Stage I: Orchard Today           Stage II: ZSA Mainnet            Stage III: Project Tachyon
┌────────────────────────┐       ┌────────────────────────┐       ┌────────────────────────┐
│ 512B OrchardMemoSeal   │ ───►  │ ZIP 226/227 ZsaNote    │ ───►  │ 32B Tachygram +        │
│ ("ZYOZ" single-use)    │ Burn  │ (value=1, finalized,   │ Swap  │ Tachystamp Epoch Root  │
│                        │ + ZK  │  2-of-3 Pallas FROST)  │       │ + O(log N) Merkle Sync │
└────────────────────────┘       └────────────────────────┘       └────────────────────────┘
            ▲                                ▲                                ▲
            └─────────────── Identical AssetId, OOB Media & Ragu PCD ─────────┘
```

1. **Stage I (`OrchardSealAdapter` — Live Today):** Commits the 512-byte `"ZYOZ"` header inside standard Orchard encrypted memos; spending the Orchard note retires the seal.
2. **Stage II (`OrchardZsaAdapter` — ZSA Mainnet):** Holders generate a Halo2 `prove_migration` proof, burn their Stage I seal, and claim a `value = 1` finalized L1 ZSA note co-signed by a `2-of-3` Pallas FROST issuer committee—unlocking single-transaction shielded `ZSA <-> ZEC` atomic swaps.
3. **Stage III (`TachyonAdapter` — Planetary Scale):** Compresses tens of thousands of mints and nullifiers into 32-byte `Tachystamp` epoch roots, allowing mobile wallets to verify state via prunable $O(\log N)$ `MerkleWitness` paths without leaking queried `AssetId`s.

---

## 7. Reference Implementation Benchmarks

Measured on the 13-crate Rust reference workspace (`rustc 1.99`, Pasta `EqAffine`/`Fp`, $k = 6$):

| Operation | Latency | Size | Complexity |
| :--- | :--- | :--- | :--- |
| **Halo2 Ownership / Trait Proof** | `740 ms` prove / `27 ms` verify | `5.9 KB` | $O(1)$ |
| **Ragu 12-Hop Composable PCD** | `~315 ms/hop` / `16 ms` verify | `6.2 KB` | $O(1)$ size & verify |
| **Tachyon 10,000-Mint Epoch Drop** | `119 ms` batch aggregation | `32 B` root | $O(\log N)$ (`14` hashes) |
