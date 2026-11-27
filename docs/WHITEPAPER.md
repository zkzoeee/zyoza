# Zyoza: Proof-Carrying Shielded State Objects for Zcash

**Version 1.1 — Technical Whitepaper**

## Abstract
Public blockchains expose the complete ownership graph, price history, and metadata of non-fungible assets, turning collectors, event attendees, and credential holders into targets. Conversely, Zcash’s shielded protocols—**Orchard**, **Zcash Shielded Assets (ZSA, ZIP 226/227)**, and **Project Tachyon**—preserve financial privacy by keeping the base layer intentionally minimal, omitting on-chain media storage, arbitrary state machines, and public indexability.

**Zyoza** bridges this gap without bloating Zcash L1. Zyoza wraps encrypted out-of-band payloads (`zyoza-oob`) inside constant-size recursive **Ragu non-uniform Proof-Carrying Data (PCD)** (`zyoza-proofs`) and anchors anti-double-spend commitments onto Zcash (`zyoza-settlement`). Every Zyoza object derives a **ZIP 227-compatible `AssetId`** and Pallas **`AssetBase`** from day one, allowing assets minted today via Orchard single-use seals to **crystallize 1:1** into native L1 ZSA notes and scale to **Tachyon** aggregated bundles with zero broken identifiers.

---

## 1. The Core Engineering Insight: Three Orthogonal Layers

Instead of forcing Zcash validators to store metadata or execute smart-contract VMs, Zyoza splits every digital object into three independent layers:

| Layer | Responsibility | Cryptographic Mechanism |
| :--- | :--- | :--- |
| **1. Identity & Scarcity (`zyoza-core`)** | Canonical asset ID, private supply caps, selective viewing keys | ZIP 227 `AssetId` / Pallas `AssetBase`, `CollectionSpec` nullifiers, `ObjectViewingKey` |
| **2. Out-of-Band Payload (`zyoza-oob`)** | Encrypted media, off-chain state, O(1) key handover, backups | `ChaCha20Poly1305` DEK + Pallas ECDH / hybrid `ML-KEM-768` key wrapping |
| **3. Lineage & Settlement (`zyoza-proofs`, `zyoza-settlement`)** | Programmable transition rules, provenance, double-spend prevention | Halo2 IPA & `RaguPcdEngine`; `OrchardSeal` -> `OrchardZSA` -> `Tachyon` |

**Why this matters:** Consensus nodes only ever validate standard shielded notes and 32-byte nullifiers. Megabytes of artwork and arbitrarily long provenance histories add **zero bytes** of permanent validator bloat and align directly with **Project Tachyon’s** removal of in-band secret distribution.

---

## 2. Anatomy of a 512-Byte `"ZYOZ"` Seal & O(1) Key Re-Wrapping

### 2.1 Exact Byte Layout Inside an Orchard Encrypted Memo
In Stage I (live on Zcash today), each mint or transfer commits its state inside the standard 512-byte encrypted Orchard memo field:

```text
Byte Offset:  0..4     4..6    6..10     10..42       42..74       74..106      106..138      138..140   140..512
            ┌────────┬───────┬─────────┬────────────┬────────────┬────────────┬─────────────┬──────────┬──────────────┐
Field:      │ "ZYOZ" │ v0001 │ Profile │  AssetId   │ StateRoot  │   Nonce    │  OOB Hash   │ URI Len  │   OOB URI    │
Size:       │  4 B   │  2 B  │   4 B   │   32 B     │   32 B     │   32 B     │    32 B     │   2 B    │    372 B     │
            └────────┴───────┴─────────┴────────────┴────────────┴────────────┴─────────────┴──────────┴──────────────┘
```

### 2.2 O(1) Bandwidth Transfers via DEK Re-Wrapping
Uploading and re-encrypting large media files on every transfer is prohibitive. Zyoza encrypts the media payload *once* under a random 256-bit Data Encryption Key ($\text{DEK}$) using `ChaCha20Poly1305` with $\text{AAD} = \text{AssetId}$.
* When Alice transfers the object to Bob, Alice unwraps the 32-byte $\text{DEK}$ with her secret key and re-encapsulates **only those 32 bytes** to Bob’s public key (`rewrap_for_recipient`).
* For long-lived archival art and RWA deeds, `zyoza-oob::pq_kem` combines classical Pallas ECDH with post-quantum KEM encapsulation (`hybrid-pallas-mlkem768-hkdf-sha256`) so "harvest now, decrypt later" adversaries must break both assumptions:
  $$\text{KEK} = \text{HKDF-SHA256}_{\text{AssetId}}(\text{SS}_{\text{Pallas}} \parallel \text{SS}_{\text{PQ}})$$

---

## 3. Private Scarcity Without Public `totalSupply()`

On Ethereum, buyers verify scarcity by reading public storage; on a shielded chain, mints are invisible. Zyoza guarantees collection rules privately using a declarative `CollectionSpec(issuer_vk, slug, max_supply, unique_media, mint_window)`:

1. **Deterministic Domain-Separated Mint Nullifiers:** Every governed mint must atomically reveal up to three deterministic nullifiers:
   * $\text{NF}_{\text{aid}} = \text{BLAKE2b}(\text{"ZYOZA-MINT-AID1\_"}, \text{col\_id} \parallel \text{AssetId})$ — blocks minting the same `AssetId` twice with a new nonce.
   * $\text{NF}_{\text{idx}} = \text{BLAKE2b}(\text{"ZYOZA-MINT-IDX1\_"}, \text{col\_id} \parallel \text{token\_index})$ — blocks two assets from claiming slot $i \in [1, N]$.
   * $\text{NF}_{\text{med}} = \text{BLAKE2b}(\text{"ZYOZA-MINT-MED1\_"}, \text{col\_id} \parallel \text{SHA256}(\text{media}))$ — blocks copy-minting identical media inside the collection.
2. **Zero-Knowledge Supply-Cap Range Proof (`IssuanceCapEngine`):** A Halo2 circuit over Pasta $\mathbb{F}_p$ decomposes $(i - 1)$ and $(N - i)$ into 16 binary-constrained bits ($b \cdot (1 - b) = 0$) and enforces $(i - 1) + 1 + (N - i) = N$, proving $1 \le i \le N$ without revealing which edition number was minted.

---

## 4. Why Ragu Non-Uniform PCD Beats Indexers and Monolithic zkVMs

Verifying an object’s lifecycle (royalties paid, lockups respected, event check-ins, game upgrades) faces a classic trilemma:
* **Public Indexers (Ethereum/Solana):** Fast to verify, zero privacy—every past owner and price is public.
* **Client-Side History Replay (Legacy CSV):** Leaks the entire transaction DAG to every future buyer and grows linearly $O(H)$ with hop count $H$.
* **Monolithic Universal Circuits / zkVMs:** Preserve privacy, but force every simple transfer to prove one giant worst-case circuit.

**Zyoza’s Solution — Ragu Non-Uniform PCD (`zyoza-proofs`):**
Built over Zcash’s cycle of **Pasta curves** (`Pallas` / `Vesta`, no trusted setup), Zyoza partitions rules into lightweight step subcircuits (`MintStep`, `TransferStep`, `RoyaltyStep`, `TicketCheckInStep`, `AttributeUpgradeStep`):
* **Pay-Per-Step Proving:** Each transition proves *only* the subcircuit for that action (e.g., `RaguRuleCircuit` enforcing $\text{royalty\_req} \cdot (1 - \text{royalty\_paid}) = 0$ in Plonk constraints).
* **Constant-Size Lineage:** Step $k$ folds the running accumulator $\text{acc}_k = \text{acc}_{k-1} + H_{\text{step}}(\text{profile\_id}, \text{AssetId}, C_k)$ into a single constant-size proof ($\approx 6.2\text{ KB}$ JSON / $2,112\text{ B}$ raw IPA). Whether an NFT has been traded once or 500 times, verification takes $\approx 16\text{ ms}$ and reveals **zero prior owners**.
* **Cross-Profile Composability:** A single object can fold steps across Zyoza’s five vertical profiles—collectibles (`NFT1`), event tickets (`TKT1`), soulbound credentials (`CRD1`), mutable game gear (`GAM1`), and compliant real-world deeds (`RWA1`).

---

## 5. Selective Disclosure & Front-Running-Resistant Markets

* **Per-Object Viewing Keys (`ObjectViewingKey`):** Derived as $\text{BLAKE2b}_{\text{"ZYOZA-OVK-v1"}}(\text{AssetId} \parallel \text{secret})$. A collector can reveal *one* NFT’s title, art, and traits to a gallery without exposing any other asset in their Zcash wallet.
* **Halo2 Ownership & Trait Proofs:** Sellers prove *"I hold an unspent Zyoza in Collection X (or with trait `shades = Venetian`)"* bound to a fresh challenge, powering **ZK-verified listings** and **sealed-bid ZEC auctions** where losing bids stay private.

---

## 6. Three-Stage Zcash Settlement Path (Zero Broken IDs)

Because `AssetId` and Pallas `AssetBase = HashToCurve("z.cash:OrchardZSA", AssetId)` follow **ZIP 227** from day one, Zyoza upgrades cleanly across Zcash’s roadmap:

1. **Stage I — Orchard Single-Use Seals (Live Today):** `"ZYOZ"` 512-byte memo commitments anchored in standard Orchard notes; spending the note retires the seal.
2. **Stage II — Native ZSA Crystallization (ZIP 226/227):** Holders prove seal retirement via Halo2 (`prove_migration`), co-signed by a `2-of-3` Pallas **FROST** threshold committee, to mint a `value = 1` finalized L1 `ZsaNote` with the **identical `AssetId`**. This unlocks trustless 1-transaction `ZSA <-> ZEC` atomic swaps.
3. **Stage III — Project Tachyon:** `TachyonAdapter` aggregates 10,000+ mints and nullifiers into a single 32-byte `Tachystamp` epoch root in `119 ms`, letting mobile wallets verify state via prunable $O(\log N)$ Merkle paths (`14` hashes) without leaking queried `AssetId`s.

---

## 7. Empirical Reference Benchmarks

Measured on the 13-crate Rust workspace (`rustc 1.99`, Pasta `EqAffine`/`Fp`, $k = 6$):

| Operation | Prove / Execute | Verify | Artifact Size |
| :--- | :--- | :--- | :--- |
| **Halo2 Ownership / Trait Proof** | `740 ms` | `27 ms` | `5,935 B` (`2,112 B` raw IPA) |
| **Ragu 12-Hop Composable PCD (`NFT1` + `TKT1`)** | `~315 ms / hop` | `16 ms` ($O(1)$) | `6,279 B` (`2,112 B` raw IPA) |
| **Tachyon 10,000-Mint Epoch + Merkle Sync** | `119 ms` batch | `< 1 ms` (`14` hashes) | `32 B` `Tachystamp` root |
