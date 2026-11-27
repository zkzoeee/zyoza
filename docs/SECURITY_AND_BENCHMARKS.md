# Zyoza Security Model, Formal Constraints & Benchmarks

## 1. Measured Reference Benchmarks

All measurements below were collected directly from `cargo test --workspace --offline -- --nocapture` on **Apple M2 Pro** (`macOS`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, Cargo profile `opt-level = 2`, single-threaded Ragu `baked` backend without `multicore`):

| Operation | Engine / Parameters | Prove / Execute | Verify | Artifact Size |
| :--- | :--- | :--- | :--- | :--- |
| **Ragu Recursive PCD Fold (`fuse` + `compress`)** | `tachyon-zcash/ragu` (`WalletRank = R<13>`, Pasta) | `7,409 ms / hop` | `732 ms` ($O(1)$) | **`7,168 B`** (`CompressedProof<Pasta>`) |
| **Ragu Poseidon-Merkle Ownership Proof** | `OwnershipMerkleCircuit` (`MERKLE_DEPTH = 4`, Pasta) | `14,447 ms` *(incl. table init)* | `466 ms` | **`7,168 B`** (`CompressedProof<Pasta>`) |
| **Ragu Supply-Cap / Trait / Migration Proof** | `IssuanceCapCircuit` / `AttributeCircuit` / `MigrationCircuit` (`WalletRank`) | `~7.0 s` *(warm thread)* | `~460 ms` | **`7,168 B`** (`CompressedProof<Pasta>`) |
| **Tachyon 10,000-Mint Epoch Aggregation** | `TachyonAdapter` (simulated 14-level Merkle epoch) | `< 50 ms` | `< 1 ms` (14 hashes) | `32 B` `Tachystamp` root |

*Note on first-call initialization:* `ragu::Application` initializes its baked Pasta synthesis tables per worker thread on first touch (`~7 s` on Apple M2 Pro); subsequent `fuse` + `compress` folds on warm threads run in `~7.4 s` and always compress to **`7,168 bytes`** (`CompressedProof::<Pasta>::encoded_len::<WalletRank>()`).

---

## 2. Threat Model, Enforcement Boundaries & Trust Assumptions

1. **Double-Spending / Forked Off-Chain State**
   * *Mechanism:* Each transition retires the prior note's commitment/nullifier and binds the new commitment in Ragu's `LineageHeader` (`left[SLOT_LATEST] == witness.prev_commit_fp`).
   * *Prototype status:* Simulated in memory by `OrchardSealAdapter`, `OrchardZsaAdapter`, and `TachyonAdapter`. On live Zcash, Orchard consensus enforces single-spend nullifiers while buyers verify the current note opening + compressed Ragu lineage proof prior to payment.
2. **Duplicate Collection Slot / Media Re-Minting (`CollectionSpec`)**
   * *Mechanism:* Deterministic domain-separated nullifiers (`NF_aid`, `NF_idx`, `NF_med`) collide if an issuer attempts to mint the same slot or SHA-256 media hash twice, paired with Ragu 16-bit range proofs (`IssuanceCapCircuit`, $1 \le \text{idx} \le \text{cap}$).
   * *Enforcement boundary:* In Stage I (pre-ZSA), `NF_*` must be published to a public bulletin/indexer stream so buyers can verify global slot uniqueness; in Stage II (ZIP 227), supply caps and `finalize = true` are enforced directly by Zcash consensus.
3. **Metadata & Media Leakage**
   * *Mechanism:* Payloads travel out-of-band (`zyoza-oob`) encrypted under `ChaCha20Poly1305` (`AAD = AssetId`) with ephemeral Pallas ECDH (`ecdh-pallas-hkdf-sha256`). Stage I memos start with ZIP 302 `0xFF` (`[0xFF, 'Z', 'Y', 'O', 'Z']`) so wallets never parse them as UTF-8 text.
4. **Wallet Doxxing & Front-Running on Marketplaces**
   * *Mechanism:* Collectors disclose individual items via per-asset `ObjectViewingKey`, prove collection holdings via Ragu `OwnershipMerkleCircuit` bound to a fresh verifier `challenge`, and bid via salted `BLAKE2b-256` commit-reveal (`revealed_zatoshis = None` until reveal).
5. **Single Issuer Key Compromise (Stage II ZSA Crystallization)**
   * *Mechanism:* `zyoza-settlement::frost_issuer` requires a `2-of-3` threshold Schnorr signature on Pallas before authorizing ZSA issuance. *(Prototype uses trusted-dealer `keygen_dealer`; production deployments require interactive FROST DKG.)*
6. **Off-Chain Data Availability**
   * *Mechanism:* Losing an `OobEnvelope` halts future CSV transfers; mitigated via content-addressed IPFS/Arweave pinning and `encrypt_backup(wallet_seed, state)` recovery snapshots.

---

## 3. Formal Circuit Specifications (`zyoza-proofs`)

### 3.1 Ragu Non-Uniform Recursive Lineage (`Application<Pasta, WalletRank, 5>`)
* **Public Header (`LineageHeader`, 4 $\mathbb{F}_p$ elements):**
  $$\mathbf{h} = (\text{asset\_fp},\; \text{genesis\_commit\_fp},\; \text{latest\_commit\_fp},\; \text{acc\_fp})$$
* **Base Step (`MintCircuit`, `Index 1`):**
  $$\text{acc}_1 = \text{Poseidon}(1,\; \text{prof},\; \text{asset},\; \text{cmt}_1,\; \text{sec}), \quad \mathbf{h}_1 = (\text{asset},\; \text{cmt}_1,\; \text{cmt}_1,\; \text{acc}_1)$$
* **Recursive Steps (`Index 2..5`):** Enforce contiguity and subcircuit predicates in-circuit:
  $$\mathbf{h}_{\text{prev}}[0] - \text{asset} = 0, \qquad \mathbf{h}_{\text{prev}}[2] - \text{cmt}_{\text{prev}} = 0$$
  * **`RoyaltyCircuit` (`Index 3`):** Allocates Boolean wires $r_{\text{req}}, r_{\text{paid}} \in \{0,1\}$ and enforces:
    $$r_{\text{req}} \cdot (1 - r_{\text{paid}}) = 0$$
  * **`TicketCheckInCircuit` (`Index 4`):** Computes $\text{nf}_{\text{tkt}} = \text{Poseidon}(\text{sec}, \text{cmt}_{\text{next}})$ in-circuit and absorbs $\text{nf}_{\text{tkt}}$ into $\text{acc}_{i+1}$.

### 3.2 Ragu Poseidon-Merkle Ownership (`OwnershipMerkleCircuit`, `Index 6`)
* Proves witness $(\text{asset}, \text{sec}, \{(\text{sib}_\ell, b_\ell)\}_{\ell=0}^{3}, \text{chal})$ satisfies:
  $$\text{leaf} = \text{Poseidon}(\text{asset}, \text{Poseidon}(\text{sec}))$$
  $$\text{cur}_{\ell+1} = \text{Poseidon}(\text{select}(b_\ell, \text{sib}_\ell, \text{cur}_\ell),\; \text{select}(b_\ell, \text{cur}_\ell, \text{sib}_\ell)) \quad (\ell = 0..3)$$
  $$\text{OwnershipHeader} = \text{Poseidon}(\text{cur}_4,\; \text{chal})$$
  Verifier recomputes $\text{Poseidon}(\text{collection\_root}, \text{chal})$ and calls `Application::verify_compressed`.

### 3.3 Ragu Supply-Cap, Attribute & Migration Circuits (`Index 7..9`)
* **`IssuanceCapCircuit` (`Index 7`, `CapHeader`):** Allocates $d_{\text{lo}} = \text{idx} - 1$ and $d_{\text{hi}} = \text{cap} - \text{idx}$, calls Ragu's `Element::enforce_le::<16>(u16::MAX)` on both so neither can wrap modulo $p$, and outputs $\text{CapHeader} = d_{\text{lo}} + 1 + d_{\text{hi}}$, proving $1 \le \text{idx} \le \text{cap} \le 65,535$.
* **`AttributeCircuit` (`Index 8`, `AttributeHeader`):** Binds $\text{owner\_leaf} = \text{Poseidon}(\text{asset}, \text{Poseidon}(\text{sec}))$ to $(\text{trait\_fp}, \text{chal})$ via $\text{Poseidon}(\text{Poseidon}(\text{owner\_leaf}, \text{trait\_fp}), \text{chal})$.
* **`MigrationCircuit` (`Index 9`, `MigrationHeader`):** Enforces $\text{sec} \neq 0$ via `Element::enforce_nonzero`, derives $\text{burn\_nf} = \text{Poseidon}(\text{asset}, \text{sec})$, and outputs $\text{Poseidon}(\text{Poseidon}(\text{asset}, \text{cmt}_{\text{p1}}), \text{burn\_nf})$.
