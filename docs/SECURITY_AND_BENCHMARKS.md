# Zyoza Security Model, Formal Constraints & Benchmarks

## 1. Measured Warm vs. Cold Benchmarks

All measurements below were observed on **Apple Silicon (`Apple M2 Pro`, macOS, `rustc 1.99.1`, `opt-level = 2`, Ragu `WalletRank = R<13>`, native `multicore` Rayon enabled)** using Zyoza's dedicated single prover thread (`zyoza-ragu-prover`):

| Operation | Cold First Call *(incl. one-time table init)* | Warm Prover Thread *(steady-state)* | `verify_compressed` ($O(1)$) | Compressed Proof Size |
| :--- | :--- | :--- | :--- | :--- |
| **One-Time Prover Init (`warmup_prover`)** | `~4.8 s` *(once per server process)* | `0 ms` *(reused across all requests)* | — | — |
| **Standalone Seed Proof** (`Mint` / `Ownership` / `Cap` / `Trait` / `Migration`) | `~6.8–9.2 s` *(if un-warmed)* | **`~2.1–4.2 s`** *(varies with CPU thermal/core load)* | **`~370–600 ms`** | **`7,168 B`** (`CompressedProof<Pasta>`) |
| **Recursive Lineage Fold (`Application::fuse` + `compress`)** | `~7.0–9.8 s` *(if un-warmed)* | **`~2.2–5.0 s / hop`** | **`~370–600 ms`** | **`7,168 B`** (`CompressedProof<Pasta>`) |
| **Studio Governed Mint (`MintCircuit` + `IssuanceCapCircuit`)** | `~9.0–13.5 s` *(2 proofs + cold init)* | **`~4.2–8.4 s`** *(2 warm Ragu proofs)* | **`~370–600 ms`** | `2 x 7,168 B` |
| **Tachyon 10,000-Mint Epoch Aggregation** *(simulated)* | `< 50 ms` | `< 50 ms` | `< 1 ms` (14 hashes) | `32 B` `Tachystamp` root |

*Why warm vs. cold differs:* `ApplicationBuilder::finalize` builds baked Pallas/Vesta synthesis tables once (`~4.8 s`) on `zyoza-ragu-prover` (spawned automatically at `zyoza-gallery-demo` startup). Under single-threaded builds (`wasm32` without `multicore`), warm proving takes `~7.0–7.5 s` per proof; with native `multicore` (`rayon`), warm proving runs in `~2.1–5.0 s` depending on available performance cores.

---

## 2. Threat Model, Statement Bindings & Known Prototype Limits

1. **Uncompressed Lineage Proof Linkability (Upstream Ragu Limit)**
   * *Current Status:* Presenting a `7,168 B` `CompressedProof<Pasta>` to a third-party verifier hides intermediate witnesses. However, handing an asset to a *next* owner who wants to call `Application::fuse` requires transmitting the uncompressed `Proof<Pasta, WalletRank>`, which in upstream `tachyon-zcash/ragu` today is **not zero-knowledge and not unlinkable under `rerandomize`**. Full inter-owner history hiding awaits upstream Ragu ZK rerandomization.
2. **Royalty Enforcement Scope (`RoyaltyCircuit` vs. L1 Payment)**
   * *Current Status:* `MintCircuit` commits `royalty_req` (`0` or `1`) and `creator_tag = Poseidon(creator_secret)` into `LineageHeader`. `TransferCircuit` enforces `royalty_req == 0` (preventing bypass), and `RoyaltyCircuit` enforces `royalty_req * (Poseidon(ack_secret) - creator_tag) == 0`. In Stage I this proves **creator/escrow receipt co-authorization**, whereas trustless atomic ZEC royalty settlement requires Stage II PCZT atomic swaps.
3. **Collection Supply Caps & Uniqueness (`IssuanceCapCircuit` + `CollectionSpec`)**
   * *Current Status:* `IssuanceCapCircuit` proves $1 \le \text{idx} \le \text{max\_supply} \le 65,535$ bound to `(collection_id, asset_id, slot_commitment)`. Preventing an issuer from minting *two different* assets with the same `idx` requires checking deterministic `NF_idx` nullifiers in a public Stage I bulletin log (or Stage II ZSA consensus).
4. **Gallery Ownership, State Binding & Challenge Replay (`OwnershipMerkleCircuit`)**
   * *Current Status:* `OwnershipHeader` binds `[collection_root, state_root, challenge]`. `GalleryService` verifies that `collection_root` is registered in its multi-holder index, checks `state_root == NftState::state_root()`, and **consumes one-time server CSPRNG challenges** on `submit_listing` so replayed challenges fail. Stateless verifiers must maintain their own challenge nonce cache.
5. **Owner Secret Stand-Ins & Orchard Note Opening**
   * *Current Status:* Owner authorization across `LineageHeader`, `OwnershipMerkleCircuit`, `AttributeCircuit`, and `MigrationCircuit` checks `Poseidon(secret) == owner_tag` using off-chain 32-byte secrets (derived demo keys in Studio). Binding `owner_tag` and the 512-byte memo seal directly to an on-chain Orchard note commitment `cm_x` inside a circuit is a future design target.
6. **Commit-Reveal Sealed Auctions**
   * *Current Status:* Zyoza Studio hashes `SHA-256("ZYOZA-BID-CMT-v2" || listing_id || bidder || bid_zatoshis || salt_32)` **in the browser** before sending only `commitment_hex` to the server, keeping bid values hidden from both public observers and the server until the reveal phase.

---

## 3. Formal Circuit Equations (`ragu::Application<Pasta, WalletRank, 12>`)

1. **`LineageHeader` (`Suffix 0`, 10 $\mathbb{F}_p$ slots):**
   $$\mathbf{h} = (\text{aid},\; \text{cmt}_0,\; \text{cmt}_k,\; \text{tag}_{\text{own}},\; k,\; \text{kind},\; \text{prof},\; r_{\text{req}},\; \text{tag}_{\text{cre}},\; \text{nf}_{\text{evt}})$$
   * **Every fold (`Index 2..5`):** $\mathbf{h}_{\text{prev}}[0] - \text{aid} = 0$, $\;\mathbf{h}_{\text{prev}}[2] - \text{cmt}_{\text{prev}} = 0$, $\;\mathbf{h}_{\text{prev}}[3] - \text{Poseidon}(\text{sec}_{\text{cur}}) = 0$.
   * **`TransferCircuit` (`Index 2`):** $\mathbf{h}_{\text{prev}}[7] = 0$.
   * **`RoyaltyCircuit` (`Index 3`):** $\mathbf{h}_{\text{prev}}[7] \cdot (\text{Poseidon}(\text{sec}_{\text{ack}}) - \mathbf{h}_{\text{prev}}[8]) = 0$.
   * **`TicketCheckInCircuit` (`Index 4`):** $\text{nf}_{\text{evt}} = \text{Poseidon}(\text{Poseidon}(\text{aid}, \text{sec}_{\text{cur}}), \text{cmt}_{\text{next}})$.
2. **`OwnershipHeader` (`Suffix 1`, 3 $\mathbb{F}_p$ slots):**
   $$\text{leaf} = \text{Poseidon}(\text{Poseidon}(\text{aid}, \text{state\_root}), \text{Poseidon}(\text{sec})) \xrightarrow{\text{Merkle}_4} \text{collection\_root}$$
3. **`CapHeader` (`Suffix 2`, 4 $\mathbb{F}_p$ slots):**
   $$\text{enforce\_le}_{16}(d_{\text{lo}}, 65535), \quad \text{enforce\_le}_{16}(d_{\text{hi}}, 65535), \quad \text{cap} = d_{\text{lo}} + 1 + d_{\text{hi}}$$
   $$\text{slot\_cmt} = \text{Poseidon}(\text{Poseidon}(\text{col\_id}, \text{aid}), \text{Poseidon}(d_{\text{lo}} + 1, \text{blind}))$$
4. **`AttributeHeader` (`Suffix 3`, 4 $\mathbb{F}_p$ slots):**
   $$\text{trait\_fp} \xrightarrow{\text{Merkle}_4} \text{traits\_root}, \quad \text{tag}_{\text{own}} = \text{Poseidon}(\text{sec}), \quad \text{ch}_{\text{out}} = \text{Poseidon}(\text{trait\_fp}, \text{chal})$$
5. **`MigrationHeader` (`Suffix 4`, 4 $\mathbb{F}_p$ slots):**
   $$\text{tag}_{\text{own}} = \text{Poseidon}(\text{sec}), \quad \text{burn\_nf} = \text{Poseidon}(\text{Poseidon}(\text{aid}, \text{cmt}_{\text{p1}}), \text{sec})$$
