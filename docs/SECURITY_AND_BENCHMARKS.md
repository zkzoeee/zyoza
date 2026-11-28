# Zyoza Security Model, Formal Constraints & Benchmarks

## 1. Measured Warm vs. Cold Benchmarks

All measurements below were observed on **Apple Silicon (`Apple M2 Pro`, 10 cores, macOS, `rustc 1.99.1`, `--release`, Ragu rev `a812865` at `WalletRank = R<13>`, native `multicore` and `asm` enabled)** using Zyoza's dedicated single prover thread (`zyoza-ragu-prover`). Reproduce with `cargo test --release -p zyoza-proofs bench_ragu -- --ignored --nocapture`.

| Operation | Cold First Call *(incl. one-time table init)* | Warm Prover Thread *(steady-state)* | `verify_compressed` ($O(1)$) | Compressed Proof Size |
| :--- | :--- | :--- | :--- | :--- |
| **One-Time Prover Init (`warmup_prover`)** | `~2.5 s` *(once per server process)* | `0 ms` *(reused across all requests)* | — | — |
| **Standalone Seed Proof** (`Ownership` / `Cap` / `Trait` / `Migration`: `seed` + `compress`) | `~3.5 s` *(if un-warmed)* | **`~1.0–1.1 s`** | **`~70–100 ms`** | **`6,208 B`** (`CompressedProof<Pasta>`) |
| **Recursive Lineage Fold (`Application::fuse` + `compress`)** | `~3.5 s` *(if un-warmed)* | **`~1.0 s / hop`** (`fuse` `~0.57 s` + `compress` `~0.45 s`); **`~0.6 s / hop`** with `fold_step_deferred` | **`~70–100 ms`** | **`6,208 B`** (`CompressedProof<Pasta>`) |
| **Studio Governed Mint (`MintCircuit` + `IssuanceCapCircuit`)** | `~4.2 s` *(2 proofs + cold init)* | **`~1.7 s`** *(deferred mint seed `~0.6 s` + cap proof `~1.05 s`)* | **`~70–100 ms`** | `6,208 B` cap proof; the mint proof is compressed on demand |
| **Tachyon 10,000-Mint Epoch Aggregation** *(simulated)* | `< 50 ms` | `< 50 ms` | `< 1 ms` (14 hashes) | `32 B` `Tachystamp` root |

*Why warm vs. cold differs:* `ApplicationBuilder::finalize` builds the application once (`~2.5 s`) on `zyoza-ragu-prover` (spawned automatically at `zyoza-gallery-demo` startup). Supplying a stored bootstrap proof (`with_bootstrap`) cut this to `~1.8 s` in testing, but needs a 34 MB cache file, so it is not enabled.

*What changed these numbers:* moving from Ragu rev `5d22564` to `a812865` with `asm` took `fuse` from `~1.6 s` to `~0.57 s`, `compress` from `~0.95 s` to `~0.45 s`, `verify_compressed` from `~420 ms` to `~75 ms`, and the proof from `7,168 B` to `6,208 B`. Deferring compression saves a further `~0.45 s` on every hop that nobody verifies: a 6-hop lineage verified once at the end ran about 35% faster. An uncompressed (still foldable) proof is `~34 MB`.

*Browser proving (WebAssembly, single-threaded, Chrome on the same laptop):* prover warm-up `~16 s` (all of it building the Ragu application; it was `~25–28 s` before the bootstrap proof replaced a separately seeded unit proof as the right-hand input of each fold), Studio mint `~27 s` (lineage seed plus the supply-cap proof), every other proving step `~16–17 s` (a fold with compression, or compress-if-needed plus one standalone proof), `verify_compressed` under Node `~1.1 s`. The prover is a `9.8 MB` WebAssembly file (`4.4 MB` gzipped) and used about `460 MB` of memory. The server verifies every browser proof natively before committing a step.

*Hosted numbers (Fly.io `shared-cpu-2x`, 1 GB, x86-64):* a fold took `~5.3 s` on the old Ragu rev, `~5.1–5.3 s` on the new rev built without x86 assembly, and `~4.1–4.9 s` with `RUSTFLAGS="-C target-feature=+adx,+bmi2"` (set in the `Dockerfile`). A Studio mint went `9.8 s` -> `7.6 s` -> `5.7 s` and crystallization `6.0 s` -> `4.3 s`. Moving to `shared-cpu-4x` (1 GB, `iad`) brought a fold to `~3.0–3.2 s`, a mint to `~4.7–5.2 s`, crystallization to `~3.1–3.3 s` and `verify_compressed` to `~220–240 ms` (down from `~370 ms` on 2x). Those times were measured from Asia and include about `0.45 s` of network round trip. Doubling the vCPUs gave roughly 1.4x, not 2x. The current deployment is `shared-cpu-2x` (1 GB, `iad`): `~4.7 s` per fold. In a sustained test, a mint, a transfer and 11 folds ran at that speed, then the CPU burst allowance ran out and the next proofs took `30–59 s`. On `shared-cpu-1x` (1 GB) the first proofs took `~7.2 s` per fold and `~10.5 s` per mint with `verify_compressed` at `~480 ms`, and pages stayed responsive. But after about seven proofs in a row the CPU burst allowance ran out and every proof took `87–106 s`, so 1x is not usable for the Studio. Peak resident memory there was `~306 MB`. The remaining gap to the laptop's `~1 s` is core count and core speed: the prover is multi-threaded and shared vCPUs are slower than laptop cores. Ragu's x86-64 assembly has no runtime CPU detection, so that binary only runs on CPUs with BMI2 and ADX.

---

## 2. Threat Model, Statement Bindings & Known Prototype Limits

1. **Uncompressed Lineage Proof Linkability (Upstream Ragu Limit)**
   * *Current Status:* Presenting a `6,208 B` `CompressedProof<Pasta>` to a third-party verifier hides intermediate witnesses. However, handing an asset to a *next* owner who wants to call `Application::fuse` requires transmitting the uncompressed `Proof<Pasta, WalletRank>`, which in upstream `tachyon-zcash/ragu` today is **not zero-knowledge and not unlinkable under `rerandomize`**. Full inter-owner history hiding awaits upstream Ragu ZK rerandomization.
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
