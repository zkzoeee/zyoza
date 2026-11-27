# 🥟 Zyoza Security Model, Formal Constraints & Benchmarks

## 1. Measured Benchmarks (Unoptimized Debug Test Profile)

All measurements below were observed directly from `cargo test --workspace --offline -- --nocapture` on macOS (`rustc 1.99.1`, Halo2 IPA `k = 6` over Pasta `EqAffine`/`Fp`):

| Operation | Measured Latency | Payload / Proof Size | Notes |
| :--- | :--- | :--- | :--- |
| **Halo2 Ownership Prove** | `740 ms` | `5,935 bytes` | Proves `asset_id` knowledge + collection binding |
| **Halo2 Ownership Verify** | `27 ms` | `5,935 bytes` | Rejects mismatched challenge or root |
| **Ragu 12-Hop Composable PCD Fold** | `3,472 ms` (`~315 ms/hop`) | `6,279 bytes` | 12 hops across `NFT1` + `TKT1` (`single_len = 6,284 B`) |
| **Ragu 12-Hop PCD Verify** | `16 ms` | `6,279 bytes` | Constant-size & O(1) verification regardless of hops |
| **Tachyon 10,000-Mint Drop** | `119 ms` | `32 bytes` (`Tachystamp` root) | 10,000 `Tachygram` commitments aggregated |
| **Tachyon Oblivious Sync (10k bucket)** | `< 1 ms` (`0 ms`) | `10,000 x 32 B` (`320 KB`) | Client checks membership locally without leaking `AssetId` |

---

## 2. Threat Model & Mitigations

1. **Double-Spending / Forked Off-Chain State**
   * *Mitigation:* Every state transition consumes a unique L1 commitment/nullifier (`OrchardSealAdapter` in Phase 1, `OrchardZsaAdapter` in Phase 4, `TachyonAdapter` in Phase 5). Reusing any prior commitment or nullifier is rejected.
2. **Metadata & Media Leakage**
   * *Mitigation:* All media and profile state travel out-of-band (`zyoza-oob`) encrypted with `ChaCha20Poly1305` and ephemeral Pallas ECDH (`ecdh-pallas-hkdf-sha256`). Only opaque commitments and a 372-byte pointer hit the Orchard memo.
3. **Wallet Doxxing on Marketplaces / Gates**
   * *Mitigation:* Collectors disclose individual objects via per-object `ObjectViewingKey` (`zyoza-core::disclosure`) and prove collection/trait/ticket validity via Halo2/Ragu zero-knowledge proofs without exposing Zcash addresses or full wallets.
4. **Local Client-Side State Loss**
   * *Mitigation:* `zyoza-oob::{encrypt_backup, decrypt_backup}` provides seed-derived `ChaCha20Poly1305` encrypted state snapshots.
5. **Single Issuer Key Compromise (ZSA Crystallization)**
   * *Mitigation:* `zyoza-settlement::frost_issuer` enforces `t-of-n` (`2-of-3`) threshold Schnorr signatures on Pallas before authorizing ZSA issuance bundles.
6. **Ticket Replay & Soulbound Bypass**
   * *Mitigation:* `TKT1` enforces one-time `Hash(secret || event_id)` check-in nullifiers via `TicketGatekeeper`; `CRD1` rejects any non-revocation state transition.

---

## 3. Formal Circuit Constraint Specification (`MembershipKnowledgeCircuit`)

Over the Pasta base field $\mathbb{F}_p$ (`pallas::Base`):
* **Advice columns:** `secret`, `leaf`, `challenge`
* **Instance column:** `[ch, digest]`
* **Custom Plonk gate (`knowledge_binding`):**
  $$s \cdot (\text{secret} \cdot \text{challenge} + \text{leaf} - \text{out}) = 0$$
* **Equality constraints:** `challenge == instance[0]`, `out == instance[1]`.
* **PCD Folding Invariant (`RaguPcdEngine`):**
  $$\text{acc}_{i+1} = \text{acc}_i + \text{H}_{\text{step}}(\text{profile\_id}, \text{asset\_id}, \text{state\_commitment}_i)$$
  $$\text{ch}_{i+1} = \text{H}_{\text{fold}}(\text{acc}_i, \text{asset\_id}, i+1, \text{profile\_id})$$
