# Zyoza — Proof-Carrying Objects on Zcash

**Wrapped in secrecy. Folded in proof.**

Zyoza lets you mint, trade and prove ownership of collectibles, tickets, credentials, game items and deeds on Zcash, without exposing your wallet. The media stays encrypted off-chain, the chain holds a 512-byte seal, and every change of hands adds one step to a recursive proof that stays 6,208 bytes however long the history gets.

**Live demo:** <https://zyoza.fly.dev> — landing page, the six-step [Zyoza Studio](https://zyoza.fly.dev/demo), and the rendered [whitepaper](https://zyoza.fly.dev/whitepaper).

> **Status: research prototype, not audited.** The proofs are real: every circuit runs on [`tachyon-zcash/ragu`](https://github.com/tachyon-zcash/ragu), which is itself unaudited. Settlement is a simulated in-memory ledger, not yet wired to a Zcash node. Handing an uncompressed proof to the next owner is not yet unlinkable in upstream Ragu. See [Security & Benchmarks](docs/SECURITY_AND_BENCHMARKS.md).

## How it works

1. **Seal it.** State and media are encrypted once (`ChaCha20-Poly1305`) and stored off-chain. Zcash gets a 512-byte ZIP 302 memo seal plus mint nullifiers that stop a slot being minted twice.
2. **Hand it over.** A transfer re-wraps only the 32-byte data key for the buyer (ephemeral Pallas ECDH) and folds one step into the object's Ragu proof.
3. **Show only what you choose.** A per-object viewing key discloses one item, and a zero-knowledge Merkle proof shows ownership, without revealing the rest of the wallet.

Each object carries a ZIP 227 `AssetDigest` / `AssetBase` from mint, so a Stage I seal can later be burned 1:1 into a native Zcash Shielded Asset (Stage II) and move to Tachyon commitments (Stage III).

## Profiles

| Profile | Use case | Rules today |
| :--- | :--- | :--- |
| `NFT1` | Art and collectibles: trade with no public owner list, royalty receipts | Ragu `RoyaltyCircuit` |
| `TKT1` | Event tickets: resell privately, check in once | Ragu `TicketCheckInCircuit` |
| `GAM1` | Game items: upgrades fold into the same proof as trades | Ragu `UpgradeCircuit` |
| `CRD1` | Credentials: bound to one holder, revocable | Host-side checks |
| `RWA1` | Real-world deeds: transfers gated by a compliance credential | Host-side checks |

## Workspace Layout (13 Crates)

| Crate | Status | Purpose |
| :--- | :--- | :--- |
| `zyoza-core` | Implemented | ZIP 227 `AssetDigest`/`AssetId`/`AssetBase`, 512B ZIP 302 `OrchardMemoSeal` (`0xFF\|\|"ZYOZ"`), `CollectionSpec`, `ObjectViewingKey`, core traits |
| `zyoza-oob` | Implemented | `ChaCha20Poly1305` + ephemeral Pallas ECDH (`HKDF-SHA256`) 32B DEK re-wrapping, `OobStorage`, seed-encrypted backups |
| `zyoza-proofs` | Implemented | Pure `tachyon-zcash/ragu` (one `Application` over Pasta at `WalletRank`, 10-slot lineage header) with 10 registered `Step<Pasta>` circuits: recursive PCD (`Mint`, `Transfer`, `Royalty`, `TicketCheckIn`, `Upgrade`), `OwnershipMerkleCircuit`, 16-bit `IssuanceCapCircuit`, `AttributeCircuit`, and `MigrationCircuit` |
| `zyoza-settlement` | Simulated Ledger | Real `orchard` key/address derivation, 2-of-3 Pallas threshold Schnorr signing (trusted-dealer setup), plus in-memory `OrchardSealAdapter`, `OrchardZsaAdapter`, and `TachyonAdapter` |
| `zyoza-profile-nft` | Implemented | `NFT1` collectibles (encrypted media manifest, royalties, time lockups, provenance) |
| `zyoza-profile-ticket` | Implemented | `TKT1` ticketing (one-time Poseidon/BLAKE2b check-in nullifiers, replay rejection) |
| `zyoza-profile-cred` | Implemented | `CRD1` soulbound credentials (non-transferability, issuer revocation registry) |
| `zyoza-profile-gaming` | Implemented | `GAM1` Lootz cypherpunk items (mutable XP, level-ups, equipment slots) |
| `zyoza-profile-rwa` | Implemented | `RWA1` tokenized real-world deeds (`CRD1` compliance gating, notary attestation) |
| `zyoza-sdk` | Implemented | High-level `ZyozaNftClient` + portable JSON/byte-slice FFI layer |
| `zyoza-wasm` | Implemented | `wasm-bindgen` browser verification & preview bindings |
| `zyoza-cli` | Implemented | CLI for `init`, `nft mint`, `nft transfer`, `nft inspect`, `prove-ownership`, `verify-proof`, `ticket` |
| `apps/gallery-demo` | Implemented | Axum web server: landing page (`/`), Zyoza Studio (`/demo`), Markdown-rendered `/whitepaper`, `/spec`, `/security`, and the commit-reveal auction API. Pages are compiled into the binary |

## Quickstart

Requires Rust `1.97+` (`rustc 1.99` tested). The first build compiles Ragu and takes a few minutes.

```bash
# Run the full workspace test suite (ZIP 227/302 vectors, all ten Ragu circuits, Studio HTTP API)
cargo test --workspace --offline
```

```bash
# Serve the landing page, Studio and docs at http://127.0.0.1:8080 (override with ZYOZA_LISTEN)
cargo run --release -p zyoza-gallery-demo
```

The HTML pages and docs are embedded at compile time, so rebuild and restart the server after editing anything under `apps/gallery-demo/src/*.html` or `docs/*.md`.

## Deployment (Fly.io)

The repo ships a `Dockerfile` and `fly.toml` for the gallery server. It runs as a single machine with no HA:

```bash
fly deploy --ha=false
```

* **Machine:** `shared-cpu-2x` with 1 GB RAM. The Ragu prover peaks near 360 MB, so 512 MB is too tight. On this size a fold took about 5 s before the Ragu upgrade (about 1 s on an M-series laptop now); the hosted machine has not been re-measured.
* **Idle behaviour:** the machine stops when idle and wakes on the next request. Studio state is in memory and shared by all visitors, so a stop or anyone's "Reset session" clears it.
* **First deploy of a new app:** allocate addresses once with `fly ips allocate-v4 --shared` and `fly ips allocate-v6`.
* **Lockfile:** `Cargo.lock` is committed and the Docker build uses `cargo build --locked`, so every build uses the same pinned Ragu revision.

## Documentation
* [Whitepaper (`docs/WHITEPAPER.md`)](docs/WHITEPAPER.md) — served live as HTML at `/whitepaper`
* [Protocol Specification (`docs/SPEC.md`)](docs/SPEC.md) — served live as HTML at `/spec`
* [Security Model, Constraints & Benchmarks (`docs/SECURITY_AND_BENCHMARKS.md`)](docs/SECURITY_AND_BENCHMARKS.md) — served live as HTML at `/security`

## Social assets
`docs/social/` holds launch images and the script that generates the pixel-art scene (`gyoza-party.py`).

## License
Licensed under either of **MIT** or **Apache-2.0** at your option.
