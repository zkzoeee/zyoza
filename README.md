# Zyoza — Proof-Carrying Shielded State Objects on Zcash

> **Status:** Research prototype — 100% unified `tachyon-zcash/ragu` non-uniform recursive PCD & zero-knowledge circuits (10 registered `Step<Pasta>` subcircuits), Pallas ECDH + ChaCha20-Poly1305 out-of-band wrapping, ZIP 227 `AssetDigest`/`AssetBase`, ZIP 302 binary memo seals, and salted commit-reveal auctions executing over a simulated in-memory settlement ledger. Not audited.

**Zyoza** lets creators and collectors mint, transfer, selectively disclose, and trade private NFTs, event tickets, credentials, game items, and deeds on Zcash without leaking ownership history or bloating L1 state.

## Workspace Layout (13 Crates)

| Crate | Status | Purpose |
| :--- | :--- | :--- |
| `zyoza-core` | Implemented | ZIP 227 `AssetDigest`/`AssetId`/`AssetBase`, 512B ZIP 302 `OrchardMemoSeal` (`0xFF\|\|"ZYOZ"`), `CollectionSpec`, `ObjectViewingKey`, core traits |
| `zyoza-oob` | Implemented | `ChaCha20Poly1305` + ephemeral Pallas ECDH (`HKDF-SHA256`) 32B DEK re-wrapping, `OobStorage`, seed-encrypted backups |
| `zyoza-proofs` | Implemented | Pure `tachyon-zcash/ragu` (`Application<Pasta, WalletRank, 5>`) with 10 registered `Step<Pasta>` circuits: recursive PCD (`Mint`, `Transfer`, `Royalty`, `TicketCheckIn`, `Upgrade`), `OwnershipMerkleCircuit`, 16-bit `IssuanceCapCircuit`, `AttributeCircuit`, and `MigrationCircuit` |
| `zyoza-settlement` | Simulated Ledger | Real `orchard` key/address derivation, 2-of-3 Pallas threshold Schnorr signing (trusted-dealer setup), plus in-memory `OrchardSealAdapter`, `OrchardZsaAdapter`, and `TachyonAdapter` |
| `zyoza-profile-nft` | Implemented | `NFT1` collectibles (encrypted media manifest, royalties, time lockups, provenance) |
| `zyoza-profile-ticket` | Implemented | `TKT1` ticketing (one-time Poseidon/BLAKE2b check-in nullifiers, replay rejection) |
| `zyoza-profile-cred` | Implemented | `CRD1` soulbound credentials (non-transferability, issuer revocation registry) |
| `zyoza-profile-gaming` | Implemented | `GAM1` Lootz cypherpunk items (mutable XP, level-ups, equipment slots) |
| `zyoza-profile-rwa` | Implemented | `RWA1` tokenized real-world deeds (`CRD1` compliance gating, notary attestation) |
| `zyoza-sdk` | Implemented | High-level `ZyozaNftClient` + portable JSON/byte-slice FFI layer |
| `zyoza-wasm` | Implemented | `wasm-bindgen` browser verification & preview bindings |
| `zyoza-cli` | Implemented | CLI for `init`, `nft mint`, `nft transfer`, `nft inspect`, `prove-ownership`, `verify-proof`, `ticket` |
| `apps/gallery-demo` | Implemented | Axum web server (`/`, `/demo` Zyoza Studio, Markdown-rendered `/whitepaper`, `/spec`, `/security`, and commit-reveal auction API) |

## Quickstart

Requires Rust `1.97+` (`rustc 1.99+` tested).

```bash
# Run full workspace test suite (ZIP 227/302 vectors, 10-circuit Ragu PCD/ZK suite, Tachyon 10k drop, Studio HTTP API)
cargo test --workspace --offline

# Launch Landing Page + Zyoza Studio + Whitepaper (defaults to http://127.0.0.1:8080; override via ZYOZA_LISTEN)
ZYOZA_LISTEN=127.0.0.1:8080 cargo run -p zyoza-gallery-demo
```

## Documentation
* [Whitepaper (`docs/WHITEPAPER.md`)](docs/WHITEPAPER.md) — served live as HTML at `/whitepaper`
* [Protocol Specification (`docs/SPEC.md`)](docs/SPEC.md) — served live as HTML at `/spec`
* [Security Model, Constraints & Benchmarks (`docs/SECURITY_AND_BENCHMARKS.md`)](docs/SECURITY_AND_BENCHMARKS.md) — served live as HTML at `/security`

## License
Licensed under either of **MIT** or **Apache-2.0** at your option.
