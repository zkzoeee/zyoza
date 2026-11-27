# 🥟 Zyoza — Shielded State Objects on Zcash

**Zyoza** is a modular, privacy-first **Shielded State Object** protocol on Zcash—launching first for **NFTs (`NFT1`)**, extensible to **ticketing (`TKT1`)** and **soulbound credentials (`CRD1`)**, live today on **Orchard**, and upgrade-ready for **ZSA (ZIP 226/227)** and **Tachyon + Ragu (non-uniform PCD)**.

## Workspace Layout

| Crate | Purpose |
| :--- | :--- |
| `zyoza-core` | ZIP 227 `AssetId`/`AssetBase`, 512B `OrchardMemoSeal`, `ObjectViewingKey`, core traits |
| `zyoza-oob` | `ChaCha20Poly1305` + Pallas ECDH key handover, `OobStorage`, encrypted backups |
| `zyoza-settlement` | `OrchardSealAdapter`, `OrchardRpcAdapter`, `OrchardZsaAdapter`, `TachyonAdapter`, FROST |
| `zyoza-proofs` | Halo2 Pasta IPA ownership/attribute/migration proofs + `RaguPcdEngine` |
| `zyoza-profile-nft` | `NFT1` profile (encrypted media manifest, royalties, lockups, provenance) |
| `zyoza-profile-ticket` | `TKT1` profile (anonymous one-time check-in nullifiers, replay rejection) |
| `zyoza-profile-cred` | `CRD1` profile (soulbound non-transferability, revocation registry) |
| `zyoza-sdk` | High-level `ZyozaNftClient` + portable JSON/byte-slice FFI layer |
| `zyoza-wasm` | `wasm-bindgen` browser bindings |
| `zyoza-cli` | CLI for `init`, `nft mint`, `nft transfer`, `nft inspect`, `prove-ownership`, `verify-proof` |
| `apps/gallery-demo` | Axum HTTP API + web UI for OVK-unlocked listings, ZK badges & sealed-bid auctions |

## Quickstart

```bash
# Run full workspace test suite (unit, Halo2, Ragu PCD, Tachyon 10k drop, HTTP API)
cargo test --workspace --offline

# Run the Gallery Demo HTTP server (default 127.0.0.1:8080)
cargo run -p zyoza-gallery-demo
```

## Documentation
* [Whitepaper](docs/WHITEPAPER.md)
* [Protocol Specification](docs/SPEC.md)
* [Security Model, Constraints & Benchmarks](docs/SECURITY_AND_BENCHMARKS.md)
