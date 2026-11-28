# Zyoza Protocol Specification (`v2.0`)

Zyoza is a modular **Shielded State Object** protocol on Zcash—launching first for **NFTs (`NFT1`)**, extensible to **ticketing (`TKT1`)**, **soulbound credentials (`CRD1`)**, **cypherpunk gaming items (`GAM1`)**, and **tokenized real-world deeds (`RWA1`)**.

> **Implementation Boundary:** Cryptographic primitives (`AssetDigest`/`AssetBase`, 512-byte ZIP 302 codec, `ChaCha20Poly1305` + Pallas ECDH key wrapping, unified 10-circuit `tachyon-zcash/ragu` PCD & ZK proofs, and 2-of-3 Pallas Schnorr threshold signing) are implemented and tested in Rust; Orchard, ZSA, and Tachyon ledger adapters currently execute in memory (`Simulated`).

---

## 1. ZIP 227-Aligned `AssetDigest`, `AssetId`, and `AssetBase`

Every Zyoza object derives its 64-byte `AssetDigest`, 32-byte `AssetId`, and Pallas curve point `AssetBase` deterministically from its issuer key (`ik`) and canonical asset description bytes, matching **ZIP 227**:

1. **Description Collision-Resistant Hash (`32 bytes`):**
   `desc_hash = BLAKE2b-256(personal = "ZSA-AssetDescCRH", input = asset_desc)`
2. **ZIP 227 Asset Digest (`64 bytes`, version byte `0x00`):**
   `asset_digest = BLAKE2b-512(personal = "ZSA-Asset-Digest", input = [0x00] || ik || desc_hash)`
3. **Compact Stage I Seal Identifier (`32 bytes`):**
   `asset_id = asset_digest[0..32]`
4. **OrchardZSA Value Commitment Base (Pallas Point):**
   `asset_base = GroupHash^P(domain = "z.cash:OrchardZSA", input = asset_digest)`

Because `asset_digest` and `asset_base` follow ZIP 227 from genesis, Stage I single-use seals crystallize 1:1 into Stage II native OrchardZSA notes (`value = 1`, `finalized = true`) without re-keying identity.

---

## 2. 512-Byte ZIP 302 Orchard Memo Seal Binary Layout

Per **ZIP 302**, memos starting with `0xFF` indicate arbitrary non-text binary application data so standard Zcash wallets never render binary seals as garbled UTF-8. Each Stage I transition packs a 512-byte seal with magic `[0xFF, 'Z', 'Y', 'O', 'Z']`:

| Offset (bytes) | Size | Field | Type / Encoding | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0..5` | 5 | `magic` | `[u8; 5]` | `[0xFF, b'Z', b'Y', b'O', b'Z']` (`ff5a594f5a`) |
| `5..7` | 2 | `version` | `u16` (BE) | Protocol version (`0x0001`) |
| `7..11` | 4 | `profile_id` | `[u8; 4]` | Vertical ID (`"NFT1"`, `"TKT1"`, `"CRD1"`, `"GAM1"`, `"RWA1"`) |
| `11..43` | 32 | `asset_id` | `[u8; 32]` | `AssetDigest[0..32]` |
| `43..75` | 32 | `state_root` | `[u8; 32]` | `SHA-256` commitment to canonical off-chain profile state |
| `75..107` | 32 | `nonce` | `[u8; 32]` | Per-transition randomness |
| `107..139` | 32 | `oob_pointer_hash` | `[u8; 32]` | `BLAKE2b-256` integrity hash of the `OobEnvelope` |
| `139..141` | 2 | `oob_uri_len` | `u16` (BE) | Byte length of `oob_uri` (`0..=371`) |
| `141..512` | 371 | `oob_uri_bytes` | `[u8; 371]` | UTF-8 OOB pointer URI/CID, zero-padded |

Total: `5 + 2 + 4 + 32 + 32 + 32 + 32 + 2 + 371 = 512` bytes.

---

## 3. Out-of-Band (OOB) Envelope Schema (`zyoza-oob`)

Heavy payloads (encrypted media, metadata manifests, and Ragu recursive proofs) travel out-of-band, aligning with **Project Tachyon's** removal of in-band 512-byte encrypted memos:

```json
{
  "version": 1,
  "profile_id": "NFT1",
  "asset_id": "<64-char hex>",
  "state_root": "<64-char hex>",
  "nonce": "<64-char hex>",
  "cipher": "chacha20poly1305",
  "cipher_nonce": "<24-char hex>",
  "encrypted_payload_b64": "<base64 ciphertext>",
  "wrapped_key": {
    "scheme": "ecdh-pallas-hkdf-sha256",
    "ephemeral_pk": "<64-char hex>",
    "wrap_nonce": "<24-char hex>",
    "ciphertext_b64": "<base64 wrapped 32B DEK>"
  },
  "integrity_hash": "<64-char hex>"
}
```

Transfers call `OobEnvelope::rewrap_for_recipient`, unwrapping only the 32-byte `DEK` and re-encapsulating it to the recipient's Pallas public key without re-encrypting or re-uploading media blobs.

---

## 4. Core Trait Boundaries (`zyoza-core`) & Ragu Circuits (`zyoza-proofs`)

1. **`AssetProfile`** — Vertical-specific schema, transition validation, and `ObjectViewingKey` selective-disclosure preview (`NFT1`, `TKT1`, `CRD1`, `GAM1`, `RWA1`).
2. **`SettlementAdapter`** — Swappable anchor backend (`OrchardSealAdapter` -> `OrchardZsaAdapter` -> `TachyonAdapter`).
3. **`ProofEngine`** — Implemented purely via `RaguPcdEngine` (`tachyon-zcash/ragu`, `Application<Pasta, WalletRank, 5>`, 10 registered `Step<Pasta>` subcircuits, `6,208 B` constant `CompressedProof<Pasta>`).

---

## 5. Canonical Test Vectors

### Vector 1: `AssetDigest::derive` & `AssetId::derive`
* **Inputs:**
  * `issuer_vk`: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` (`[0xaa; 32]`)
  * `asset_desc`: `7a796f7a613a6e66743a67656e657369733a30303031` (`"zyoza:nft:genesis:0001"`)
* **Output (`asset_id = asset_digest[0..32]`):**
  * `042c6151e59c2efb60192f1f1f8eb02c985b9b51bce636058ebb755db8634854` *(verified by `zyoza_core::tests::canonical_asset_id_and_seal_roundtrip`)*

### Vector 2: `OrchardMemoSeal` Binary Header (`512 bytes`)
* `magic` (`0..5`): `ff5a594f5a` (`0xFF || "ZYOZ"`)
* `version` (`5..7`): `0001`
* `profile_id` (`7..11`): `4e465431` (`"NFT1"`)
* `asset_id` (`11..43`): `042c6151e59c2efb60192f1f1f8eb02c985b9b51bce636058ebb755db8634854`
* `state_root` (`43..75`): `1111...1111` (`[0x11; 32]`)
* `nonce` (`75..107`): `2222...2222` (`[0x22; 32]`)
* `oob_pointer_hash` (`107..139`): `3333...3333` (`[0x33; 32]`)
* `oob_uri` (`139..512`): `"ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"` (`oob_uri_len = 0x0042` = 66 bytes, remaining 305 bytes zero-padded)
