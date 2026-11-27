# 🥟 Zyoza Protocol Specification (`v1`)

Zyoza is a modular **Shielded State Object** protocol on Zcash—launching first for **NFTs (`NFT1`)**, immediately extensible to **ticketing (`TKT1`)**, **credentials (`CRD1`)**, and **gaming/RWAs**, live today on **Orchard**, and upgrade-compatible with **ZSA (ZIP 226/227)** and **Tachyon + Ragu (non-uniform PCD)**.

---

## 1. ZIP 227-Compatible `AssetId` & `AssetBase` Derivation

Every Zyoza object derives its 32-byte `AssetId` deterministically from its issuer verification key and canonical asset description bytes, matching ZIP 227's domain-separated structure:

1. **Description Hash:**
   `desc_hash = BLAKE2b-256(personal = "ZSA-AssetDesc___", input = asset_desc)`
2. **Asset Identifier (`AssetId`):**
   `asset_id = BLAKE2b-256(personal = "ZSA-AssetId_____", input = issuer_vk || desc_hash)`
3. **Asset Base (OrchardZSA Phase 4):**
   `asset_base = GroupHash("z.cash:OrchardZSA", asset_id)` on the Pallas curve.

Because `asset_id` is derived identically in Phase 1 (Orchard single-use seal) and Phase 4 (native OrchardZSA), existing objects crystallize 1:1 into native L1 ZSA notes without breaking identity or provenance.

---

## 2. 512-Byte Orchard Memo Seal Binary Layout

In Phase 1, each mint or transfer anchors a single-use seal inside an Orchard action's 512-byte encrypted memo field:

| Offset (bytes) | Size | Field | Type / Encoding | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0..4` | 4 | `magic` | `[u8; 4]` | ASCII `"ZYOZ"` (`0x5a594f5a`) |
| `4..6` | 2 | `version` | `u16` (BE) | Protocol version (`0x0001`) |
| `6..10` | 4 | `profile_id` | `[u8; 4]` | Vertical ID (e.g. `"NFT1"`, `"TKT1"`, `"CRD1"`) |
| `10..42` | 32 | `asset_id` | `[u8; 32]` | ZIP 227-derived `AssetId` |
| `42..74` | 32 | `state_root` | `[u8; 32]` | Commitment to current off-chain state |
| `74..106` | 32 | `nonce` | `[u8; 32]` | Per-transition random/sequential nonce |
| `106..138` | 32 | `oob_pointer_hash` | `[u8; 32]` | BLAKE2b-256 hash of the canonical OOB envelope |
| `138..140` | 2 | `oob_uri_len` | `u16` (BE) | Byte length of `oob_uri` (`0..=372`) |
| `140..512` | 372 | `oob_uri_bytes` | `[u8; 372]` | UTF-8 OOB pointer URI/CID, zero-padded |

Total: `4 + 2 + 4 + 32 + 32 + 32 + 32 + 2 + 372 = 512` bytes.

---

## 3. Out-of-Band (OOB) Envelope Schema

Heavy payloads (encrypted art/media, metadata manifests, provenance proofs, and wrapped decryption keys) travel out-of-band, aligning with **Tachyon's** removal of in-band secret distribution:

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
    "ciphertext_b64": "<base64 wrapped symmetric key>"
  },
  "integrity_hash": "<64-char hex>"
}
```

---

## 4. Core Trait Boundaries (`zyoza-core`)

1. **`AssetProfile`** — Vertical-specific schema, transition validation, and selective-disclosure preview (`NFT1`, `TKT1`, `CRD1`).
2. **`SettlementAdapter`** — Swappable L1 anchor (`orchard_seal` → `orchard_zsa` → `tachyon`).
3. **`ProofEngine`** — Swappable ZK prover/verifier (`halo2` → `ragu` non-uniform PCD).

---

## 5. Canonical Test Vectors

### Vector 1: `AssetId::derive`
* **Inputs:**
  * `issuer_vk`: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` (`[0xaa; 32]`)
  * `asset_desc`: `7a796f7a613a6e66743a67656e657369733a30303031` (`"zyoza:nft:genesis:0001"`)
* **Output (`asset_id`):**
  * `4dc1131d5acc7767bdb447240316d5a8f7294b8f80ce90416b7e8fecc1870aa6` *(verified by `zyoza-core::tests::canonical_asset_id_and_seal_roundtrip`)*

### Vector 2: `OrchardMemoSeal` Header (512 bytes)
* `magic`: `5a594f5a` (`"ZYOZ"`)
* `version`: `0001`
* `profile_id`: `4e465431` (`"NFT1"`)
* `asset_id`: `4dc1131d5acc7767bdb447240316d5a8f7294b8f80ce90416b7e8fecc1870aa6`
* `state_root`: `1111...1111` (`[0x11; 32]`)
* `nonce`: `2222...2222` (`[0x22; 32]`)
* `oob_pointer_hash`: `3333...3333` (`[0x33; 32]`)
* `oob_uri`: `"ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"` (`oob_uri_len = 0x0042` = 66 bytes, remaining 306 bytes zero-padded)
