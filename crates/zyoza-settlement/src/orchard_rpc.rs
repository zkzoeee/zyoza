//! JSON-RPC settlement adapter for `zcashd` / `zebrad` Orchard transactions.

use zyoza_core::{
    AssetId, ZyozaError, OrchardMemoSeal, SettlementAdapter, SettlementReceipt, ORCHARD_MEMO_LEN,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Mutex;

/// Connection and address configuration for a Zcash node JSON-RPC endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    pub url: String,
    pub from_ua: String,
    pub to_ua: String,
    pub fee_zatoshis: u64,
}

/// Transport abstraction for issuing Zcash JSON-RPC 2.0 requests.
pub trait RpcTransport: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value, ZyozaError>;
}

/// `SettlementAdapter` that anchors 512-byte `OrchardMemoSeal` commitments via `z_sendmany`.
pub struct OrchardRpcAdapter<T: RpcTransport> {
    config: RpcConfig,
    transport: T,
    spent_commitments: Mutex<HashSet<[u8; 32]>>,
}

impl<T: RpcTransport> OrchardRpcAdapter<T> {
    /// Creates a new `OrchardRpcAdapter` with the given config and transport.
    pub fn new(config: RpcConfig, transport: T) -> Self {
        Self {
            config,
            transport,
            spent_commitments: Mutex::new(HashSet::new()),
        }
    }

    fn send_memo_tx(
        &self,
        commitment: [u8; 32],
        memo: &[u8; ORCHARD_MEMO_LEN],
    ) -> Result<SettlementReceipt, ZyozaError> {
        let memo_hex = hex::encode(memo);
        let amount_zec = (self.config.fee_zatoshis as f64) / 100_000_000.0;
        let params = json!([
            self.config.from_ua,
            [{
                "address": self.config.to_ua,
                "amount": amount_zec,
                "memo": memo_hex,
            }],
            1
        ]);

        let resp = self.transport.call("z_sendmany", params)?;
        let txid_hex = resp
            .as_str()
            .ok_or_else(|| ZyozaError::Settlement("z_sendmany did not return txid/opid".into()))?;

        let mut tx_id = [0u8; 32];
        if let Ok(bytes) = hex::decode(txid_hex) {
            if bytes.len() == 32 {
                tx_id.copy_from_slice(&bytes);
            }
        }

        Ok(SettlementReceipt {
            backend: "orchard_rpc".to_string(),
            tx_id,
            commitment,
            block_height: None,
        })
    }
}

impl<T: RpcTransport> SettlementAdapter for OrchardRpcAdapter<T> {
    fn anchor_mint(
        &self,
        asset_id: &AssetId,
        state_commitment: [u8; 32],
        memo: &[u8; ORCHARD_MEMO_LEN],
    ) -> Result<SettlementReceipt, ZyozaError> {
        let parsed = OrchardMemoSeal::from_bytes(memo)?;
        if parsed.asset_id != *asset_id {
            return Err(ZyozaError::Settlement("RPC memo asset_id mismatch".into()));
        }
        self.send_memo_tx(state_commitment, memo)
    }

    fn anchor_transfer(
        &self,
        asset_id: &AssetId,
        prev_commitment: [u8; 32],
        next_commitment: [u8; 32],
        memo: &[u8; ORCHARD_MEMO_LEN],
    ) -> Result<SettlementReceipt, ZyozaError> {
        let parsed = OrchardMemoSeal::from_bytes(memo)?;
        if parsed.asset_id != *asset_id {
            return Err(ZyozaError::Settlement("RPC memo asset_id mismatch".into()));
        }
        if !self.spent_commitments.lock().unwrap().insert(prev_commitment) {
            return Err(ZyozaError::Settlement(
                "double-spend rejected: commitment already spent".into(),
            ));
        }
        self.send_memo_tx(next_commitment, memo)
    }

    fn verify_seal(&self, receipt: &SettlementReceipt) -> Result<bool, ZyozaError> {
        if self.spent_commitments.lock().unwrap().contains(&receipt.commitment) {
            return Ok(false);
        }
        let txid_hex = hex::encode(receipt.tx_id);
        let resp = self
            .transport
            .call("getrawtransaction", json!([txid_hex, 1]))?;
        Ok(resp.get("confirmations").and_then(|v| v.as_u64()).unwrap_or(0) >= 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zyoza_core::PROTOCOL_VERSION;

    struct MockRpcTransport;

    impl RpcTransport for MockRpcTransport {
        fn call(&self, method: &str, params: Value) -> Result<Value, ZyozaError> {
            match method {
                "z_sendmany" => {
                    let arr = params.as_array().unwrap();
                    let memo = arr[1][0]["memo"].as_str().unwrap();
                    assert_eq!(memo.len(), ORCHARD_MEMO_LEN * 2);
                    Ok(Value::String("aa".repeat(32)))
                }
                "getrawtransaction" => Ok(json!({ "confirmations": 3 })),
                other => Err(ZyozaError::Settlement(format!("unexpected RPC: {other}"))),
            }
        }
    }

    #[test]
    fn orchard_rpc_mint_transfer_and_verify() {
        let adapter = OrchardRpcAdapter::new(
            RpcConfig {
                url: "http://127.0.0.1:18232".into(),
                from_ua: "utest1from".into(),
                to_ua: "utest1to".into(),
                fee_zatoshis: 10_000,
            },
            MockRpcTransport,
        );
        let asset_id = AssetId::derive(&[0x01; 32], b"zyoza:rpc:1");
        let memo = OrchardMemoSeal {
            version: PROTOCOL_VERSION,
            profile_id: *b"NFT1",
            asset_id,
            state_root: [0x11; 32],
            nonce: [0x22; 32],
            oob_pointer_hash: [0x33; 32],
            oob_uri: "ipfs://rpc".into(),
        }
        .to_bytes()
        .unwrap();

        let mint = adapter.anchor_mint(&asset_id, [0x11; 32], &memo).unwrap();
        assert!(adapter.verify_seal(&mint).unwrap());

        let xfer = adapter
            .anchor_transfer(&asset_id, [0x11; 32], [0x22; 32], &memo)
            .unwrap();
        assert!(!adapter.verify_seal(&mint).unwrap());
        assert!(adapter.verify_seal(&xfer).unwrap());
        assert!(adapter
            .anchor_transfer(&asset_id, [0x11; 32], [0x33; 32], &memo)
            .is_err());
    }
}
