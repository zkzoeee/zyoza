use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use zyoza_core::{
    AssetDesc, AssetId, ObjectViewingKey, OwnershipProofRequest, OwnershipVerifyRequest,
    ProofEngine, SettlementAdapter,
};
use zyoza_oob::{LocalFsStorage, OobEnvelope, OobKeypair, OobStorage};
use zyoza_profile_nft::{CollectionPolicy, NftProfile, NftState};
use zyoza_profile_ticket::{TicketProfile, TicketState, TicketTransitionWitness};
use zyoza_proofs::Halo2ProofEngine;
use zyoza_sdk::ZyozaNftClient;
use zyoza_settlement::OrchardSealAdapter;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "zyoza", version, about = "🥟 Zyoza — Shielded State Objects on Zcash")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a local Zyoza workspace directory.
    Init {
        #[arg(long, default_value = ".zyoza")]
        dir: PathBuf,
    },
    /// NFT1 profile commands.
    Nft {
        #[command(subcommand)]
        action: NftCommands,
    },
    /// TKT1 ticketing profile commands.
    Ticket {
        #[command(subcommand)]
        action: TicketCommands,
    },
}

#[derive(Subcommand)]
enum TicketCommands {
    /// Mint a shielded Zyoza event ticket (TKT1).
    Mint {
        #[arg(long)]
        event_id: String,
        #[arg(long)]
        event_name: String,
        #[arg(long, default_value = "GA")]
        seat_tier: String,
    },
    /// Derive a one-time anonymous check-in nullifier for a ticket.
    Checkin {
        #[arg(long)]
        event_id: String,
        #[arg(long)]
        secret: String,
    },
}

#[derive(Subcommand)]
enum NftCommands {
    /// Mint a new shielded Zyoza NFT.
    Mint {
        #[arg(long, default_value = ".zyoza")]
        dir: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long)]
        creator: String,
        #[arg(long)]
        owner_seed: String,
        #[arg(long)]
        media_uri: String,
        #[arg(long, default_value = "genesis")]
        collection: String,
        #[arg(long, default_value = "1")]
        item_id: String,
    },
    /// Transfer a shielded Zyoza NFT to a new owner seed.
    Transfer {
        #[arg(long, default_value = ".zyoza")]
        dir: PathBuf,
        #[arg(long)]
        asset_id: String,
        #[arg(long)]
        from_seed: String,
        #[arg(long)]
        to_seed: String,
    },
    /// Inspect an NFT using its ObjectViewingKey (or shielded if omitted).
    Inspect {
        #[arg(long, default_value = ".zyoza")]
        dir: PathBuf,
        #[arg(long)]
        asset_id: String,
        #[arg(long)]
        owner_seed: String,
        #[arg(long)]
        ovk: Option<String>,
    },
    /// Generate a Halo2 Pasta ZK ownership proof for an NFT.
    ProveOwnership {
        #[arg(long, default_value = ".zyoza")]
        dir: PathBuf,
        #[arg(long)]
        asset_id: String,
        #[arg(long)]
        collection_root: String,
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        secret: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a Halo2 Pasta ZK ownership proof.
    VerifyProof {
        #[arg(long)]
        collection_root: String,
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        proof_file: PathBuf,
    },
}

#[derive(Default, Serialize, Deserialize)]
struct LocalLedger {
    nfts: HashMap<String, StoredNft>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredNft {
    asset_id_hex: String,
    commitment_hex: String,
    oob_uri: String,
    ovk_hex: String,
    state: NftState,
}

fn load_ledger(dir: &Path) -> Result<LocalLedger> {
    let path = dir.join("ledger.json");
    if !path.exists() {
        return Ok(LocalLedger::default());
    }
    let data = fs::read(&path)?;
    Ok(serde_json::from_slice(&data)?)
}

fn save_ledger(dir: &Path, ledger: &LocalLedger) -> Result<()> {
    let path = dir.join("ledger.json");
    fs::write(path, serde_json::to_vec_pretty(ledger)?)?;
    Ok(())
}

fn parse_32(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("invalid hex")?;
    if bytes.len() != 32 {
        bail!("expected 32-byte hex, got {} bytes", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { dir } => {
            fs::create_dir_all(dir.join("oob"))?;
            save_ledger(&dir, &LocalLedger::default())?;
            println!("Initialized Zyoza workspace at {}", dir.display());
        }
        Commands::Nft { action } => match action {
            NftCommands::Mint {
                dir,
                title,
                creator,
                owner_seed,
                media_uri,
                collection,
                item_id,
            } => {
                let seed = parse_32(&owner_seed)?;
                let owner_keys = OobKeypair::from_seed_bytes(&seed);
                let storage = LocalFsStorage::new(dir.join("oob"))?;
                let client = ZyozaNftClient::new(storage, OrchardSealAdapter::new(), Halo2ProofEngine);
                let mut rng = StdRng::seed_from_u64(1);

                let desc = AssetDesc {
                    namespace: "zyoza".to_string(),
                    collection,
                    item_id,
                };
                let out = client.mint_nft(
                    &mut rng,
                    &[0x01; 32],
                    &desc,
                    title,
                    "Minted via zyoza-cli".to_string(),
                    creator,
                    media_uri,
                    BTreeMap::new(),
                    CollectionPolicy {
                        royalty_bps: 0,
                        lockup_until_unix: None,
                    },
                    &owner_keys,
                    &seed,
                    1_700_000_000,
                )?;

                let mut ledger = load_ledger(&dir)?;
                let id_hex = out.asset_id.to_hex();
                let ovk_hex = hex::encode(out.viewing_key.key_bytes);
                ledger.nfts.insert(
                    id_hex.clone(),
                    StoredNft {
                        asset_id_hex: id_hex.clone(),
                        commitment_hex: hex::encode(out.commitment),
                        oob_uri: out.oob_uri.clone(),
                        ovk_hex: ovk_hex.clone(),
                        state: out.state,
                    },
                );
                save_ledger(&dir, &ledger)?;

                println!("Minted Zyoza NFT:");
                println!("  asset_id: {id_hex}");
                println!("  oob_uri:  {}", out.oob_uri);
                println!("  ovk:      {ovk_hex}");
            }
            NftCommands::Transfer {
                dir,
                asset_id,
                from_seed,
                to_seed,
            } => {
                let mut ledger = load_ledger(&dir)?;
                let entry = ledger
                    .nfts
                    .get(&asset_id)
                    .cloned()
                    .context("asset_id not found in local ledger")?;

                let from_keys = OobKeypair::from_seed_bytes(&parse_32(&from_seed)?);
                let to_keys = OobKeypair::from_seed_bytes(&parse_32(&to_seed)?);
                let storage = LocalFsStorage::new(dir.join("oob"))?;
                let prev_oob: OobEnvelope = storage.get(&entry.oob_uri)?;
                let prev_commit = parse_32(&entry.commitment_hex)?;

                let settlement = OrchardSealAdapter::new();
                // Re-anchor prior commitment into local adapter state for CLI simulation.
                let dummy_memo = zyoza_core::OrchardMemoSeal {
                    version: zyoza_core::PROTOCOL_VERSION,
                    profile_id: *b"NFT1",
                    asset_id: entry.state.asset_id,
                    state_root: entry.state.state_root()?,
                    nonce: [0u8; 32],
                    oob_pointer_hash: [0u8; 32],
                    oob_uri: entry.oob_uri.clone(),
                }
                .to_bytes()?;
                settlement.anchor_mint(&entry.state.asset_id, prev_commit, &dummy_memo)?;

                let client = ZyozaNftClient::new(storage, settlement, Halo2ProofEngine);
                let mut rng = StdRng::seed_from_u64(2);
                let out = client.transfer_nft(
                    &mut rng,
                    &entry.state,
                    prev_commit,
                    &prev_oob,
                    &from_keys,
                    &to_keys,
                    true,
                    1_700_000_100,
                )?;

                ledger.nfts.insert(
                    asset_id.clone(),
                    StoredNft {
                        asset_id_hex: asset_id.clone(),
                        commitment_hex: hex::encode(out.commitment),
                        oob_uri: out.oob_uri.clone(),
                        ovk_hex: entry.ovk_hex,
                        state: out.state,
                    },
                );
                save_ledger(&dir, &ledger)?;
                println!("Transferred Zyoza NFT {asset_id} -> {}", out.oob_uri);
            }
            NftCommands::Inspect {
                dir,
                asset_id,
                owner_seed,
                ovk,
            } => {
                let ledger = load_ledger(&dir)?;
                let entry = ledger
                    .nfts
                    .get(&asset_id)
                    .context("asset_id not found in local ledger")?;
                let owner_keys = OobKeypair::from_seed_bytes(&parse_32(&owner_seed)?);
                let storage = LocalFsStorage::new(dir.join("oob"))?;
                let oob = storage.get(&entry.oob_uri)?;
                let state_bytes = oob.open(&owner_keys.secret)?;
                let ovk_obj = match ovk {
                    Some(k) => Some(ObjectViewingKey {
                        asset_id: AssetId(parse_32(&asset_id)?),
                        key_bytes: parse_32(&k)?,
                    }),
                    None => None,
                };
                let preview = zyoza_core::AssetProfile::public_preview(
                    &NftProfile,
                    &state_bytes,
                    ovk_obj.as_ref(),
                )?;
                println!("{}", serde_json::to_string_pretty(&preview)?);
            }
            NftCommands::ProveOwnership {
                dir,
                asset_id,
                collection_root,
                challenge,
                secret,
                out,
            } => {
                let _ = load_ledger(&dir)?;
                let proof = Halo2ProofEngine.prove_ownership(&OwnershipProofRequest {
                    asset_id: AssetId(parse_32(&asset_id)?),
                    collection_root: parse_32(&collection_root)?,
                    secret_witness: secret.into_bytes(),
                    challenge: parse_32(&challenge)?,
                })?;
                fs::write(&out, &proof)?;
                println!("Wrote Halo2 ownership proof ({} bytes) to {}", proof.len(), out.display());
            }
            NftCommands::VerifyProof {
                collection_root,
                challenge,
                proof_file,
            } => {
                let proof = fs::read(&proof_file)?;
                let ok = Halo2ProofEngine.verify_ownership(
                    &OwnershipVerifyRequest {
                        collection_root: parse_32(&collection_root)?,
                        challenge: parse_32(&challenge)?,
                    },
                    &proof,
                )?;
                println!("Proof valid: {ok}");
                if !ok {
                    bail!("proof verification failed");
                }
            }
        },
        Commands::Ticket { action } => match action {
            TicketCommands::Mint {
                event_id,
                event_name,
                seat_tier,
            } => {
                let desc = AssetDesc {
                    namespace: "zyoza".into(),
                    collection: event_id.clone(),
                    item_id: seat_tier.clone(),
                };
                let asset_id = AssetId::derive(&[0x01; 32], &desc.to_canonical_bytes());
                let tkt = TicketState {
                    asset_id,
                    event_id,
                    event_name,
                    seat_tier,
                    transferable: true,
                    checked_in: false,
                };
                let wit = serde_json::to_vec(&TicketTransitionWitness { is_checkin: false })?;
                zyoza_core::AssetProfile::validate_transition(
                    &TicketProfile,
                    None,
                    &tkt.to_bytes()?,
                    &wit,
                )?;
                println!("Minted TKT1 ticket: asset_id={}", asset_id.to_hex());
            }
            TicketCommands::Checkin { event_id, secret } => {
                let tkt = TicketState {
                    asset_id: AssetId([0u8; 32]),
                    event_id,
                    event_name: String::new(),
                    seat_tier: String::new(),
                    transferable: true,
                    checked_in: true,
                };
                let nf = tkt.derive_checkin_nullifier(secret.as_bytes());
                println!("TKT1 check-in nullifier: {}", hex::encode(nf));
            }
        },
    }
    Ok(())
}
