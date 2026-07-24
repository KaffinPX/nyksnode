use std::panic;
use std::time::Duration;

use anyhow::Result;
use anyhow::bail;
use clap::Parser;
use nyks_protocol::consensus::network::Network;
use nyks_rpc_client::http::HttpClient;
use nyks_wallet_core::entropy::wallet_entropy::WalletEntropy;
use nyks_wallet_sdk::wallet::Wallet;
use nyks_wallet_sdk::wallet::WalletEvent;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::core::storage::Storage;

pub mod core;

#[derive(Parser)]
#[command(name = "nyks-wallet")]
#[command(about = "A nyks daemon wallet")]
struct Args {
    /// Mnemonic to import.
    #[arg(long)]
    mnemonic: Option<String>,

    /// RPC URL to use (JSON/HTTP).
    #[arg(long)]
    rpc_url: String,

    /// Directory to store wallet data in.
    #[arg(long, default_value = "./wallet_data")]
    wallet_dir: String,

    /// Network to connect to.
    #[arg(long, default_value = "main")]
    network: Network,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let filter = EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("nyks_wallet=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        default_hook(panic_info);
        std::process::exit(1);
    }));

    let rpc = HttpClient::new(args.rpc_url);
    let storage = Storage::new(args.wallet_dir);
    let entropy = resolve_mnemonic(&storage, args.mnemonic)?;
    let wallet = Wallet::new(rpc, entropy, storage.chain.get_height(), args.network);

    // Import initial state of wallet.
    wallet.import_utxos(storage.utxos.iter().collect()).await;

    // Start console "readline" task.
    tokio::spawn(core::console::start_console(wallet.clone()));

    // Start sync loop
    let mut interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        interval.tick().await;

        let events = wallet.sync().await.unwrap();

        for event in events {
            match event {
                WalletEvent::UtxoReceived { key, utxo } => {
                    match utxo.inclusion_block {
                        Some((_, block_height)) => info!(
                            "Discovered new UTXO containing {} NYKS on block {} (AOCL leaf {}).",
                            utxo.get_native_currency_amount(),
                            block_height,
                            utxo.membership_proof.aocl_leaf_index,
                        ),
                        None => info!(
                            "Discovered new UTXO containing {} NYKS (AOCL leaf {}).",
                            utxo.get_native_currency_amount(),
                            utxo.membership_proof.aocl_leaf_index,
                        ),
                    }

                    storage.utxos.put(&key, &utxo);
                }
                WalletEvent::UtxoInvalidated { key, utxo } => {
                    info!(
                        "UTXO containing {} NYKS was invalidated and marked as spent in an unknown block (AOCL leaf {}).",
                        utxo.get_native_currency_amount(),
                        utxo.membership_proof.aocl_leaf_index,
                    );

                    storage.utxos.put(&key, &utxo);
                }
            }
        }

        storage.chain.set_height(wallet.height().await);
    }
}

fn phrase_to_words(phrase: &str) -> Vec<String> {
    phrase.split_whitespace().map(str::to_owned).collect()
}

/// Resolves and validates the mnemonic for this session, returning a `WalletEntropy`.
///
/// - If `--mnemonic` is passed and no wallet exists, validates, imports, and returns it.
/// - If `--mnemonic` is passed and a wallet already exists, returns an error.
/// - If no `--mnemonic` is passed and a wallet exists, parses and returns the stored one.
/// - If no `--mnemonic` is passed and no wallet exists, returns an error with instructions.
fn resolve_mnemonic(storage: &Storage, mnemonic_arg: Option<String>) -> Result<WalletEntropy> {
    match (mnemonic_arg, storage.keys.get_mnemonic()) {
        (Some(_), Some(_)) => {
            bail!("a wallet is already imported; remove ./wallet_data to start fresh");
        }
        (Some(mnemonic), None) => {
            let words = phrase_to_words(&mnemonic);
            let entropy = WalletEntropy::from_phrase(&words)
                .map_err(|e| anyhow::anyhow!("invalid mnemonic: {e}"))?;
            storage.keys.set_mnemonic(&mnemonic);
            info!("mnemonic imported successfully");
            Ok(entropy)
        }
        (None, Some(mnemonic)) => {
            let words = phrase_to_words(&mnemonic);
            let entropy = WalletEntropy::from_phrase(&words)
                .map_err(|e| anyhow::anyhow!("stored mnemonic is corrupt: {e}"))?;
            Ok(entropy)
        }
        (None, None) => {
            bail!("no wallet found; import one with --mnemonic <MNEMONIC>");
        }
    }
}
