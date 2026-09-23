pub mod core;
mod dashboard;
mod setup;

use std::panic;

use anyhow::Result;
use clap::Parser;
use nyks_consensus::network::Network;
use nyks_rpc_client::http::HttpClient;
use nyks_wallet_core::entropy::wallet_entropy::WalletEntropy;
use nyks_wallet_sdk::wallet::Wallet;

use crate::core::storage::Storage;

#[derive(Parser)]
#[command(name = "nyks-wallet")]
#[command(about = "A nyks daemon wallet")]
struct Args {
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

    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // Always leave the terminal usable, even if we panic mid-draw.
        core::tui::restore();
        default_hook(panic_info);
        std::process::exit(1);
    }));

    let rpc = HttpClient::new(args.rpc_url);
    let storage = Storage::new(args.wallet_dir);

    let entropy = match storage.keys.get_mnemonic() {
        Some(mnemonic) => {
            let words: Vec<String> = mnemonic.split_whitespace().map(str::to_owned).collect();
            WalletEntropy::from_phrase(&words)
                .map_err(|e| anyhow::anyhow!("stored mnemonic is corrupt: {e}"))?
        }
        None => setup::run(&storage)?,
    };

    let wallet = Wallet::new(rpc, entropy, storage.chain.get_height(), args.network);

    // Import initial state of wallet.
    wallet.import_utxos(storage.utxos.iter().collect()).await;

    // Sync loop runs in the background; the TUI takes over the main task and
    // owns the terminal until the user quits.
    tokio::spawn(core::sync::run(wallet.clone(), storage));

    dashboard::run(wallet).await
}
