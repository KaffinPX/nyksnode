use std::panic;

use anyhow::Result;
use clap::Parser;
use nyks_rpc_client::http::HttpClient;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::flow::Miner;

pub mod flow;
pub mod guesser;

#[derive(Parser)]
#[command(name = "nyks-miner")]
#[command(about = "A nyks CPU miner")]
struct Args {
    /// Address to mine for (coinbase reward receiver)
    #[arg(long)]
    address: String,
    /// RPC URL to use (JSON/HTTP)
    #[arg(long)]
    rpc_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let filter = EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("nyks_miner=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        default_hook(panic_info);
        std::process::exit(1);
    }));

    info!("Initializing nyks-miner, the operator of nyks blocks...");

    let client = HttpClient::new(args.rpc_url);
    let miner = Miner::new(client, args.address);

    miner.main_loop().await;

    Ok(())
}
