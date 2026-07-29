use std::panic;

use anyhow::Result;
use clap::Parser;
use nyks_rpc_client::http::HttpClient;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::core::args::Args;
use crate::miner::flow::Miner;

pub mod core;
pub mod miner;

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

    args.validate_address();

    let client = HttpClient::new(args.rpc_url.clone());
    let miner = Miner::new(client, args.address.clone(), args.min_reward_fraction());

    miner.main_loop().await;

    Ok(())
}
