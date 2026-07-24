use std::panic;

use anyhow::Result;
use clap::Parser;
use nyks_rpc_client::http::HttpClient;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::composer::flow::Composer;
use crate::core::args::Args;

pub mod composer;
pub mod core;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let filter = EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("nyks_composer=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        default_hook(panic_info);
        std::process::exit(1);
    }));

    info!("Initializing nyks-composer, the architect of nyks blocks...");

    let client = HttpClient::new(args.rpc_url.clone());
    let prover = Composer::new(args, client);

    prover.main_loop().await;

    Ok(())
}
