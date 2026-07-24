use anyhow::Result;
use clap::Parser;
use nyks_prover::ProverJobSettings;
use nyks_rpc_client::http::HttpClient;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::core::args::Args;
use crate::core::prover::init_prover_settings;
use crate::upgrader::flow::Upgrader;

mod core;
mod upgrader;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let filter =
        EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("nyks_upgrader=info,warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    info!("Initializing nyks-upgrader, architect of nyks transactions...");

    init_prover_settings(ProverJobSettings::default());
    let client = HttpClient::new(&args.rpc_url);
    let upgrader = Upgrader::new(args, client);

    upgrader.main_loop().await;

    Ok(())
}
