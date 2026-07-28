use clap::Parser;
use nyks_protocol::consensus::network::Network;

#[derive(Parser)]
#[command(name = "nyks-miner")]
#[command(about = "A nyks CPU miner")]
pub struct Args {
    /// RPC URL to use (JSON/HTTP)
    #[arg(long, default_value = "http://localhost:9797")]
    pub rpc_url: String,

    /// Address to mine for (coinbase reward receiver)
    #[arg(long)]
    pub address: String,

    /// Network we are going to mine on.
    #[arg(long, default_value_t = Network::Main)]
    pub network: Network,
}
