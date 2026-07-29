use clap::Parser;
use nyks_protocol::consensus::network::Network;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::http::HttpClient;
use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::address::Recipient;

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

    /// Minimum guesser reward as a percentage of total block reward (0-100), default 10.
    #[arg(long, default_value_t = 10.0)]
    pub min_percentage_reward: f64,
}

impl Args {
    /// Validates the percentage is in range and converts it to a fraction
    /// (e.g. 10.0 -> 0.10) for internal use.
    pub fn min_reward_fraction(&self) -> f64 {
        assert!(
            (0.0..=100.0).contains(&self.min_percentage_reward),
            "min-percentage-reward must be between 0 and 100, got {}",
            self.min_percentage_reward
        );

        self.min_percentage_reward / 100.0
    }

    /// Creates an RPC client and verifies that the connected node is on the
    /// expected network.
    pub async fn rpc_client(&self) -> HttpClient {
        let client = HttpClient::new(self.rpc_url.clone());

        let remote_network = client
            .network()
            .await
            .expect("Failed to connect to RPC node")
            .network
            .parse::<Network>()
            .unwrap();

        assert_eq!(
            self.network, remote_network,
            "Network mismatch: expected {:?}, connected node is on {:?}",
            self.network, remote_network,
        );

        client
    }

    /// Validates that `address` is a well-formed address for the selected network.
    pub fn validate_address(&self) {
        Address::from_bech32m(&self.address, self.network).expect("Invalid address");
    }
}
