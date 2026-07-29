use clap::Parser;
use nyks_consensus::network::Network;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

#[derive(Parser)]
#[command(name = "nyks-upgrader")]
#[command(about = "architect of nyks transactions")]
pub struct Args {
    /// RPC URL to use (JSON/HTTP)
    #[arg(long)]
    pub rpc_url: String,

    /// Recipient of the gobbling rewards.
    #[arg(long)]
    pub address: String,

    /// Network we are upgrading transactions on.
    #[arg(long, default_value_t = Network::Main)]
    pub network: Network,

    /// How much reward we charge per transaction.
    #[arg(
        long,
        value_parser = NativeCurrencyAmount::coins_from_str,
        default_value_t = NativeCurrencyAmount::coins(1)
    )]
    pub fee: NativeCurrencyAmount,
}
