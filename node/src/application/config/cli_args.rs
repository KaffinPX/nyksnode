use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use bytesize::ByteSize;
use clap::builder::RangedI64ValueParser;
use clap::builder::TypedValueParser;
use clap::Parser;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use nyks_consensus::transaction::transaction_proof::TransactionProofQuality;
use tracing::error;

use crate::application::config::parser::multiaddr::parse_to_multiaddr;
use crate::state::mining::block_proposal::BlockProposalRejectError;
use nyks_consensus::network::Network;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_rpc_core::api::ops::Namespace;

const MAX_NUM_INPUTS_FOR_PC_BACKED_TXS: u64 = 200;

/// The `nyks-node` command-line program starts a nyks node.
#[derive(Parser, Debug, Clone)]
#[clap(author, version, about)]
pub struct Args {
    /// The data directory that contains the wallet and blockchain state
    ///
    /// The default varies by operating system, and includes the network, e.g.
    ///
    /// Linux:   /home/alice/.config/nyks/core/main
    ///
    /// Windows: C:\Users\Alice\AppData\Roaming\nyks\core\main
    ///
    /// macOS:   /Users/Alice/Library/Application Support/nyks/main
    #[clap(long, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    /// A directory holding block data that can be used to bootstrap the state
    /// to speedup the initial block download.
    #[clap(long, value_name = "DIR")]
    pub import_blocks_from_directory: Option<PathBuf>,

    /// The number of blocks between each database flush during block-importing.
    ///
    /// A value of 0 disables automatic flushing during block-importing.
    /// Lower non-zero values flush more frequently, reducing memory usage but
    /// increasing I/O overhead. Higher values reduce flush frequency and I/O,
    /// but increase memory usage. If you run into memory issues during block-
    /// import, consider lowering this value.
    #[clap(long, default_value = "250")]
    pub(crate) import_block_flush_period: usize,

    /// Set this to disable block validation for a faster block-import.
    #[clap(long)]
    pub disable_validation_in_block_import: bool,

    /// Ban connections to and from the given IP address.
    ///
    /// If a libp2p Multiaddr is supplied, the underlying IP address will be
    /// exctracted.
    ///
    /// E.g.: --ban 1.2.3.4 --ban /ip4/8.8.4.4/udp/1337/quic-v1
    #[structopt(long = "ban", value_parser(parse_to_multiaddr))]
    pub(crate) bans: Vec<Multiaddr>,

    /// The threshold at which a peer's standing is considered “bad”. Current
    /// connections to peers in bad standing are terminated. Connection attempts
    /// from peers in bad standing are refused.
    ///
    /// For a list of reasons that cause bad standing, see
    /// [NegativePeerSanction](nyks_p2p::peer::NegativePeerSanction).
    #[clap(
        long,
        default_value = "1000",
        value_name = "VALUE",
        value_parser = clap::value_parser!(u16).range(1..),
    )]
    pub(crate) peer_tolerance: u16,

    /// Only connect to the peers specified by --peer.
    /// When this flag is set, peer discovery is disabled and incoming
    /// connections from unlisted peers are rejected.
    #[arg(long)]
    pub restrict_peers_to_list: bool,

    /// Maximum number of peers to accept connections from.
    ///
    /// Will not prevent outgoing connections made with `--peer`.
    /// Set this value to 0 to refuse all incoming connections.
    #[clap(
        long,
        default_value = "10",
        value_name = "COUNT",
        value_parser = clap::value_parser!(u16).map(|u| usize::from(u)),
    )]
    pub(crate) max_num_peers: usize,

    /// Maximum number of peers to accept from each IP address.
    ///
    /// Multiple nodes can run on the same IP address which would either mean
    /// that multiple nodes run on the same machine, or multiple machines are
    /// on the same network that uses Network Address Translation and has one
    /// public IP.
    #[clap(long)]
    pub(crate) max_connections_per_ip: Option<usize>,

    /// Handshake timeout in seconds.
    ///
    /// The timeout used for all messages received and sent during the handshake
    /// protocol for incoming connections. Can be lowered if the client is
    /// attacked by many connection attempts. Can be raised if client is running
    /// on a machine with a bad internet connection.
    #[clap(long, default_value = "4", value_name = "SECONDS")]
    pub(crate) handshake_timeout: u8,

    /// Whether to act as bootstrapper node.
    ///
    /// Bootstrapper nodes ensure that the maximum number of peers is never
    /// reached by disconnecting from existing peers when the maximum is about
    /// to be reached. As a result, they will respond with high likelihood to
    /// incoming connection requests -- in contrast to regular nodes, which
    /// refuse incoming connections when the max is reached.
    #[clap(long)]
    pub(crate) bootstrap: bool,

    /// Minimum fee value for ProofCollection-backed transaction per input.
    ///
    /// Transactions with fees lower than this will not be requested from
    /// peers, will not be inserted into the mempool, and will not be
    /// relayed to peers.
    ///
    /// The value is per input. So the fee must be at least this value times
    /// the number of inputs in the transaction for the transaction to be
    /// relayed to peers.
    #[clap(long, default_value = "0.0005", value_parser = NativeCurrencyAmount::coins_from_str)]
    pub(crate) min_relay_pctx_fee_per_input: NativeCurrencyAmount,

    /// By default, a composer will share block proposals with all peers. If
    /// this flag is set, the composer will *not* share their block proposals.
    #[clap(long)]
    pub(crate) secret_compositions: bool,

    /// If set, node will only accept block proposals from these IP addresses.
    ///
    /// Multiple IP address can be set in which case the node will accept
    /// block proposals from any node connected from an IP in this list. Apart
    /// from ignoring all other block proposals, this argument does not change
    /// the proposal-selection behavior, meaning that the node will still pick
    /// the most favorable block proposal in terms of guesser rewards, as long
    /// as they are shared from any of these IPs.
    ///
    /// Example: `--whitelisted-composer=8.8.8.8 --whitelisted-composer=8.8.4.4`
    ///          `--whitelisted-composer=2001:db8:3333:4444:5555:6666:7777:8888`
    #[clap(long = "whitelisted-composer")]
    pub(crate) whitelisted_composers: Vec<IpAddr>,

    /// If set, all composition from peers will be ignored.
    #[clap(long)]
    pub(crate) ignore_foreign_compositions: bool,

    /// Prune the mempool when it exceeds this size in RAM.
    ///
    /// Units: B (bytes), K (kilobytes), M (megabytes), G (gigabytes)
    ///
    /// E.g. --max-mempool-size 500M
    #[clap(long, default_value = "1G", value_name = "SIZE")]
    pub(crate) max_mempool_size: ByteSize,

    /// Port on which to listen for libp2p QUIC peer connections.
    #[clap(long, default_value = "9800", value_name = "PORT")]
    pub quic_port: u16,

    /// Port on which to listen for libp2p TCP peer connections.
    #[clap(long, default_value = "9801", value_name = "PORT")]
    pub tcp_port: u16,

    /// IP on which to listen for peer connections. Will default to all network
    /// interfaces, IPv4 and IPv6.
    #[clap(short, long, default_value = "::")]
    pub peer_listen_addr: IpAddr,

    /// Public IP where the node is reachable.
    ///
    /// Only use for globally accessible IPs. Setting this value overrides
    /// libp2p AutoNAT behaviour. If no public IPs are set, libp2p's AutoNAT
    /// protocol will automatically try to guess the NAT status and external
    /// addresses.
    ///
    /// Examples:
    /// ```text
    /// --public-ip 93.7.1.1 --public-ip 2001:db8::1428:57ab
    /// ```
    #[structopt(long = "public-ip")]
    pub public_ips: Vec<IpAddr>,

    /// Maximum number of blocks that the client can catch up to without going
    /// into sync mode.
    ///
    /// Default: 100.
    ///
    /// The process running this program should have access to enough RAM: at
    /// least the number of blocks set by this argument multiplied with the max
    /// block size (around 2 MB). Probably 1.5 to 2 times that amount for good
    /// margin.
    // Notice that the minimum value here may not be less than
    // [SYNC_CHALLENGE_POW_WITNESS_LENGTH](crate::models::peer::SYNC_CHALLENGE_POW_WITNESS_LENGTH)
    // as that would prevent going into sync mode.
    #[clap(long, default_value = "100", value_parser(RangedI64ValueParser::<usize>::new().range(10..100000)))]
    pub(crate) sync_mode_threshold: usize,

    /// By default the node will attempt to resume a previously aborted sync
    /// process, whose blocks are stored in a temporary directory. Set this flag
    /// to instruct the node ensure it is working in its own temporary directory
    /// if a sync process is started.
    #[clap(long)]
    pub(crate) no_resume_sync: bool,

    /// Override the directory used to store downloaded blocks during sync.
    ///
    /// Defaults to a subdirectory under the system temp dir. Setting this is
    /// handy when the temp partition is too small or you want sync data to
    /// survive reboots. The directory is created if it doesn't exist.
    #[clap(long, value_name = "DIR")]
    pub(crate) sync_dir: Option<PathBuf>,

    /// Multiaddrs (or IPs) of nodes to connect to, e.g.:
    /// ```text
    /// --peer /ip4/8.8.8.8 \
    /// --peer /ip4/8.8.4.4/udp/1337/quic-v1 \
    /// --peer 139.162.193.206:9798 \
    /// --peer [2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9]:9798
    /// ```
    ///
    /// It's easier to connect without `/p2p/...` in the end of the address.
    ///
    /// The trust assumptions are interpreted in spirit of libp2p Multiaddr.
    ///
    /// - without `/p2p/...` it will be adding any peer found on the endpoint;
    /// - with `/p2p/...` connections to the given endpoint will fail if the
    ///   `PeerId` there had changed; and it will continue to try to reach this
    ///   peer indefinitely.
    #[structopt(long = "peer", value_parser(parse_to_multiaddr))]
    pub peers: Vec<Multiaddr>,

    /// Generate a fresh identity for this session only.
    #[clap(long)]
    pub(crate) incognito: bool,

    /// Generate a new identity to use going forward.
    ///
    /// Back up the old identity file.
    #[clap(long)]
    pub(crate) new_identity: bool,

    /// Use the identity contained in the given file.
    #[clap(long)]
    pub(crate) identity_file: Option<String>,

    /// Specify network, `main`, `alpha`, `beta`, `testnet`, or `regtest`
    #[structopt(long, default_value = "main", short)]
    pub network: Network,

    /// Enable tokio tracing for consumption by the tokio-console application
    /// note: this will attempt to connect to localhost:6669
    #[structopt(long, name = "tokio-console", default_value = "false")]
    pub tokio_console: bool,

    /// The duration (in seconds) during which new connection attempts from peers
    /// are ignored after a connection to them was closed.
    ///
    /// Does not affect abnormally closed connections. For example, if a connection
    /// is dropped due to networking issues, an immediate reconnection attempt is
    /// not affected by this cooldown.
    //
    // The default should be larger than the default interval between peer discovery
    // to meaningfully suppress rapid reconnection attempts.
    #[clap(long, default_value = "1800", value_parser = duration_from_seconds_str)]
    pub reconnect_cooldown: Duration,

    /// Construct and maintain a UTXO index
    ///
    /// If set, all announcements and inputs in all processed blocks will be
    /// indexed in a database that enables a fast rescan for the discovery of
    /// all balance-affecting inputs and outputs of blocks.
    ///
    /// If blocks have already been processed without this flag active, and the
    /// flag is later activated, all blocks up to the current tip will be
    /// indexed, when a new block is set as tip. This process might take some
    /// time (tens of minutes).
    #[clap(long)]
    pub utxo_index: bool,

    /// Enable JSON/HTTP RPC.
    /// You can optionally specify an address and port (default: 127.0.0.1:9797).
    /// If not given, RPC is disabled.
    #[clap(
        long,
        default_missing_value = "127.0.0.1:9797",
        num_args = 0..=1,
        value_name = "ADDR"
    )]
    pub listen_rpc: Option<SocketAddr>,

    /// RPC modules to enable.
    /// Specifies which sets of RPC methods are exposed (e.g., node or chain).
    /// By default, both "node" and "chain" modules are enabled.
    ///
    /// WARNING: Activating some of these endpoints may expose wallet secrets
    /// through the JSON/HTTP RPC. Make sure you don't activate the wrong ones
    /// on an unsecured network.
    #[clap(
        long,
        value_parser = clap::value_parser!(Namespace),
        use_value_delimiter = true,
        default_value = "Node,Chain",
        value_name = "NAMESPACES"
    )]
    pub rpc_modules: Vec<Namespace>,

    /// Enable unsafe RPC methods over all transports (e.g., HTTP).
    ///
    /// WARNING: Enabling this exposes dangerous RPC behavior and should only be used in
    /// isolated, controlled environments.
    ///
    /// This may result in:
    /// - Denial of Service (DoS) by triggering heavy or expensive computations.
    /// - Exposure of internal node state or metrics that could aid an attacker.
    /// - Misconfigurations leading to unexpected or unsafe behavior.
    #[clap(long)]
    pub unsafe_rpc: bool,
}

impl Default for Args {
    fn default() -> Self {
        let empty: Vec<String> = vec![];
        Self::parse_from(empty)
    }
}

fn duration_from_seconds_str(s: &str) -> Result<Duration, std::num::ParseIntError> {
    Ok(Duration::from_secs(s.parse()?))
}

impl Args {
    pub fn default_with_network(network: Network) -> Self {
        Self {
            network,
            ..Default::default()
        }
    }

    /// Check if block proposal should be accepted from this IP address.
    pub(crate) fn accept_block_proposal_from(
        &self,
        address: &Multiaddr,
    ) -> Result<(), BlockProposalRejectError> {
        if self.ignore_foreign_compositions {
            return Err(BlockProposalRejectError::IgnoreAllForeign);
        }
        if self.whitelisted_composers.is_empty() {
            return Ok(());
        }

        let ip_address = address
            .iter()
            .find_map(|proto| match proto {
                Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
                Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
                _ => None,
            })
            .ok_or(BlockProposalRejectError::NotWhitelisted)?;

        let ip_address = match ip_address {
            IpAddr::V4(_) => ip_address,
            IpAddr::V6(v6) => match v6.to_ipv4() {
                Some(v4) => std::net::IpAddr::V4(v4),
                None => ip_address,
            },
        };
        if !self.whitelisted_composers.contains(&ip_address) {
            return Err(BlockProposalRejectError::NotWhitelisted);
        }

        Ok(())
    }

    /// Check if a transaction should be inserted into the mempool and relayed
    /// to peers. Proofcollection-backed transactions that pay too small fees
    /// are not relayed.
    pub(crate) fn relay_transaction(
        &self,
        num_inputs: u64,
        tx_fee: NativeCurrencyAmount,
        proof_quality: TransactionProofQuality,
    ) -> bool {
        match proof_quality {
            TransactionProofQuality::ProofCollection => {
                if num_inputs > MAX_NUM_INPUTS_FOR_PC_BACKED_TXS {
                    return false;
                }

                let num_inputs: u32 = num_inputs
                    .try_into()
                    .expect("Already checked that number of inputs was not too high.");

                let Some(min_fee) = self
                    .min_relay_pctx_fee_per_input
                    .checked_scalar_mul(num_inputs)
                else {
                    error!("Multiplication overflowed in fee calculation. This should not happen.");
                    return false;
                };

                tx_fee >= min_fee
            }
            // For now, all single proof txs are relayed. A threshold value
            // could be set here too though.
            TransactionProofQuality::SingleProof => true,
        }
    }

    /// Generates the set of local addresses the node should bind to.
    ///
    /// This method expands [`Self::peer_listen_addr`] into a list of
    /// [`Multiaddr`] strings covering both TCP and QUIC transports.
    ///
    /// ### Protocol Expansion
    ///
    /// - If [`Self::peer_listen_addr`] is set to the unspecified address
    ///   (`::` or `0.0.0.0`), this returns addresses for **both** IPv4 and IPv6
    ///   interfaces to ensure maximum reachability.
    /// - For each IP, it generates a TCP multiaddr on
    ///   [`libp2p_tcp`](libp2p::tcp) and a QUIC-v1 multiaddr on
    ///   [`libp2p_quic`](libp2p::quic).
    ///
    /// This list specifically excludes [`Self::peer_port`] (Legacy TCP), as
    /// that port is managed by the legacy networking stack and should not be
    /// bound by the libp2p [`Swarm`](libp2p::Swarm).
    ///
    /// # Return Value
    ///
    /// A `Vec<Multiaddr>` in the format:
    /// - `/ip4/<addr>/tcp/<port>`
    /// - `/ip4/<addr>/udp/<port>/quic-v1`
    pub fn own_listen_addresses(&self) -> Vec<Multiaddr> {
        let mut addrs = Vec::new();

        // Determine if we need to expand "::" into both 0.0.0.0 and ::
        let ips = if self.peer_listen_addr.is_unspecified() {
            vec![
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ]
        } else {
            vec![self.peer_listen_addr]
        };

        for ip in ips {
            // Add TCP Multiaddr
            let mut tcp_addr = Multiaddr::from(ip);
            tcp_addr.push(Protocol::Tcp(self.tcp_port));
            addrs.push(tcp_addr);

            // Add QUIC Multiaddr (QUIC runs over UDP)
            let mut quic_addr = Multiaddr::from(ip);
            quic_addr.push(Protocol::Udp(self.quic_port));
            quic_addr.push(Protocol::QuicV1);
            addrs.push(quic_addr);
        }

        addrs
    }

    /// List of publicly reachable Multiaddrs with embedded IPv{4,6} defined by
    /// the user.
    ///
    /// If non-empty, this list overrides libp2p's AutoNAT behaviour and informs
    /// libp2p of the external addresses this node is reachable on.
    pub(crate) fn own_public_addresses(&self) -> Vec<Multiaddr> {
        let mut addrs = Vec::new();

        for ip in &self.public_ips {
            // Add TCP Multiaddr
            let mut tcp_addr = Multiaddr::from(*ip);
            tcp_addr.push(Protocol::Tcp(self.tcp_port));
            addrs.push(tcp_addr);

            // Add QUIC Multiaddr (QUIC runs over UDP)
            let mut quic_addr = Multiaddr::from(*ip);
            quic_addr.push(Protocol::Udp(self.quic_port));
            quic_addr.push(Protocol::QuicV1);
            addrs.push(quic_addr);
        }

        addrs
    }

    /// The list of IPs banned from the CLI.
    ///
    /// This convenience function extracts the IPs from the `bans` argument
    /// which contains `Multiaddr`s, not IPs.
    pub fn banned_ips(&self) -> Vec<IpAddr> {
        self.bans
            .iter()
            .filter_map(|ma| {
                ma.iter().find_map(|protocol| match protocol {
                    Protocol::Ip4(ipv4_addr) => Some(IpAddr::V4(ipv4_addr)),
                    Protocol::Ip6(ipv6_addr) => Some(IpAddr::V6(ipv6_addr)),
                    _ => None,
                })
            })
            .collect()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::net::Ipv6Addr;

    use num_traits::Zero;

use super::*;
    use crate::application::config::parser::multiaddr::parse_to_multiaddr;

    #[test]
    fn default_args_test() {
        let default_args = Args::default();

        assert_eq!(1000, default_args.peer_tolerance);
        assert_eq!(10, default_args.max_num_peers);
        assert_eq!(
            IpAddr::from(Ipv6Addr::UNSPECIFIED),
            default_args.peer_listen_addr
        );
    }

    #[test]
    fn cli_args_default_network_agrees_with_enum_default() {
        assert_eq!(Args::default().network, Network::default());
    }

    #[test]
    fn relay_transaction_unit_test() {
        let cli = Args::default();
        assert!(
            !cli.relay_transaction(
                1,
                NativeCurrencyAmount::zero(),
                TransactionProofQuality::ProofCollection
            ),
            "proof-collection backed transaction not paying fee is not relayed"
        );
        assert!(
            cli.relay_transaction(
                1,
                NativeCurrencyAmount::coins(1),
                TransactionProofQuality::ProofCollection
            ),
            "proof-collection backed transaction paying a high fee is relayed"
        );
        assert!(
            cli.relay_transaction(
                1,
                NativeCurrencyAmount::coins(1),
                TransactionProofQuality::SingleProof
            ),
            "single-proof backed transaction paying a high fee is relayed"
        );
        assert!(
            !cli.relay_transaction(
                300,
                NativeCurrencyAmount::coins(1000),
                TransactionProofQuality::ProofCollection
            ),
            "proof-collection transaction with too many inputs is never relayed."
        );
        assert!(
            !cli.relay_transaction(
                u64::MAX,
                NativeCurrencyAmount::coins(1000),
                TransactionProofQuality::ProofCollection
            ),
            "No crash on overflow"
        );
    }

    #[test]
    fn can_specify_ips_as_peers() {
        let mut cli = Args::default();

        let ipv4 = "139.162.193.206:9798".to_string();
        let ipv6 = "[2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9]:9798".to_string();

        cli.peers.push(parse_to_multiaddr(&ipv4).unwrap());
        cli.peers.push(parse_to_multiaddr(&ipv6).unwrap());
    }

    #[test]
    fn can_specify_multiaddrs_as_peers() {
        let mut cli = Args::default();

        let ipv4 = "/ip4/8.8.8.8".to_string();
        let ipv4_udp_quic = "/ip4/8.8.4.4/udp/1337/quic-v1".to_string();

        cli.peers.push(parse_to_multiaddr(&ipv4).unwrap());
        cli.peers.push(parse_to_multiaddr(&ipv4_udp_quic).unwrap());
    }
}
