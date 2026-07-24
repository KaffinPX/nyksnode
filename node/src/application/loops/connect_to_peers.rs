use std::collections::HashSet;
use std::fmt::Debug;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;
use bincode::Options;
use chrono::DateTime;
use chrono::Utc;
use futures::SinkExt;
use futures::TryStreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;
use tokio_serde::formats::Bincode;
use tokio_serde::SymmetricallyFramed;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::application::config::cli_args;
use crate::application::config::parser::multiaddr::multiaddr_to_socketaddr;
use crate::application::config::parser::multiaddr::socketaddr_to_multiaddr;
use crate::application::loops::peer_loop::channel::MainToPeerTask;
use crate::application::loops::peer_loop::channel::PeerTaskToMain;
use crate::application::loops::peer_loop::PeerLoopHandler;
use crate::state::GlobalStateLock;
use crate::MAGIC_STRING_REQUEST;
use crate::MAGIC_STRING_RESPONSE;
use nyks_p2p::peer::handshake_data::HandshakeData;
use nyks_p2p::peer::handshake_data::VersionString;
use nyks_p2p::peer::peer_info::pseudorandom_peer_id;
use nyks_p2p::peer::ConnectionRefusedReason;
use nyks_p2p::peer::InternalConnectionStatus;
use nyks_p2p::peer::NegativePeerSanction;
use nyks_p2p::peer::PeerMessage;
use nyks_p2p::peer::PeerSanction;
use nyks_p2p::peer::PeerStanding;
use nyks_p2p::peer::TransferConnectionStatus;

// Max peer message size is 500MB. Should be enough to send 250 blocks in a
// block batch-response.
pub const MAX_PEER_FRAME_LENGTH_IN_BYTES: usize = 500 * 1024 * 1024;

/// Only accept connections where peer's reported timestamp deviates from our
/// by less than this value.
/// TODO: move to protocol...
const PEER_TIME_DIFFERENCE_THRESHOLD_IN_SECONDS: u128 = 90;

/// Use this function to ensure that the same rules apply for both
/// ingoing and outgoing connections. This limits the size of messages
/// peers can send.
pub(crate) fn get_codec_rules() -> LengthDelimitedCodec {
    let mut codec_rules = LengthDelimitedCodec::new();
    codec_rules.set_max_frame_length(MAX_PEER_FRAME_LENGTH_IN_BYTES);
    codec_rules
}

/// Returns a bincode codec with allocation limits to prevent OOM attacks.
///
/// This prevents "length bomb" attacks where a malicious peer sends a tiny
/// frame claiming to contain a Vec with billions of elements. Without limits,
/// bincode would pre-allocate memory based on the claimed length, causing OOM.
///
/// The limit is set to match MAX_PEER_FRAME_LENGTH_IN_BYTES (500MB).
fn get_bincode_codec<Item, SinkItem>() -> Bincode<Item, SinkItem, impl Options + Copy>
where
    Item: serde::de::DeserializeOwned,
    SinkItem: serde::Serialize,
{
    bincode::DefaultOptions::new()
        .with_limit(MAX_PEER_FRAME_LENGTH_IN_BYTES as u64)
        .into()
}

/// Infallible absolute difference between two timestamps, in seconds.
fn system_time_diff_seconds(peer: SystemTime, own: SystemTime) -> u128 {
    let peer = peer
        .duration_since(UNIX_EPOCH)
        .map(|d| i128::from(d.as_secs()))
        .unwrap_or_else(|e| -i128::from(e.duration().as_secs()));

    let own = own
        .duration_since(UNIX_EPOCH)
        .map(|d| i128::from(d.as_secs()))
        .unwrap_or_else(|e| -i128::from(e.duration().as_secs()));

    (own - peer).unsigned_abs()
}

/// Initial check if incoming connection is allowed. Performed prior to the
/// sending of the handshake.
pub(crate) fn precheck_incoming_connection_is_allowed(
    cli: &cli_args::Args,
    connecting_ip: IpAddr,
) -> bool {
    let connecting_ip = match connecting_ip {
        IpAddr::V4(_) => connecting_ip,
        IpAddr::V6(v6) => match v6.to_ipv4() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => connecting_ip,
        },
    };
    if cli.restrict_peers_to_list {
        let allowed_ips: Vec<std::net::IpAddr> = cli
            .peers
            .iter()
            .filter_map(multiaddr_to_socketaddr)
            .map(|p| p.ip())
            .collect();
        let is_allowed = allowed_ips.contains(&connecting_ip);
        if !is_allowed {
            debug!("Rejecting incoming connection from unlisted peer {connecting_ip} due to --restrict-peers-to-list",);
            return false;
        }
    }

    if cli.banned_ips().contains(&connecting_ip) {
        debug!("Rejecting incoming connection because it's explicitly banned");
        return false;
    }

    if cli.disallow_all_incoming_peer_connections() {
        debug!("Rejecting incoming connection because all incoming connections are disallowed");
        return false;
    }

    true
}

/// Check if connection is allowed. Used for both ingoing and outgoing connections.
///
/// Note: this function is part of the legacy peer-to-peer stack. Therefore it
/// is okay to use [`SocketAddr`] and
/// [`pseudorandom_peer_id`].
///
/// # Locking
///   * acquires `global_state_lock` for read
async fn check_if_connection_is_allowed(
    global_state_lock: GlobalStateLock,
    own_handshake: &HandshakeData,
    other_handshake: &HandshakeData,
    peer_address: &SocketAddr,
) -> InternalConnectionStatus {
    let cli_arguments = global_state_lock.cli();
    let global_state = global_state_lock.lock_guard().await;

    // Disallow connection if peer is banned via CLI arguments
    if cli_arguments.banned_ips().contains(&peer_address.ip()) {
        let ip = peer_address.ip();
        debug!("Peer {ip}, banned via CLI argument, attempted to connect. Disallowing.");
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
    }

    // Disallow connection if we disagree about time.
    if system_time_diff_seconds(other_handshake.timestamp, own_handshake.timestamp)
        > PEER_TIME_DIFFERENCE_THRESHOLD_IN_SECONDS
    {
        let own_datetime_utc: DateTime<Utc> = own_handshake.timestamp.into();
        let peer_datetime_utc: DateTime<Utc> = other_handshake.timestamp.into();
        warn!(
                "New peer {} disagrees with us about time. Peer reports time {} but our clock at handshake was {}.",
                peer_address,
                peer_datetime_utc.format("%Y-%m-%d %H:%M:%S"),
                own_datetime_utc.format("%Y-%m-%d %H:%M:%S"));
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::bad_timestamp());
    }

    // Disallow connection if peer is in bad standing
    let standing = global_state
        .net
        .get_peer_standing_from_database(peer_address.ip())
        .await;

    // (But ignore bad standing if the peer is a CLI argument.)
    let cli_peers = cli_arguments
        .peers
        .iter()
        .filter_map(multiaddr_to_socketaddr)
        .collect::<HashSet<_>>();
    if standing.is_some_and(|s| s.is_bad()) && !cli_peers.contains(peer_address) {
        let ip = peer_address.ip();
        debug!("Peer {ip}, banned because of bad standing, attempted to connect. Disallowing.");
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::BadStanding);
    }

    if let Some(time) = global_state
        .net
        .last_disconnection_time_of_peer(other_handshake.instance_id)
    {
        if SystemTime::now()
            .duration_since(time)
            .is_ok_and(|d| d < cli_arguments.reconnect_cooldown)
        {
            debug!(
                "Refusing connection with {peer_address} \
                 due to reconnect cooldown ({cooldown} seconds).",
                cooldown = cli_arguments.reconnect_cooldown.as_secs(),
            );

            // A “wrong” reason is given because of backwards compatibility.
            // todo: Use next breaking release to give a more accurate reason here.
            let reason = ConnectionRefusedReason::MaxPeerNumberExceeded;
            return InternalConnectionStatus::Refused(reason);
        }
    }

    // Disallow connection if max number of peers has been reached or
    // exceeded. There is another test in `answer_peer_inner` that precedes
    // this one; however this test is still necessary to resolve potential
    // race conditions.
    // Note that if we are bootstrapping, then we *do* want to accept the
    // connection and temporarily exceed the maximum. In this case a
    // `DisconnectFromLongestLivedPeer` message should have been sent to
    // the main loop already but that message need not have been processed by
    // the time we get here.
    if cli_arguments.max_num_peers <= global_state.net.peer_map.len() && !cli_arguments.bootstrap {
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded);
    }

    // Disallow connection to already connected peer.
    if global_state.net.peer_map.values().any(|peer| {
        peer.instance_id() == other_handshake.instance_id
            || multiaddr_to_socketaddr(&peer.address()).is_some_and(|sa| sa == *peer_address)
    }) {
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected);
    }

    // Cap connections per IP, if specified.
    if let Some(max_connections_per_ip) = cli_arguments.max_connections_per_ip {
        let peer_ip = peer_address.ip();
        let num_connections_to_this_ip = global_state
            .net
            .peer_map
            .values()
            .filter_map(|info| multiaddr_to_socketaddr(&info.address()))
            .filter(|sa| sa.ip() == peer_ip)
            .count();
        if num_connections_to_this_ip >= max_connections_per_ip {
            return InternalConnectionStatus::Refused(
                ConnectionRefusedReason::MaxPeerNumberExceeded,
            );
        }
    }

    // Disallow connection to self
    if own_handshake.instance_id == other_handshake.instance_id {
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect);
    }

    // Disallow connection if versions are incompatible
    if !VersionString::versions_are_compatible(own_handshake.version, other_handshake.version) {
        warn!(
            "Attempting to connect to incompatible version. You might have to upgrade, or the other node does. Own version: {}, other version: {}",
            own_handshake.version,
            other_handshake.version);
        return InternalConnectionStatus::Refused(ConnectionRefusedReason::IncompatibleVersion);
    }

    // If this connection touches the maximum number of peer connections, say
    // so with special OK code.
    if cli_arguments.max_num_peers == global_state.net.peer_map.len() + 1 {
        info!("ConnectionStatus::Accepted, but max # connections is now reached");
        return InternalConnectionStatus::AcceptedMaxReached;
    }

    debug!("ConnectionStatus::Accepted");
    InternalConnectionStatus::Accepted
}

/// Respond to an incoming connection initiation.
///
/// Catch and process errors (if any) gracefully.
///
/// All incoming connections from peers must go through this function.
///
/// The `handshake_permit` is released after the handshake completes (success or
/// failure), not when the connection closes. This prevents semaphore starvation
/// attacks where an attacker holds connections idle to exhaust permits.
pub(crate) async fn answer_peer<S>(
    stream: S,
    state_lock: GlobalStateLock,
    peer_address: std::net::SocketAddr,
    main_to_peer_task_rx: broadcast::Receiver<MainToPeerTask>,
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    own_handshake_data: HandshakeData,
    handshake_permit: Option<OwnedSemaphorePermit>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + std::fmt::Debug + std::marker::Unpin,
{
    let inner_ret = answer_peer_inner(
        stream,
        state_lock.clone(),
        peer_address,
        main_to_peer_task_rx,
        peer_task_to_main_tx,
        own_handshake_data,
        handshake_permit,
    )
    .await;

    inner_ret
}

/// Handles all* incoming connections. Returns when the connection is closed.
///
/// A returned `Result::Error` always indicates that the connection was closed
/// through some networking error, either in this function or in the peer loop
/// that this function invokes if the handshake protocol is successful.
///
/// A returned `Result::Ok` means that either the peer loop was entered or the
/// handshake was not completed. The reason for this behavior is that we want
/// malicious connection attempts to be as resource light as possible. And
/// allocating thousands of anyhow errors can use a lot of RAM.
///
/// The `handshake_permit` is dropped after handshake completes to release the
/// semaphore slot for new incoming connection attempts.
///
/// *: This function belongs to the legacy peer-to-peer stack, meaning in
/// particular that it is okay to use [`SocketAddr`]. However, this function
/// does not handle *all* incoming connections: connections coming in over the
/// libp2p network stack are handled by the
/// [`NetworkActor`](crate::application::network::actor::NetworkActor) and the
/// [`StreamGateway`](crate::application::network::gateway::StreamGateway).
async fn answer_peer_inner<S>(
    stream: S,
    state: GlobalStateLock,
    peer_address: SocketAddr,
    main_to_peer_task_rx: broadcast::Receiver<MainToPeerTask>,
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    own_handshake_data: HandshakeData,
    handshake_permit: Option<OwnedSemaphorePermit>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Debug + Unpin,
{
    debug!("Established incoming TCP connection with {peer_address}");

    // Build the communication/serialization/frame handler
    let length_delimited = Framed::new(stream, get_codec_rules());
    let mut peer = SymmetricallyFramed::new(length_delimited, get_bincode_codec());

    // Complete Neptune handshake
    let handshake_timeout: u64 = state.cli().handshake_timeout.into();
    let handshake_timeout = Duration::from_secs(handshake_timeout);
    let maybe_msg = timeout(handshake_timeout, peer.try_next()).await;
    let (magic_value, peer_handshake) = match maybe_msg {
        Ok(Ok(Some(PeerMessage::Handshake { magic_value, data }))) => (magic_value, data),
        Ok(Ok(_)) => {
            // no heavy anyhow::Error, just close
            tracing::warn!(%peer_address, "unexpected message instead of handshake");
            return Ok(());
        }
        Ok(Err(e)) => {
            // no heavy anyhow::Error, just close
            tracing::warn!(%peer_address, error = ?e, "I/O error during handshake");
            return Ok(());
        }
        Err(_) => {
            // no heavy anyhow::Error, just close
            tracing::warn!(%peer_address, "handshake timed out");
            return Ok(());
        }
    };

    if magic_value != *MAGIC_STRING_REQUEST {
        // no heavy anyhow::Error, just close
        warn!("No valid magic value from {peer_address}. Closing connection.");
        return Ok(());
    }

    let handshake_response = PeerMessage::Handshake {
        magic_value: *MAGIC_STRING_RESPONSE,
        data: Box::new(own_handshake_data),
    };
    timeout(handshake_timeout, peer.send(handshake_response)).await??;

    // Verify peer network before moving on
    let peer_network = peer_handshake.network;
    let own_network = own_handshake_data.network;
    ensure!(
        peer_network == own_network,
        "Cannot connect with {peer_address}: \
        Peer runs {peer_network}, this client runs {own_network}."
    );

    // Check if incoming connection is allowed
    let connection_status = check_if_connection_is_allowed(
        state.clone(),
        &own_handshake_data,
        &peer_handshake,
        &peer_address,
    )
    .await;
    timeout(
        handshake_timeout,
        peer.send(PeerMessage::ConnectionStatus(connection_status.into())),
    )
    .await??;
    if let InternalConnectionStatus::Refused(reason) = connection_status {
        let reason = format!("Refusing incoming connection. Reason: {reason:?}");
        debug!("{reason}");
        bail!("{reason}");
    }

    // Whether the incoming connection comes from a peer in bad standing is
    // checked in `check_if_connection_is_allowed`. So if we get here, we are
    // good to go.
    info!("Connection accepted from {peer_address}");

    // Release the handshake permit now that handshake is complete.
    // This allows new incoming connections to start their handshake.
    // The connection is now governed by max_num_peers, not the semaphore.
    drop(handshake_permit);

    // If necessary, disconnect from another, existing peer.
    if connection_status == InternalConnectionStatus::AcceptedMaxReached && state.cli().bootstrap {
        info!("Maximum # peers reached, so disconnecting from an existing peer.");
        peer_task_to_main_tx
            .send(PeerTaskToMain::DisconnectFromLongestLivedPeer)
            .await?;
    }

    let peer_distance = 1; // All incoming connections have distance 1
    let peer_id = pseudorandom_peer_id(&peer_address);
    let peer_multiaddr = socketaddr_to_multiaddr(peer_address);
    let mut peer_loop_handler = PeerLoopHandler::new(
        peer_task_to_main_tx,
        state,
        peer_id,
        peer_multiaddr,
        *peer_handshake,
        true,
        peer_distance,
    );

    // Run peer loop.
    peer_loop_handler
        .run_wrapper(peer, main_to_peer_task_rx)
        .await?;

    Ok(())
}

/// Perform handshake and establish connection to a new peer while handling any
/// panics in the peer task gracefully.
///
/// All* outgoing connections to peers must go through this function.
///
/// *: This function belongs to the legacy peer-to-peer stack, which is in the
/// process of being deprecated. Since it is part of the legacy stack, it is
/// okay to use [`SocketAddr`]. However, the new libp2p network stack offers an
/// alternative way to call new peers, see
/// [`NetworkActorCommand::Dial`](crate::application::network::channel::NetworkActorCommand::Dial).
pub(crate) async fn call_peer(
    peer_address: std::net::SocketAddr,
    state: GlobalStateLock,
    main_to_peer_task_rx: broadcast::Receiver<MainToPeerTask>,
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    own_handshake_data: HandshakeData,
    peer_distance: u8,
) {
    debug!("Attempting to initiate connection to {peer_address}");
    match tokio::net::TcpStream::connect(peer_address).await {
        Err(e) => {
            let msg = format!("Failed to establish TCP connection to {peer_address}: {e}");
            if peer_distance == 1 {
                // outgoing connection to peer of distance 1 means user has
                // requested a connection to this peer through CLI
                // arguments, and should be warned if this fails.
                warn!("{msg}");
            } else {
                debug!("{msg}");
            }
        }
        Ok(stream) => {
            match call_peer_inner(
                stream,
                state,
                peer_address,
                main_to_peer_task_rx,
                peer_task_to_main_tx,
                &own_handshake_data,
                peer_distance,
            )
            .await
            {
                Ok(()) => (),
                Err(e) => {
                    let msg = format!("{e}. Failed to establish connection.");
                    // outgoing connection to peer of distance 1 means user has
                    // requested a connection to this peer through CLI
                    // arguments, and should be warned if this fails.
                    if peer_distance == 1 {
                        warn!("{msg}");
                    } else {
                        debug!("{msg}");
                    }
                }
            }
        }
    };

    info!("Connection to {peer_address} closing");
}

/// Legacy peer-to-peer stack.
async fn call_peer_inner<S>(
    stream: S,
    state: GlobalStateLock,
    peer_address: std::net::SocketAddr,
    main_to_peer_task_rx: broadcast::Receiver<MainToPeerTask>,
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
    own_handshake: &HandshakeData,
    peer_distance: u8,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Debug + Unpin,
{
    debug!("Established outgoing TCP connection with {peer_address}");

    // Build the communication/serialization/frame handler
    let length_delimited = Framed::new(stream, get_codec_rules());
    let mut peer = SymmetricallyFramed::new(length_delimited, get_bincode_codec());

    // Make Neptune handshake
    let outgoing_handshake = PeerMessage::Handshake {
        magic_value: *MAGIC_STRING_REQUEST,
        data: Box::new(own_handshake.to_owned()),
    };
    peer.send(outgoing_handshake).await?;
    debug!("Awaiting connection status response from {peer_address}");

    let Some(PeerMessage::Handshake {
        magic_value,
        data: other_handshake,
    }) = peer.try_next().await?
    else {
        bail!("Didn't get handshake response from {peer_address}");
    };
    ensure!(
        magic_value == *MAGIC_STRING_RESPONSE,
        "Didn't get expected magic value for handshake from {peer_address}",
    );

    debug!("Got correct magic value response from {peer_address}!");
    if other_handshake.network != own_handshake.network {
        let other = other_handshake.network;
        let own = own_handshake.network;
        bail!("Cannot connect with {peer_address}: Peer runs {other}, this client runs {own}.");
    }

    match peer.try_next().await? {
        Some(PeerMessage::ConnectionStatus(TransferConnectionStatus::Accepted)) => {
            debug!("Outgoing connection accepted by {peer_address}");
        }
        Some(PeerMessage::ConnectionStatus(TransferConnectionStatus::Refused(reason))) => {
            bail!("Outgoing connection attempt to {peer_address} refused. Reason: {reason:?}");
        }
        _ => {
            bail!(
                "Got invalid connection status response from {peer_address} on outgoing connection"
            );
        }
    }

    // Peer accepted us. Check if we accept the peer. Note that the protocol does not stipulate
    // that we answer with a connection status here, so if the connection is *not* accepted, we
    // simply hang up but log the reason for the refusal.
    let connection_status = check_if_connection_is_allowed(
        state.clone(),
        own_handshake,
        &other_handshake,
        &peer_address,
    )
    .await;
    if let InternalConnectionStatus::Refused(refused_reason) = connection_status {
        warn!(
            "Outgoing connection to {peer_address} refused. Reason: {:?}\nNow hanging up.",
            refused_reason
        );
        peer.send(PeerMessage::Bye).await?;
        bail!("Attempted to connect to peer ({peer_address}) that was not allowed. This connection attempt should not have been made.");
    }

    // By default, start by asking the peer for its peers. In an adversarial
    // context, we want the network topology to be as robust as possible.
    // Blockchain data can be obtained from other peers, if this connection
    // fails.
    peer.send(PeerMessage::PeerListRequest).await?;

    let peer_id = pseudorandom_peer_id(&peer_address);
    let peer_multiaddr = socketaddr_to_multiaddr(peer_address);
    let mut peer_loop_handler = PeerLoopHandler::new(
        peer_task_to_main_tx,
        state.clone(),
        peer_id,
        peer_multiaddr,
        *other_handshake,
        false,
        peer_distance,
    );

    info!("Established outgoing connection to {peer_address}");

    // Run peer loop.
    peer_loop_handler
        .run_wrapper(peer, main_to_peer_task_rx)
        .await?;

    Ok(())
}

/// Remove peer from state. This function must be called every time
/// a peer is disconnected. Whether this happens through a panic
/// in the peer task or through a regular disconnect.
///
/// This function is shared between the legacy peer-to-peer stack and the libp2p
/// network stack.
///
/// Locking:
///   * acquires `global_state_lock` for write
pub(crate) async fn close_peer_connected_callback(
    mut global_state_lock: GlobalStateLock,
    peer_address: Multiaddr,
    to_main_tx: &mpsc::Sender<PeerTaskToMain>,
) {
    let cli_arguments = global_state_lock.cli().clone();
    let mut global_state_mut = global_state_lock.lock_guard_mut().await;

    // Find the matching peer id
    let Some(peer_id) = global_state_mut
        .net
        .peer_map
        .iter()
        .find(|(_peer_id, peer_info)| peer_info.address() == peer_address)
        .map(|(peer_id, _)| peer_id)
        .copied()
    else {
        error!("Could not find peer id for {peer_address}");
        return;
    };

    // Store any new peer-standing to database
    let peer_info_writeback = global_state_mut.net.peer_map.remove(&peer_id);
    let new_standing = if let Some(new) = peer_info_writeback {
        new.standing()
    } else {
        error!("Could not find peer standing for {peer_address}");
        let mut standing = PeerStanding::new(cli_arguments.peer_tolerance);
        let sanction = NegativePeerSanction::NoStandingFoundMaybeCrash;

        // Don't return early: _must_ send message to main loop at the end of this
        // function.
        // If the peer has now reached bad standing, the connection to it should be
        // dropped, which is currently happening anyway.
        let _ = standing.sanction(PeerSanction::Negative(sanction));
        standing
    };
    debug!("Fetched peer info standing {new_standing} for peer {peer_address}");

    let maybe_ip = peer_address.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    });
    if let Some(ip) = maybe_ip {
        global_state_mut
            .net
            .write_peer_standing_on_decrease(ip, new_standing)
            .await;
    }

    let sync_mode_is_active = global_state_mut.net.sync_anchor.is_some();
    drop(global_state_mut); // avoid holding across mpsc::Sender::send()
    debug!("Stored peer info standing {new_standing} for peer {peer_address}");

    // If in sync mode, tell sync loop about dropped peer.
    if sync_mode_is_active {
        to_main_tx
            .send(PeerTaskToMain::DroppedPeer(peer_id))
            .await
            .expect("channel to main should exist");
    }
}
