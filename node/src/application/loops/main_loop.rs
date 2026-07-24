pub(crate) mod network_event_handler;

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::net::SocketAddr;

use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::Result;
use itertools::Either;
use itertools::Itertools;
use libp2p::PeerId;
use nyks_p2p::peer::handshake_data::HandshakeData;
use nyks_p2p::peer::peer_info::PeerInfo;
use nyks_p2p::peer::transaction_notification::TransactionNotification;
use nyks_protocol::consensus::block::Block;
use rand::prelude::IteratorRandom;
use tokio::net::TcpListener;
use tokio::select;
use tokio::signal;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time;
use tokio::time::Instant;
use tokio::time::MissedTickBehavior;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::application::config::parser::multiaddr::multiaddr_to_socketaddr;
use crate::application::loops::channel::RPCServerToMain;
use crate::application::loops::connect_to_peers::answer_peer;
use crate::application::loops::connect_to_peers::call_peer;
use crate::application::loops::connect_to_peers::precheck_incoming_connection_is_allowed;
use crate::application::loops::peer_loop::channel::MainToPeerTask;
use crate::application::loops::peer_loop::channel::PeerTaskToMain;
use crate::application::loops::sync_loop::channel::BlockRequest;
use crate::application::loops::sync_loop::channel::SyncToMain;
use crate::application::loops::sync_loop::handle::SyncLoopHandle;
use crate::application::loops::sync_loop::SYNC_LOOP_CHANNEL_CAPACITY;
use crate::application::network::channel::NetworkActorCommand;
use crate::application::network::channel::NetworkEvent;
use crate::macros::fn_name;
use crate::macros::log_slow_scope;
use crate::state::mining::block_proposal::BlockProposal;
use crate::state::networking_state::SyncAnchor;
use crate::state::sync_status::SyncStatus;
use crate::state::GlobalStateLock;
use crate::SUCCESS_EXIT_CODE;

const PEER_DISCOVERY_INTERVAL: Duration = Duration::from_secs(2 * 60);
const SYNC_REQUEST_INTERVAL: Duration = Duration::from_secs(3);
const MEMPOOL_PRUNE_INTERVAL: Duration = Duration::from_secs(30 * 60);

const POTENTIAL_PEER_MAX_COUNT_AS_A_FACTOR_OF_MAX_PEERS: usize = 20;
pub(crate) const MAX_NUM_DIGESTS_IN_BATCH_REQUEST: usize = 200;

/// MainLoop is the immutable part of the input for the main loop function
#[derive(Debug)]
pub struct MainLoopHandler {
    incoming_peer_listener: TcpListener,
    global_state_lock: GlobalStateLock,

    // note: broadcast::Sender::send() does not block
    main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,

    // note: mpsc::Sender::send() blocks if channel full.
    // locks should not be held across it.
    peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,

    network_command_tx: mpsc::Sender<NetworkActorCommand>,

    peer_task_to_main_rx: mpsc::Receiver<PeerTaskToMain>,
    rpc_server_to_main_rx: mpsc::Receiver<RPCServerToMain>,
    network_event_rx: mpsc::Receiver<NetworkEvent>,
    task_handles: Vec<JoinHandle<()>>,

    #[cfg(test)]
    mock_now: Option<SystemTime>,
}

/// The mutable part of the main loop function
struct MutableMainLoopState {
    /// A (handle on a) subordinate event loop responsible for rapidly
    /// collecting blocks from peers and delivering them to the main loop in
    /// order.
    maybe_sync_loop: Option<SyncLoopHandle>,

    /// Information about potential peers for new connections.
    potential_peers: PotentialPeersState,

    /// A list of join-handles to spawned tasks.
    task_handles: Vec<JoinHandle<()>>,
}

impl MutableMainLoopState {
    fn new(task_handles: Vec<JoinHandle<()>>) -> Self {
        Self {
            maybe_sync_loop: None,
            potential_peers: PotentialPeersState::default(),
            task_handles,
        }
    }
}

/// holds information about a potential peer in the process of peer discovery
struct PotentialPeerInfo {
    _reported: SystemTime,
    _reported_by: PeerId,
    instance_id: u128,
    distance: u8,
}

impl PotentialPeerInfo {
    fn new(reported_by: PeerId, instance_id: u128, distance: u8, now: SystemTime) -> Self {
        Self {
            _reported: now,
            _reported_by: reported_by,
            instance_id,
            distance,
        }
    }
}

/// holds information about a set of potential peers in the process of peer discovery
struct PotentialPeersState {
    potential_peers: HashMap<SocketAddr, PotentialPeerInfo>,
}

impl PotentialPeersState {
    fn default() -> Self {
        Self {
            potential_peers: HashMap::new(),
        }
    }

    fn add(
        &mut self,
        reported_by: PeerId,
        potential_peer: (SocketAddr, u128),
        max_peers: usize,
        distance: u8,
        now: SystemTime,
    ) {
        let potential_peer_socket_address = potential_peer.0;
        let potential_peer_instance_id = potential_peer.1;

        // This check *should* make it likely that a potential peer is always
        // registered with the lowest observed distance.
        if self
            .potential_peers
            .contains_key(&potential_peer_socket_address)
        {
            return;
        }

        // If this data structure is full, remove a random entry. Then add this.
        if self.potential_peers.len()
            > max_peers * POTENTIAL_PEER_MAX_COUNT_AS_A_FACTOR_OF_MAX_PEERS
        {
            let mut rng = rand::rng();
            let random_potential_peer = self
                .potential_peers
                .keys()
                .choose(&mut rng)
                .unwrap()
                .to_owned();
            self.potential_peers.remove(&random_potential_peer);
        }

        let insert_value =
            PotentialPeerInfo::new(reported_by, potential_peer_instance_id, distance, now);
        self.potential_peers
            .insert(potential_peer_socket_address, insert_value);
    }

    /// Return a peer from the potential peer list that we aren't connected to
    /// and  that isn't our own address.
    ///
    /// Favors peers with a high distance and with IPs that we are not already
    /// connected to.
    ///
    /// Returns (socket address, peer distance)
    ///
    /// This function is part of the legacy peer-to-peer stack.
    fn get_candidate(
        &self,
        connected_clients: &[PeerInfo],
        own_instance_id: u128,
    ) -> Option<(SocketAddr, u8)> {
        let peers_instance_ids: Vec<u128> =
            connected_clients.iter().map(|x| x.instance_id()).collect();

        // Only pick those peers that report a listening port
        let peers_listen_addresses: Vec<SocketAddr> = connected_clients
            .iter()
            .filter_map(|x| x.listen_address())
            .filter_map(|ma| multiaddr_to_socketaddr(&ma))
            .collect();

        // Find the appropriate candidates
        let candidates = self
            .potential_peers
            .iter()
            // Prevent connecting to self. Note that we *only* use instance ID to prevent this,
            // meaning this will allow multiple nodes e.g. running on the same computer to form
            // a complete graph.
            .filter(|pp| pp.1.instance_id != own_instance_id)
            // Prevent connecting to peer we already are connected to
            .filter(|potential_peer| !peers_instance_ids.contains(&potential_peer.1.instance_id))
            .filter(|potential_peer| !peers_listen_addresses.contains(potential_peer.0))
            .collect::<Vec<_>>();

        // Prefer candidates with IPs that we are not already connected to but
        // connect to repeated IPs in case we don't have other options, as
        // repeated IPs may just be multiple machines on the same NAT'ed IPv4
        // address.
        let mut connected_ips = peers_listen_addresses.into_iter().map(|x| x.ip());
        let candidates = if candidates
            .iter()
            .any(|candidate| !connected_ips.contains(&candidate.0.ip()))
        {
            candidates
                .into_iter()
                .filter(|candidate| !connected_ips.contains(&candidate.0.ip()))
                .collect()
        } else {
            candidates
        };

        // Get the candidate list with the highest distance
        let max_distance_candidates = candidates.iter().max_by_key(|pp| pp.1.distance);

        // Pick a random candidate from the appropriate candidates
        let mut rng = rand::rng();
        max_distance_candidates
            .iter()
            .choose(&mut rng)
            .map(|x| (x.0.to_owned(), x.1.distance))
    }
}

impl MainLoopHandler {
    // todo: find a way to avoid triggering lint
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        incoming_peer_listener: TcpListener,
        global_state_lock: GlobalStateLock,
        main_to_peer_broadcast_tx: broadcast::Sender<MainToPeerTask>,
        peer_task_to_main_tx: mpsc::Sender<PeerTaskToMain>,
        network_command_tx: mpsc::Sender<NetworkActorCommand>,

        peer_task_to_main_rx: mpsc::Receiver<PeerTaskToMain>,
        rpc_server_to_main_rx: mpsc::Receiver<RPCServerToMain>,
        network_event_rx: mpsc::Receiver<NetworkEvent>,
        task_handles: Vec<JoinHandle<()>>,
    ) -> Self {
        Self {
            incoming_peer_listener,
            global_state_lock,
            main_to_peer_broadcast_tx,
            peer_task_to_main_tx,
            network_command_tx,

            peer_task_to_main_rx,
            rpc_server_to_main_rx,
            network_event_rx,

            task_handles,

            #[cfg(test)]
            mock_now: None,
        }
    }

    pub fn global_state_lock(&mut self) -> GlobalStateLock {
        self.global_state_lock.clone()
    }

    /// Allows for mocked timestamps such that time dependencies may be tested.
    #[cfg(test)]
    fn with_mocked_time(mut self, mocked_time: SystemTime) -> Self {
        self.mock_now = Some(mocked_time);
        self
    }

    fn now(&self) -> SystemTime {
        #[cfg(not(test))]
        {
            SystemTime::now()
        }
        #[cfg(test)]
        {
            self.mock_now.unwrap_or(SystemTime::now())
        }
    }

    /// Process a block whose PoW solution was solved by this client (or an
    /// external program) and has not been seen by the rest of the network yet.
    ///
    /// Shares block with all connected peers, updates own state, and updates
    /// any mempool transactions to be valid under this new block.
    ///
    /// Caller is responsible for both block validity and that the provided
    /// block has a valid PoW solution. Otherwise, the new state will be
    /// invalid.
    ///
    /// Locking:
    ///  * acquires `global_state_lock` for read and write
    async fn handle_self_guessed_block(
        &mut self,
        _main_loop_state: &mut MutableMainLoopState,
        new_block: Box<Block>,
    ) -> Result<()> {
        let new_block_hash = new_block.hash();

        // clone block in advance, so lock is held less time.
        let new_block_clone = (*new_block).clone();

        // important!  the is_canonical check and set_new_tip() need to be an
        // atomic operation, ie called within the same write-lock acquisition.
        //
        // this avoids a race condition where block B and C are both more
        // canonical than A, but B is more than C, yet C replaces B because it
        // was only checked against A.
        //
        // we release the lock as quickly as possible.
        {
            let mut gsm = self.global_state_lock.lock_guard_mut().await;

            // bail out if incoming block is not more canonical than present tip.
            if !gsm.incoming_block_is_more_canonical(&new_block) {
                drop(gsm); // drop lock right away before send.
                warn!("Got new block from miner that was not child of tip. Discarding.");
                // self.main_to_miner_tx.send(MainToMiner::Continue);
                return Ok(());
            }

            gsm.set_new_tip(new_block_clone).await?;
            gsm.flush_databases().await?;
        };

        // Share block with peers right away.
        let pmsg = MainToPeerTask::Block(new_block);
        self.main_to_peer_broadcast(pmsg);

        info!("Locally-mined block is new tip: {new_block_hash:x}");
        info!("broadcasting new block to peers");

        Ok(())
    }

    /// Locking:
    ///   * acquires `global_state_lock` for write
    async fn handle_peer_task_message(
        &mut self,
        msg: PeerTaskToMain,
        main_loop_state: &mut MutableMainLoopState,
    ) -> Result<()> {
        debug!("Received {} from a peer task", msg.get_type());
        match msg {
            PeerTaskToMain::NewBlocks(blocks) => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::NewBlocks");

                let last_block = blocks.last().unwrap().to_owned();
                {
                    // Double-check canonicity.
                    // The peer tasks also check this condition. However, there
                    // is a potential for race conditions that would otherwise
                    // lead to duplicate work.
                    let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                    let new_canonical =
                        global_state_mut.incoming_block_is_more_canonical(&last_block);
                    if !new_canonical {
                        // Incoming blocks can be non-canonical, namely if they
                        // come in via the sync loop. But the sync loop has a
                        // dedicated message for this purpose, TipSuccessor.
                        // This message handler should not be concerned with
                        // sync mode, and so it should reject non-canonical
                        // blocks.
                        return Ok(());
                    }

                    // Report.
                    info!(
                        "Block {} from peer is new canonical tip: {:x}",
                        last_block.header().height,
                        last_block.hash(),
                    );

                    // Update status.
                    global_state_mut.net.sync_status = SyncStatus::Synced;

                    // No need to worry about sync mode as it cannot be active
                    // when this message handler is. If sync mode is active,
                    // blocks are sent to the main loop through dedicated
                    // message, NewSyncBlock.

                    for new_block in blocks {
                        debug!(
                            "Storing block {:x} in database. Height: {}, Mined: {}",
                            new_block.hash(),
                            new_block.kernel.header.height,
                            new_block.kernel.header.timestamp.standard_format()
                        );

                        // Potential race condition here.
                        // What if last block is new and canonical, but first
                        // block is already known then we'll store the same block
                        // twice. That should be OK though, as the appropriate
                        // database entries are simply overwritten with the new
                        // block info. See the
                        // [GlobalState::tests::setting_same_tip_twice_is_allowed]
                        // test for a test of this phenomenon.

                        global_state_mut.set_new_tip(new_block).await?;
                    }

                    global_state_mut.flush_databases().await?;
                }

                // Inform all peers about new block
                let pmsg = MainToPeerTask::Block(Box::new(last_block.clone()));
                self.main_to_peer_broadcast(pmsg);
            }
            PeerTaskToMain::AddPeerMaxBlockHeight {
                peer_id,
                peer_address,
                claimed_height,
                claimed_cumulative_pow,
                claimed_block_mmra,
                claimed_block_digest,
            } => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::AddPeerMaxBlockHeight");

                // If we are already in sync mode, do nothing.
                if main_loop_state.maybe_sync_loop.is_some() {
                    return Ok(());
                }

                // Check if synchronization mode should be activated. Sync mode
                // is entered into if claimed accumulated proof-of-work number
                // exceeds that of our own tip and if the height difference is
                // positive and beyond a threshold value.
                let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                if global_state_mut.sync_mode_criterion(claimed_height, claimed_cumulative_pow)
                    && global_state_mut.net.sync_anchor.as_ref().is_none()
                {
                    info!(
                        "Starting sync loop because peer {} indicates tip height {}; cumulative pow: {:?}",
                        peer_address, claimed_height, claimed_cumulative_pow
                    );

                    // Set sync anchor.
                    global_state_mut.net.sync_anchor = Some(SyncAnchor::new(
                        claimed_cumulative_pow,
                        claimed_block_mmra,
                        claimed_height,
                        claimed_block_digest,
                    ));

                    // Clone info from global state and release write lock ASAP.
                    let peer_map = global_state_mut.net.peer_map.clone();
                    let network = global_state_mut.cli().network;
                    let current_height = global_state_mut.chain.tip_height();
                    let resume_please = !global_state_mut.cli().no_resume_sync;
                    let sync_dir = global_state_mut.cli().sync_dir.clone();
                    drop(global_state_mut);

                    // Create sync loop with handle.
                    let genesis_block = Block::genesis(network);
                    let mut sync_loop = SyncLoopHandle::new(
                        genesis_block,
                        claimed_height,
                        network,
                        resume_please,
                        sync_dir,
                    )
                    .await;
                    sync_loop.start();

                    // Tell sync loop about all known peers.
                    sync_loop.send_add_peer(peer_id).await;
                    for (peer, _) in peer_map.iter().take(SYNC_LOOP_CHANNEL_CAPACITY) {
                        if *peer != peer_id {
                            sync_loop.send_add_peer(*peer).await;
                        }
                    }

                    // Store sync loop handle
                    main_loop_state.maybe_sync_loop = Some(sync_loop);

                    // Ask the peer about their block at the height of our own
                    // tip. Either the peer is on the same fork as us and is
                    // just further ahead; or else the peer is on a different
                    // fork altogether. In the former case we can safely
                    // fast-forward to the current tip and this will happen
                    // automatically when the response to this question comes
                    // in. In the latter case we need to run a bisection search
                    // to find LUCA, and that happens as a side effect of the
                    // sync loop querying random blocks. When those random
                    // blocks come in, we fast-forward if we can.
                    if !current_height.is_genesis() {
                        self.main_to_peer_broadcast(MainToPeerTask::RequestBlockByHeight {
                            target_peer: peer_id,
                            height: current_height,
                        });
                    }
                }
            }
            PeerTaskToMain::PeerDiscoveryAnswer((pot_peers, reported_by, distance)) => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::PeerDiscoveryAnswer");

                let max_peers = self.global_state_lock.cli().max_num_peers;
                for pot_peer in pot_peers {
                    main_loop_state.potential_peers.add(
                        reported_by,
                        pot_peer,
                        max_peers,
                        distance,
                        self.now(),
                    );
                }
            }
            PeerTaskToMain::NewPeer(peer_id) => {
                if let Some(sync_loop) = &main_loop_state.maybe_sync_loop {
                    sync_loop.send_add_peer(peer_id).await;
                }
            }
            PeerTaskToMain::DroppedPeer(peer_id) => {
                if let Some(sync_loop) = &main_loop_state.maybe_sync_loop {
                    sync_loop.send_remove_peer(peer_id).await;
                }
            }
            PeerTaskToMain::Transaction(pt2m_transaction) => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::Transaction");

                debug!(
                    "`peer_loop` received following transaction from peer. {} inputs, {} outputs. Synced to mutator set hash: {}",
                    pt2m_transaction.transaction.kernel.inputs.len(),
                    pt2m_transaction.transaction.kernel.outputs.len(),
                    pt2m_transaction.transaction.kernel.mutator_set_hash
                );

                {
                    let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                    if pt2m_transaction.confirmable_for_block != global_state_mut.chain.tip().hash()
                    {
                        warn!("main loop got unmined transaction with bad mutator set data, discarding transaction");
                        return Ok(());
                    }

                    global_state_mut
                        .mempool_insert(pt2m_transaction.transaction.to_owned())
                        .await;
                }

                let is_nop = pt2m_transaction.transaction.kernel.inputs.is_empty()
                    && pt2m_transaction.transaction.kernel.outputs.is_empty()
                    && pt2m_transaction.transaction.kernel.announcements.is_empty();
                if !is_nop {
                    // if meaningful, send notification to peers
                    let transaction_notification: TransactionNotification =
                        (&pt2m_transaction.transaction).try_into()?;

                    let pmsg = MainToPeerTask::TransactionNotification(transaction_notification);
                    self.main_to_peer_broadcast(pmsg);
                }
            }
            PeerTaskToMain::BlockProposal(block) => {
                log_slow_scope!(fn_name!() + "::PeerTaskToMain::BlockProposal");

                debug!("main loop received block proposal from peer loop");

                // Due to race-conditions, we need to verify that this
                // block proposal is still the immediate child of tip. If it is,
                // and it has a higher guesser fee than what we're currently
                // working on, then we switch to this, and notify the miner to
                // mine on this new block. We don't need to verify the block's
                // validity, since that was done in peer loop.
                // To ensure atomicity, a write-lock must be held over global
                // state while we check if this proposal is favorable.
                {
                    let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;

                    let reward = block
                        .body()
                        .total_guesser_reward()
                        .expect("block received by main loop must have guesser reward");
                    let verdict = global_state_mut
                        .favor_incoming_block_proposal(block.header().prev_block_digest, reward);

                    if let Err(reject_reason) = verdict {
                        warn!("Main loop got unfavorable block proposal. Reason: {reject_reason}");
                        return Ok(());
                    }

                    info!("Accepted incoming foreign block proposal and replaced the current (reward: {reward} NYKS).");
                    global_state_mut.mining_state.block_proposal =
                        BlockProposal::foreign_proposal(*block.clone());
                }

                // Notify all peers of the block proposal we just accepted. Do
                // this regardless of the difference in guesser fee relative to
                // the previous proposal (as long as it is positive).
                let pmsg = MainToPeerTask::BlockProposalNotification((&*block).into());
                self.main_to_peer_broadcast(pmsg);
            }
            PeerTaskToMain::DisconnectFromLongestLivedPeer => {
                let global_state = self.global_state_lock.lock_guard().await;

                // get all peers
                let all_peers = global_state.net.peer_map.iter();

                // filter out CLI peers
                let cli_peers = global_state.cli().peers.iter().collect::<HashSet<_>>();
                let disconnect_candidates = all_peers
                    .filter(|(_id, info)| !cli_peers.contains(&info.address()))
                    .filter(|p| multiaddr_to_socketaddr(&p.1.address()).is_some());

                // find the one with the oldest connection
                let longest_lived_peer =
                    disconnect_candidates.min_by(|(_, peer_info_left), (_, peer_info_right)| {
                        peer_info_left
                            .connection_established()
                            .cmp(&peer_info_right.connection_established())
                    });

                // tell to disconnect
                if let Some((peer_id, _peer_info)) = longest_lived_peer {
                    let pmsg = MainToPeerTask::Disconnect(*peer_id);
                    self.main_to_peer_broadcast(pmsg);
                }
            }
            PeerTaskToMain::NewSyncTarget(new_target) => {
                if let Some(sync_loop) = &mut main_loop_state.maybe_sync_loop {
                    // Double-check new leadership status. Race condition.
                    let height = new_target.header().height;
                    let block_hash = new_target.hash();
                    if sync_loop.target_height().next() == height {
                        sync_loop.send_new_target(new_target).await;
                        if let Some(sync_anchor) = self
                            .global_state_lock
                            .lock_guard_mut()
                            .await
                            .net
                            .sync_anchor
                            .as_mut()
                        {
                            sync_anchor.catch_up(height, block_hash);
                        } else {
                            error!("Sync mode active but sync anchor not set. The two should always be in sync.");
                        }
                    }
                }
            }
            PeerTaskToMain::NewSyncBlock(block, peer) => {
                if let Some(sync_loop) = &main_loop_state.maybe_sync_loop {
                    // If we already know this block and it is on the canonical
                    // chain, then we can fast-forward the sync; we are only
                    // interested in downloading blocks that come after.
                    let block_digest = block.hash();
                    let state = self.global_state_lock.lock_guard().await;
                    let have_block = state
                        .chain
                        .archival_state()
                        .get_block_header(block_digest)
                        .await
                        .is_some();
                    let is_canonical = if have_block {
                        state
                            .chain
                            .archival_state()
                            .block_belongs_to_canonical_chain(block_digest)
                            .await
                    } else {
                        false
                    };
                    if have_block && is_canonical {
                        info!("Fast-forwarding sync to block {}.", block.header().height);
                        sync_loop.send_fast_forward_block(block).await;
                    } else {
                        sync_loop.send_block(block, peer);
                    }
                }
            }
            PeerTaskToMain::SyncCoverage(synchronization_bit_mask, socket_addr) => {
                if let Some(sync_loop) = &main_loop_state.maybe_sync_loop {
                    sync_loop.send_sync_coverage(socket_addr, synchronization_bit_mask);
                }
            }
            PeerTaskToMain::PeerWantsSyncBlock(peer, height) => {
                if let Some(sync_loop) = &main_loop_state.maybe_sync_loop {
                    sync_loop.send_try_fetch_block(peer, height);
                }
            }
            PeerTaskToMain::Ban(malicious_peer_id) => {
                // Forward the request. The NetworkActor is the one to enforce
                // the ban.
                if let Err(e) = self
                    .network_command_tx
                    .send(NetworkActorCommand::Ban(Either::Left(malicious_peer_id)))
                    .await
                {
                    error!("Cannot send message to NetworkActor: {e}.");
                }
            }
        }

        Ok(())
    }

    /// If necessary, disconnect from peers.
    ///
    /// While a reasonable effort is made to never have more connections than
    /// [`max_num_peers`](crate::application::config::cli_args::Args::max_num_peers),
    /// this is not guaranteed. For example, bootstrap nodes temporarily allow a
    /// surplus of incoming connections to provide their service more reliably.
    ///
    /// Never disconnects peers listed as CLI arguments.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for read
    async fn prune_peers(&self) -> Result<()> {
        // fetch all relevant info from global state; don't hold the lock
        let cli_args = self.global_state_lock.cli();
        let global_state = self.global_state_lock.lock_guard().await;
        let connected_peers = global_state
            .net
            .peer_map
            .iter()
            .map(|(peer_id, peer_info)| (*peer_id, peer_info.clone()))
            .collect_vec();
        drop(global_state);

        let num_peers = connected_peers.len();
        let max_num_peers = cli_args.max_num_peers;
        if num_peers <= max_num_peers {
            debug!("No need to prune any peer connections.");
            return Ok(());
        }
        warn!("Connected to {num_peers} peers, which exceeds the maximum ({max_num_peers}).");

        // If all connections are outbound, it's OK to exceed the max.
        if connected_peers
            .iter()
            .all(|(_, p)| p.connection_is_outbound())
        {
            warn!("Not disconnecting from any peer because all connections are outbound.");
            return Ok(());
        }

        let num_peers_to_disconnect = num_peers - max_num_peers;
        let cli_peers = cli_args.peers.iter().collect::<HashSet<_>>();
        let peers_to_disconnect = connected_peers
            .into_iter()
            .filter(|(_, peer)| !cli_peers.contains(&peer.address()))
            .choose_multiple(&mut rand::rng(), num_peers_to_disconnect);
        match peers_to_disconnect.len() {
            0 => warn!("Not disconnecting from any peer because of manual override."),
            i => info!("Disconnecting from {i} peers."),
        }
        for (peer_id, _) in peers_to_disconnect {
            let pmsg = MainToPeerTask::Disconnect(peer_id);
            self.main_to_peer_broadcast(pmsg);
        }

        Ok(())
    }

    /// If necessary, reconnect to the peers listed as CLI arguments.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for read
    async fn reconnect(&self, main_loop_state: &mut MutableMainLoopState) -> Result<()> {
        let connected_peers = self
            .global_state_lock
            .lock_guard()
            .await
            .net
            .peer_map
            .iter()
            .map(|(peer_id, peer_info)| (*peer_id, peer_info.clone()))
            .collect_vec();
        let connected_peers_addresses = connected_peers
            .iter()
            .map(|(_peer_id, peer_info)| peer_info.address().clone())
            .collect_vec();
        let peers_with_lost_connection = self
            .global_state_lock
            .cli()
            .peers
            .iter()
            .filter(|peer| !connected_peers_addresses.contains(peer));

        // If no connection was lost, there's nothing to do.
        if peers_with_lost_connection.clone().count() == 0 {
            return Ok(());
        }

        // Else, try to reconnect.
        let own_handshake_data = self
            .global_state_lock
            .lock_guard()
            .await
            .get_own_handshakedata();
        for peer_with_lost_connection in peers_with_lost_connection {
            if let Some(socketaddr) = multiaddr_to_socketaddr(peer_with_lost_connection) {
                // Disallow reconnection if peer is in bad standing
                let peer_standing = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .net
                    .get_peer_standing_from_database(socketaddr.ip())
                    .await;
                if peer_standing.is_some_and(|standing| standing.is_bad()) {
                    debug!("Not reconnecting to peer in bad standing: {socketaddr}");
                    continue;
                }

                debug!("Attempting to reconnect to peer: {socketaddr}");
                let global_state_lock = self.global_state_lock.clone();
                let main_to_peer_broadcast_rx = self.main_to_peer_broadcast_tx.subscribe();
                let peer_task_to_main_tx = self.peer_task_to_main_tx.to_owned();
                let outgoing_connection_task = tokio::task::spawn(async move {
                    call_peer(
                        socketaddr,
                        global_state_lock,
                        main_to_peer_broadcast_rx,
                        peer_task_to_main_tx,
                        own_handshake_data,
                        1, // All CLI-specified peers have distance 1
                    )
                    .await;
                });
                main_loop_state.task_handles.push(outgoing_connection_task);
            } else if let Err(e) = self
                .network_command_tx
                .send(NetworkActorCommand::Dial(peer_with_lost_connection.clone()))
                .await
            {
                warn!("Failed to reconnect to peer {peer_with_lost_connection}: {e}.");
            }
            main_loop_state.task_handles.retain(|th| !th.is_finished());
        }

        Ok(())
    }

    /// Perform peer discovery.
    ///
    /// Peer discovery involves finding potential peers from connected peers
    /// and attempts to establish a connection with one of them.
    ///
    /// Locking:
    ///   * acquires `global_state_lock` for read
    async fn discover_peers(&self, main_loop_state: &mut MutableMainLoopState) -> Result<()> {
        // fetch all relevant info from global state, then release the lock
        let cli_args = self.global_state_lock.cli();
        let global_state = self.global_state_lock.lock_guard().await;
        let connected_peers = global_state.net.peer_map.values().cloned().collect_vec();
        let own_instance_id = global_state.net.instance_id;
        let own_handshake_data = global_state.get_own_handshakedata();
        drop(global_state);

        let num_peers = connected_peers.len();
        let max_num_peers = cli_args.max_num_peers;

        // Don't make an outgoing connection if
        // - the peer limit is reached (or exceeded), or
        // - the peer limit is _almost_ reached; reserve the last slot for an
        //   incoming connection.
        if num_peers >= max_num_peers || num_peers > 2 && num_peers - 1 == max_num_peers {
            debug!("Connected to {num_peers} peers. The configured max is {max_num_peers} peers.");
            debug!("Skipping peer discovery.");
            return Ok(());
        }

        debug!("Performing peer discovery");

        // Ask all peers for their peer lists. This will eventually – once the
        // responses have come in – update the list of potential peers.
        let pmsg = MainToPeerTask::MakePeerDiscoveryRequest;
        self.main_to_peer_broadcast(pmsg);

        // Get a peer candidate from the list of potential peers. Generally,
        // the peer lists requested in the previous step will not have come in
        // yet. Therefore, the new candidate is selected based on somewhat
        // (but not overly) old information.
        let Some((peer_candidate, candidate_distance)) = main_loop_state
            .potential_peers
            .get_candidate(&connected_peers, own_instance_id)
        else {
            debug!("Found no peer candidate to connect to. Not making new connection.");
            return Ok(());
        };

        // Try to connect to the selected candidate.
        debug!("Connecting to peer {peer_candidate} with distance {candidate_distance}");
        let global_state_lock = self.global_state_lock.clone();
        let main_to_peer_broadcast_rx = self.main_to_peer_broadcast_tx.subscribe();
        let peer_task_to_main_tx = self.peer_task_to_main_tx.to_owned();
        let outgoing_connection_task = tokio::task::spawn(async move {
            call_peer(
                peer_candidate,
                global_state_lock,
                main_to_peer_broadcast_rx,
                peer_task_to_main_tx,
                own_handshake_data,
                candidate_distance,
            )
            .await;
        });
        main_loop_state.task_handles.push(outgoing_connection_task);
        main_loop_state.task_handles.retain(|th| !th.is_finished());

        // Immediately request the new peer's peer list. This allows
        // incorporating the new peer's peers into the list of potential peers,
        // to be used in the next round of peer discovery.
        let m2pmsg = MainToPeerTask::MakeSpecificPeerDiscoveryRequest(peer_candidate);
        self.main_to_peer_broadcast(m2pmsg);

        Ok(())
    }

    pub async fn run(&mut self) -> Result<i32> {
        info!("Starting main loop");

        let task_handles = std::mem::take(&mut self.task_handles);

        // Handle incoming connections, messages from peer tasks, and messages from the mining task
        let mut main_loop_state = MutableMainLoopState::new(task_handles);

        // Set up various timers.
        //
        // The `MissedTickBehavior::Delay` is appropriate for tasks that don't
        // do anything meaningful if executed in quick succession. For example,
        // pruning stale information immediately after pruning stale information
        // is almost certainly a no-op.
        // Similarly, tasks performing network operations (e.g., peer discovery)
        // should probably not try to “catch up” if some ticks were missed.

        // Don't run peer discovery immediately at startup since outgoing
        // connections started from lib.rs may not have finished yet.
        let mut peer_discovery_interval = time::interval_at(
            Instant::now() + PEER_DISCOVERY_INTERVAL,
            PEER_DISCOVERY_INTERVAL,
        );
        peer_discovery_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut block_sync_interval = time::interval(SYNC_REQUEST_INTERVAL);
        block_sync_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut mempool_cleanup_interval = time::interval(MEMPOOL_PRUNE_INTERVAL);
        mempool_cleanup_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // Spawn tasks to monitor for SIGTERM, SIGINT, and SIGQUIT. These
        // signals are only used on Unix systems.
        let (tx_term, mut rx_term) = mpsc::channel::<()>(2);
        let (tx_int, mut rx_int) = mpsc::channel::<()>(2);
        let (tx_quit, mut rx_quit) = mpsc::channel::<()>(2);
        #[cfg(unix)]
        {
            use tokio::signal::unix::signal;
            use tokio::signal::unix::SignalKind;

            // Monitor for SIGTERM
            let mut sigterm = signal(SignalKind::terminate())?;
            tokio::task::spawn(async move {
                if sigterm.recv().await.is_some() {
                    info!("Received SIGTERM");
                    tx_term.send(()).await.unwrap();
                }
            });

            // Monitor for SIGINT
            let mut sigint = signal(SignalKind::interrupt())?;
            tokio::task::spawn(async move {
                if sigint.recv().await.is_some() {
                    info!("Received SIGINT");
                    tx_int.send(()).await.unwrap();
                }
            });

            // Monitor for SIGQUIT
            let mut sigquit = signal(SignalKind::quit())?;
            tokio::task::spawn(async move {
                if sigquit.recv().await.is_some() {
                    info!("Received SIGQUIT");
                    tx_quit.send(()).await.unwrap();
                }
            });
        }

        #[cfg(not(unix))]
        drop((tx_term, tx_int, tx_quit));

        // Use a semaphore to limit number of incoming connections. Should only be
        // relevant as a countermeasure against a DOS. Each incoming connection
        // must acquire a permit. If none is free, the below call to `acquire_owned`
        // will only be resolved when an incoming connection is closed. This
        // value is set much higher than the configured max number of peers since it's
        // only intended to be used in case of heavy DOS.
        let incoming_connections_limit = Arc::new(Semaphore::new(
            self.global_state_lock.cli().max_num_peers * 2 + 4,
        ));

        let exit_code: i32 = loop {
            select! {
                Ok(()) = signal::ctrl_c() => {
                    info!("Detected Ctrl+c signal.");
                    break SUCCESS_EXIT_CODE;
                }

                // Monitor for SIGTERM, SIGINT, and SIGQUIT.
                Some(_) = rx_term.recv() => {
                    info!("Detected SIGTERM signal.");
                    break SUCCESS_EXIT_CODE;
                }
                Some(_) = rx_int.recv() => {
                    info!("Detected SIGINT signal.");
                    break SUCCESS_EXIT_CODE;
                }
                Some(_) = rx_quit.recv() => {
                    info!("Detected SIGQUIT signal.");
                    break SUCCESS_EXIT_CODE;
                }

                // Handle incoming connections from peer
                Ok((stream, peer_address)) = self.incoming_peer_listener.accept() => {
                    let ip = peer_address.ip();
                    if !precheck_incoming_connection_is_allowed(self.global_state_lock.cli(), ip) {
                        continue;
                    }

                    // Is this IP banned through database entry?
                    let peer_banned = self.global_state_lock.lock_guard().await.net.peer_databases.peer_standings_by_ip.get(ip).await.is_some_and(|x| x.is_bad());
                    if peer_banned {
                        debug!("Banned peer {ip} attempted incoming connection. Hanging up.");
                        continue;
                    }

                    // Bump semaphore counter for incoming connections. Should
                    // be done after the precheck to prevent unnecessary
                    // acquisitions.
                    let timeout = Duration::from_secs(self.global_state_lock.cli().handshake_timeout.into());
                    let permit = time::timeout(timeout, incoming_connections_limit.clone().acquire_owned()).await;
                    let Ok(permit) = permit else {
                        warn!("Too many incoming connections to handle. Dropping incoming connection from {ip}.");
                        continue;
                    };

                    let permit = permit?;

                    let state = self.global_state_lock.lock_guard().await;
                    let main_to_peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerTask> = self.main_to_peer_broadcast_tx.subscribe();
                    let peer_task_to_main_tx_clone: mpsc::Sender<PeerTaskToMain> = self.peer_task_to_main_tx.clone();
                    let own_handshake_data: HandshakeData = state.get_own_handshakedata();
                    let global_state_lock = self.global_state_lock.clone(); // bump arc refcount.
                    let incoming_peer_task_handle = tokio::task::spawn(async move {
                        // Permit is passed to answer_peer and released after handshake,
                        // not when the connection closes. This prevents semaphore
                        // starvation attacks.
                        match answer_peer(
                            stream,
                            global_state_lock,
                            peer_address,
                            main_to_peer_broadcast_rx_clone,
                            peer_task_to_main_tx_clone,
                            own_handshake_data,
                            Some(permit),
                        ).await {
                            Ok(()) => (),
                            Err(err) => debug!("Got result: {:?}", err),
                        }
                    });
                    main_loop_state.task_handles.push(incoming_peer_task_handle);
                    main_loop_state.task_handles.retain(|th| !th.is_finished());
                }

                // Handle messages from peer tasks
                Some(msg) = self.peer_task_to_main_rx.recv() => {
                    debug!("Received message sent to main task.");
                    self.handle_peer_task_message(
                        msg,
                        &mut main_loop_state,
                    )
                    .await?
                }

                // Handle messages from the network actor
                Some(network_event) = self.network_event_rx.recv() => {
                    debug!("Received message from network actor.");
                    self.handle_network_event(network_event, &mut main_loop_state)?;
                }

                // Handle messages from rpc server task
                Some(rpc_server_message) = self.rpc_server_to_main_rx.recv() => {
                    let shutdown_after_execution = self.handle_rpc_server_message(rpc_server_message, &mut main_loop_state).await?;
                    if shutdown_after_execution {
                        break SUCCESS_EXIT_CODE
                    }
                }

                // Handle messages from the sync loop (if one exists)
                Some(sync_loop_msg) = SyncLoopHandle::maybe_recv(&mut main_loop_state.maybe_sync_loop) => {
                    let Some(sync_loop) = main_loop_state.maybe_sync_loop else {
                        error!("Received message from non-existent sync loop.");
                        continue;
                    };
                    main_loop_state.maybe_sync_loop = self.handle_sync_loop_message(sync_loop_msg, sync_loop).await;
                }

                // Handle peer discovery
                _ = peer_discovery_interval.tick() => {
                    log_slow_scope!(fn_name!() + "::select::peer_discovery_interval");

                    // Check number of peers we are connected to and connect to
                    // more peers if needed.
                    debug!("Timer: peer discovery job");

                    let perform_discovery = if !self.global_state_lock.cli().network.performs_peer_discovery() {
                        // this makes regtest mode behave in a local, controlled way
                        // because no regtest nodes attempt to discover eachother, so the only
                        // peers are those that are manually added.
                        // see: https://github.com/Neptune-Crypto/neptune-core/issues/539#issuecomment-2764701027
                        debug!("peer discovery disabled for network {}", self.global_state_lock.cli().network);
                        false
                    } else if self.global_state_lock.cli().restrict_peers_to_list {
                        debug!("peer discovery disabled due to --restrict-peers-to-list");
                        false
                    } else {
                        true
                    };

                    if perform_discovery {
                        self.prune_peers().await?;
                        self.reconnect(&mut main_loop_state).await?;
                        self.discover_peers(&mut main_loop_state).await?;
                    }
                }

                // // Handle synchronization (i.e. batch-downloading of blocks)
                // _ = block_sync_interval.tick() => {
                //     log_slow_scope!(fn_name!() + "::select::block_sync_interval");

                //     trace!("Timer: block-synchronization job");
                //     self.block_sync(&mut main_loop_state).await?;
                // }

                // Clean up mempool: remove stale / too old transactions
                _ = mempool_cleanup_interval.tick() => {
                    log_slow_scope!(fn_name!() + "::select::mempool_cleanup_interval");

                    debug!("Timer: mempool-cleaner job");
                    self
                        .global_state_lock
                        .lock_guard_mut()
                        .await
                        .mempool_prune_stale_transactions()
                        .await;
                }
            }
        };

        self.graceful_shutdown(
            main_loop_state.task_handles,
            main_loop_state.maybe_sync_loop,
        )
        .await?;
        info!("Shutdown completed.");

        Ok(exit_code)
    }

    /// Handle messages from the RPC server. Returns `true` iff the client should shut down
    /// after handling this message.
    async fn handle_rpc_server_message(
        &mut self,
        msg: RPCServerToMain,
        main_loop_state: &mut MutableMainLoopState,
    ) -> Result<bool> {
        match msg {
            RPCServerToMain::BroadcastMempoolTransactions => {
                info!("Broadcasting transaction notifications for all shareable transactions in mempool");

                let mut notifications = vec![];
                {
                    let state = self.global_state_lock.lock_guard().await;
                    for (txid, _) in state.mempool.fee_density_iter() {
                        // Since a read-lock is held over global state, the
                        // transaction must exist in the mempool.
                        let tx = state
                            .mempool
                            .get(txid)
                            .expect("Transaction from iter must exist in mempool");
                        let notification = TransactionNotification::try_from(tx);
                        match notification {
                            Ok(notification) => {
                                let pmsg = MainToPeerTask::TransactionNotification(notification);
                                notifications.push(pmsg);
                            }
                            Err(error) => {
                                warn!("{error}");
                            }
                        };
                    }
                }

                for notification in notifications {
                    self.main_to_peer_broadcast(notification);
                }

                Ok(false)
            }
            RPCServerToMain::SetTipToStoredBlock(digest) => {
                info!("Setting tip to {digest:x}");

                let res = self
                    .global_state_lock()
                    .lock_guard_mut()
                    .await
                    .set_tip_to_stored_block(digest)
                    .await;
                match res {
                    Ok(_) => info!("Changed the tip to {digest:x} successfully"),
                    Err(e) => error!("Failed to set tip to {digest:x}: {e}"),
                };

                Ok(false)
            }
            RPCServerToMain::BroadcastBlockProposal => {
                let pmsg = self
                    .global_state_lock
                    .lock_guard()
                    .await
                    .mining_state
                    .block_proposal
                    .map(|proposal| MainToPeerTask::BlockProposalNotification(proposal.into()));
                if let Some(pmsg) = pmsg {
                    info!("Broadcasting block proposal notification to all peers.");
                    self.main_to_peer_broadcast(pmsg);
                } else {
                    info!("Was asked to broadcast block proposal but none is known.");
                }

                Ok(false)
            }
            RPCServerToMain::ClearMempool => {
                info!("Clearing mempool");
                self.global_state_lock
                    .lock_guard_mut()
                    .await
                    .mempool_clear()
                    .await;

                Ok(false)
            }
            RPCServerToMain::ProofOfWorkSolution(new_block) => {
                info!("Handling PoW solution from RPC call");

                self.handle_self_guessed_block(main_loop_state, new_block)
                    .await?;
                Ok(false)
            }
            RPCServerToMain::Shutdown => {
                info!("Received RPC shutdown request.");

                // shut down
                Ok(true)
            }
            RPCServerToMain::BlockProposal(block) => {
                // Due to race-conditions, we need to verify that this
                // block proposal is still the immediate child of tip. If it is,
                // and it has a higher guesser fee than what we're currently
                // working on, then we switch to this, and notify the miner to
                // mine on this new block. We don't need to verify the block's
                // validity, since that was done in peer loop.
                // To ensure atomicity, a write-lock must be held over global
                // state while we check if this proposal is favorable.
                {
                    let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                    let verdict = global_state_mut.favor_incoming_block_proposal(
                        block.header().prev_block_digest,
                        block
                            .body()
                            .total_guesser_reward()
                            .expect("block received by main loop must have guesser reward"),
                    );
                    if let Err(reject_reason) = verdict {
                        warn!("main loop got unfavorable block proposal thru RPC. Reason: {reject_reason}");
                    }

                    global_state_mut.mining_state.block_proposal =
                        BlockProposal::ForeignComposition(*block.clone());
                }

                // Notify all peers of the block proposal we just accepted. Do
                // this regardless of the difference in guesser fee relative to
                // the previous proposal (as long as it is positive).
                let pmsg = MainToPeerTask::BlockProposalNotification((&*block).into());
                self.main_to_peer_broadcast(pmsg);

                Ok(false)
            }
            RPCServerToMain::BroadcastTx(transaction) => {
                let notification: TransactionNotification = transaction.as_ref().into();

                {
                    let mut state = self.global_state_lock.lock_guard_mut().await;
                    state.mempool_insert(*transaction).await;
                }

                // Notify the peers about the transaction.
                let pmsg = MainToPeerTask::TransactionNotification(notification);
                self.main_to_peer_broadcast(pmsg);

                Ok(false)
            }
            RPCServerToMain::Ban(multiaddr) => {
                log_slow_scope!(fn_name!() + "::RPCServerToMain::Ban");

                // Try get `PeerId` from peer map. Success indicates we are
                // currently connected to them.
                let mut maybe_network_command = None;
                let mut maybe_peer_message: Option<MainToPeerTask> = None;
                if let Some((peer_id, peer_info)) = self
                    .global_state_lock()
                    .lock_guard_mut()
                    .await
                    .net
                    .peer_map
                    .iter_mut()
                    .find(|(_peer_id, peer_info)| peer_info.address() == multiaddr)
                {
                    // Send `Ban` command to NetworkActor.
                    info!("Banning peer by PeerId {peer_id}.");
                    maybe_network_command = Some(NetworkActorCommand::Ban(Either::Left(*peer_id)));

                    // Max out peer's negative standing.
                    peer_info.standing.standing = -peer_info.standing.peer_tolerance;

                    // Disconnect.
                    maybe_peer_message = Some(MainToPeerTask::Disconnect(*peer_id));
                } else if let Some(ip_addr) = multiaddr.iter().find_map(|protocol| match protocol {
                    libp2p::multiaddr::Protocol::Ip4(ipv4_addr) => Some(IpAddr::V4(ipv4_addr)),
                    libp2p::multiaddr::Protocol::Ip6(ipv6_addr) => Some(IpAddr::V6(ipv6_addr)),
                    _ => None,
                }) {
                    // Send `Ban` command to NetworkActor.
                    info!("Banning peer by IP {ip_addr}.");
                    maybe_network_command = Some(NetworkActorCommand::Ban(Either::Right(ip_addr)));
                } else {
                    warn!("Cannot ban peer: failed to extract PeerId and IP address. Nothing to hammer.");
                };

                // Now that the lock is dropped, we can send messages without
                // risk of heart attack.
                if let Some(ban_command) = maybe_network_command {
                    if let Err(e) = self.network_command_tx.send(ban_command).await {
                        error!("Cannot send Ban message to NetworkActor: {e}.");
                    }
                }
                if let Some(peer_message) = maybe_peer_message {
                    if let Err(e) = self.main_to_peer_broadcast_tx.send(peer_message) {
                        error!("Cannot send Disconnect message to peer loop: {e}.");
                    }
                }
                Ok(false)
            }
            RPCServerToMain::Unban(multiaddr) => {
                log_slow_scope!(fn_name!() + "::RPCServerToMain::Unban");

                if let Some(ip_addr) = multiaddr.iter().find_map(|protocol| match protocol {
                    libp2p::multiaddr::Protocol::Ip4(ipv4_addr) => Some(IpAddr::V4(ipv4_addr)),
                    libp2p::multiaddr::Protocol::Ip6(ipv6_addr) => Some(IpAddr::V6(ipv6_addr)),
                    _ => None,
                }) {
                    // Send Unban command to NetworkActor
                    if let Err(e) = self
                        .network_command_tx
                        .send(NetworkActorCommand::Unban(ip_addr))
                        .await
                    {
                        error!("Cannot send Unban message to NetworkActor: {e}.");
                        return Ok(false);
                    };

                    // Reset standing in database.
                    self.global_state_lock()
                        .lock_guard_mut()
                        .await
                        .net
                        .clear_ip_standing_in_database(ip_addr)
                        .await;
                } else {
                    warn!("Cannot ban peer: failed to extract IP address. Nothing to hammer.");
                }

                Ok(false)
            }
            RPCServerToMain::UnbanAll => {
                log_slow_scope!(fn_name!() + "::RPCServerToMain::UnbanAll");

                // Reset standings.
                self.global_state_lock()
                    .lock_guard_mut()
                    .await
                    .net
                    .clear_all_standings_in_database()
                    .await;

                // Instruct NetworkActor to revoke bans.
                if let Err(e) = self
                    .network_command_tx
                    .send(NetworkActorCommand::UnbanAll)
                    .await
                {
                    error!("Cannot send UnbanAll message to NetworkActor: {e}.");
                }

                Ok(false)
            }
            RPCServerToMain::Dial(address) => {
                log_slow_scope!(fn_name!() + "::RPCServerToMain::Dial");

                // Pass on message to NetworkActor.
                if let Err(e) = self
                    .network_command_tx
                    .send(NetworkActorCommand::Dial(address))
                    .await
                {
                    error!("Cannot send Dial message to NetworkActor: {e}.");
                }

                Ok(false)
            }
            RPCServerToMain::ProbeNat => {
                log_slow_scope!(fn_name!() + "::RPCServerToMain::ProbeNat");

                // Pass on message to NetworkActor.
                if let Err(e) = self
                    .network_command_tx
                    .send(NetworkActorCommand::ProbeNat)
                    .await
                {
                    error!("Cannot send ProbeNat message to NetworkActor: {e}.");
                }

                Ok(false)
            }
            RPCServerToMain::ResetRelayReservations => {
                log_slow_scope!(fn_name!() + "::RPCServerToMain::ResetRelayReservations");

                // Pass on message to NetworkActor.
                if let Err(e) = self
                    .network_command_tx
                    .send(NetworkActorCommand::ResetRelayReservations)
                    .await
                {
                    error!("Cannot send ResetRelayReservations message to NetworkActor: {e}.");
                }

                Ok(false)
            }
            RPCServerToMain::GetNetworkOverview(channel) => {
                log_slow_scope!(fn_name!() + "::RPCServerToMain::ResetRelayReservations");

                // Pass on message to NetworkActor.
                if let Err(e) = self
                    .network_command_tx
                    .send(NetworkActorCommand::GetNetworkOverview(channel))
                    .await
                {
                    error!("Cannot send GetNetworkOverview message to NetworkActor: {e}.");
                }

                Ok(false)
            }
        }
    }

    /// Handle a message from the sync loop.
    async fn handle_sync_loop_message(
        &mut self,
        sync_loop_message: SyncToMain,
        sync_loop_handle: SyncLoopHandle,
    ) -> Option<SyncLoopHandle> {
        match sync_loop_message {
            SyncToMain::Finished(block_height) => {
                info!("Finished syncing to block height {block_height}.");

                // Delete external sync anchor.
                self.global_state_lock
                    .lock_guard_mut()
                    .await
                    .net
                    .sync_anchor = None;

                // Show finished where RPC server will look.
                self.global_state_lock
                    .lock_guard_mut()
                    .await
                    .net
                    .sync_status = SyncStatus::Synced;

                // The sync loop cleaned up after itself. No need to abort tasks
                // or delete files. Just drop the handle.
                return None;
            }
            SyncToMain::Error => {
                error!("Failed to sync.");

                // Delete external sync anchor.
                self.global_state_lock
                    .lock_guard_mut()
                    .await
                    .net
                    .sync_anchor = None;

                // Provoke block height notification messages from peers. This
                // could start a new sync loop, and that one might finish
                // successfully.
                self.main_to_peer_broadcast(MainToPeerTask::RequestBlockNotification);

                // Show unknown current state where RPC server will look.
                self.global_state_lock
                    .lock_guard_mut()
                    .await
                    .net
                    .sync_status = SyncStatus::Unknown;

                // If we go the error message, the sync loop halted in error but
                // somewhat gracefully. Specifically, the sync loop would have
                // cleaned up after itself. So no need to abort tasks or delete
                // files. Just drop the handle.
                return None;
            }
            SyncToMain::TipSuccessor(block) => {
                log_slow_scope!(fn_name!() + "::SyncToMain::TipSuccessor");
                let height = block.header().height;

                let mut global_state_mut = self.global_state_lock.lock_guard_mut().await;
                let new_canonical = global_state_mut.incoming_block_is_more_canonical(&block);

                // Store block, whether as tip or not.
                if !new_canonical {
                    if let Err(e) = global_state_mut.store_block_not_tip(*block).await {
                        panic!("Could not store sync block {}: {e}.", height);
                    }
                } else if let Err(e) = global_state_mut.set_new_tip(*block).await {
                    panic!("Could not store sync block {} as new tip: {e}.", height);
                }

                // Flush.
                if let Err(e) = global_state_mut.flush_databases().await {
                    panic!("Could not flush databases following block write: {e}.");
                }

                // Report.
                info!("Processed block {height} from sync loop.");
            }
            SyncToMain::RequestBlocks(block_requests) => {
                // Distribute requests.
                for BlockRequest {
                    peer_handle,
                    height,
                } in block_requests
                {
                    self.main_to_peer_broadcast(MainToPeerTask::RequestBlockByHeight {
                        target_peer: peer_handle,
                        height,
                    });
                }
            }
            SyncToMain::Status(status) => {
                info!("Sync loop progress: {status}.");
                // Store on network state.
                self.global_state_lock
                    .lock_guard_mut()
                    .await
                    .net
                    .sync_status = SyncStatus::Syncing(status);
            }
            SyncToMain::Punish(peers) => {
                for peer in peers {
                    self.main_to_peer_broadcast(MainToPeerTask::PeerSynchronizationTimeout(peer));
                }
            }
            SyncToMain::Coverage {
                coverage,
                peer_handle,
            } => {
                self.main_to_peer_broadcast(MainToPeerTask::SyncCoverage {
                    coverage,
                    peer_handle,
                });
            }
            SyncToMain::SyncBlock { block, peer_handle } => {
                self.main_to_peer_broadcast(MainToPeerTask::SyncBlock { block, peer_handle });
            }
        }

        Some(sync_loop_handle)
    }

    async fn graceful_shutdown(
        &mut self,
        join_handles: Vec<JoinHandle<()>>,
        maybe_sync_loop_handle: Option<SyncLoopHandle>,
    ) -> Result<()> {
        info!("Shutdown initiated.");

        // If the sync loop is active, stop it.
        if let Some(sync_loop_handle) = maybe_sync_loop_handle {
            sync_loop_handle.abort().await;
        }

        // Send 'bye' message to all peers.
        let pmsg = MainToPeerTask::DisconnectAll();
        self.main_to_peer_broadcast(pmsg);
        debug!("sent bye");

        // Tell network actor to shut down swarm.
        if let Err(e) = self
            .network_command_tx
            .send(NetworkActorCommand::Shutdown)
            .await
        {
            error!("Could not send Shutdown command to Network Actor: {e}.");
        };

        // Flush all databases
        self.global_state_lock.flush_databases().await?;

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Child tasks should have finished by now. If not, abort them.
        for jh in &join_handles {
            jh.abort();
        }

        // wait for all to finish.
        futures::future::join_all(join_handles).await;

        Ok(())
    }

    // broadcasts message to peers (if any connected)
    //
    // panics if broadcast failed and channel receiver_count is non-zero
    // indicating we have peer connections.
    fn main_to_peer_broadcast(&self, msg: MainToPeerTask) {
        if let Err(e) = self.main_to_peer_broadcast_tx.send(msg) {
            // tbd: maybe we should just log an error and ignore rather
            // than panic.  but for now this preserves prior behavior
            let receiver_count = self.main_to_peer_broadcast_tx.receiver_count();
            assert_eq!(
                receiver_count, 0,
                "failed to broadcast message from main to {} peer loops: {:?}",
                receiver_count, e
            );
        }
    }
}
