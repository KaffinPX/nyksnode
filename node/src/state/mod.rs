pub mod archival_state;
pub mod blockchain_state;
pub mod claim_error;
pub mod database;
pub mod light_state;
pub mod mempool;
pub mod mining;
pub mod networking_state;
pub mod shared;
pub mod sync_status;

use std::collections::HashMap;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;
use blockchain_state::BlockchainArchivalState;
use blockchain_state::BlockchainState;
use light_state::LightState;
use mempool::Mempool;
use mining::block_proposal::BlockProposal;
use mining::mining_state::MiningState;
use networking_state::NetworkingState;
use num_traits::Zero;
use nyks_consensus::block::block_header::BlockHeader;
use nyks_consensus::block::block_header::BlockHeaderWithBlockHashWitness;
use nyks_consensus::block::block_height::BlockHeight;
use nyks_consensus::block::difficulty_control::ProofOfWork;
use nyks_consensus::block::Block;
use nyks_consensus::consensus_rule_set::ConsensusRuleSet;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::transaction::transaction_kernel::TransactionKernel;
use nyks_consensus::transaction::transaction_kernel_id::TransactionKernelId;
use nyks_consensus::transaction::Transaction;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_database::storage::storage_schema::traits::StorageWriter as SW;
use nyks_database::storage::storage_vec::traits::*;
use nyks_locks::tokio as sync_tokio;
use nyks_locks::tokio::AtomicRwReadGuard;
use nyks_locks::tokio::AtomicRwWriteGuard;
use nyks_p2p::peer::handshake_data::HandshakeData;
use nyks_p2p::peer::handshake_data::VersionString;
use nyks_p2p::peer::peer_info::PeerInfo;
use nyks_p2p::peer::transfer_block::TransferBlock;
use nyks_p2p::peer::SyncChallenge;
use nyks_p2p::peer::SyncChallengeResponse;
use nyks_p2p::peer::SYNC_CHALLENGE_POW_WITNESS_LENGTH;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::application::config::cli_args;
use crate::application::config::data_directory::DataDirectory;
use crate::state::mining::block_proposal::BlockProposalRejectError;
use crate::ArchivalState;
use crate::RPCServerToMain;
use crate::VERSION;

/// `GlobalStateLock` holds a
/// [`tokio::AtomicRw`](crate::application::locks::tokio::AtomicRw)
/// ([`RwLock`](tokio::sync::RwLock)) over [`GlobalState`].
///
/// Conceptually** all reads and writes of application state
/// require acquiring this lock.
///
/// Having a single lock is useful for a few reasons:
///  1. Enables write serialization over all application state.
///     (blockchain, mempool, wallet, global flags)
///  2. Readers see a consistent view of data.
///  3. makes it easy to reason about locking.
///  4. simplifies the codebase.
///
/// The primary drawback is that long write operations can
/// block readers.  As such, every effort should be made to keep
/// write operations as short as possible, though
/// correctness/atomicity have first priority.
///
/// Using an `RwLock` is beneficial for concurrency vs using a `Mutex`.
/// Readers do not block eachother.  Only a writer blocks readers.
/// See [`RwLock`](std::sync::RwLock) docs for details.
///
/// ** unless some type uses interior mutability.  We have made
/// efforts to eradicate interior mutability in this crate.
///
/// Usage conventions:
///
/// ```text
///
/// // property naming:
/// struct Foo {
///     global_state_lock: GlobalStateLock
/// }
///
/// // read guard naming:
/// let global_state = foo.global_state_lock.lock_guard().await;
///
/// // write guard naming:
/// let global_state_mut = foo.global_state_lock.lock_guard_mut().await;
/// ```
///
/// These conventions make it easy to distinguish read access from write
/// access when reading and reviewing code.
///
/// When using a read-guard or write-guard, always drop it as soon as possible.
/// Failure to do so can result in poor concurrency or deadlock.
///
/// Deadlocks are generally not hard to track down.  Lock events are traced.
/// The app log records each `TryAcquire`, `Acquire` and `Release` event
/// when run with `RUST_LOG='info,neptune_cash=trace'`.
///
/// If a deadlock has occurred, the log will end with a `TryAcquire` event
/// (read or write) and just scroll up to find the previous `Acquire` for
/// write event to see which thread is holding the lock.
#[derive(Debug, Clone)]
pub struct GlobalStateLock {
    global_state_lock: sync_tokio::AtomicRw<GlobalState>,

    /// The `cli_args::Args` are read-only and accessible by all tasks/threads.
    cli: cli_args::Args,

    // holding this sender here enables it be used by the tx_initiator rust API
    // for broadcasting Tx as well as the RPC API.
    // (we might consider renaming the channel.)
    rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,

    /// A cache for the synchronous handshake getter, used as a fallback when
    /// syncly acquiring the read lock on `global_state_lock` fails.
    handshake_cache: Arc<std::sync::RwLock<HandshakeData>>,
}

impl GlobalStateLock {
    pub(crate) fn from_global_state(
        global_state: GlobalState,
        rpc_server_to_main_tx: tokio::sync::mpsc::Sender<RPCServerToMain>,
    ) -> Self {
        let cli = global_state.cli.clone();
        let initial_handshake_cache = global_state.get_own_handshakedata();
        let handshake_cache = Arc::new(std::sync::RwLock::new(initial_handshake_cache));
        let global_state_lock = sync_tokio::AtomicRw::from((
            global_state,
            Some("GlobalState"),
            Some(crate::LOG_TOKIO_LOCK_EVENT_CB),
        ));

        Self {
            global_state_lock,
            cli,
            rpc_server_to_main_tx,
            handshake_cache,
        }
    }

    /// Fetches handshake data synchronously.
    ///
    /// Tries to update the cache from the async mutex via `try_lock`. If
    /// successful, update the cache. If busy, returns the cached version
    /// immediately.
    ///
    /// This function is for obtaining the node's
    /// [`HandshakeData`](nyks_p2p::peer::handshake_data) without
    /// immediately (*i.e.*, without blocking) in a synchronous environment.
    /// In other cases, call [`GlobalState::get_own_handshakedata`] instead.
    pub(crate) fn get_own_handshakedata_sync(&self) -> HandshakeData {
        // Happy path: we obtain the read lock on global state.
        if let Ok(global_state) = self.global_state_lock.try_lock_guard() {
            let mut handshake_data = global_state.get_own_handshakedata();

            // Update the cache.
            // Note about concurrency: `write()` only blocks if another thread
            // is currently writing (which should be rare).
            if let Ok(mut cache) = self.handshake_cache.write() {
                *cache = handshake_data;
            }

            handshake_data.timestamp = SystemTime::now();
            return handshake_data;
        }

        // Fallback: Read from cache.
        // Note about concurrency: `read()` allows multiple concurrent readers.
        // However, `read()` blocks if the write lock is currently being held.
        // Besides being rare, this event implies that some other thread also
        // executing `get_own_handshakedata_sync` simultaneously *did* manage to
        // get the `global_state` read lock. Doubly rare. In this event, the
        // lock is released (and `read()` allowed to continue) as soon as the
        // new `handshake_data` is stored in the cache -- a matter of
        // microseconds at most.
        let mut handshake_data = *self.handshake_cache.read().expect("Lock poisoned");

        handshake_data.timestamp = SystemTime::now();
        handshake_data
    }

    // flush databases (persist to disk)
    pub async fn flush_databases(&mut self) -> Result<()> {
        self.lock_guard_mut().await.flush_databases().await
    }

    /// store a block (non coinbase)
    pub async fn set_new_tip(&mut self, new_block: Block) -> Result<()> {
        self.lock_guard_mut().await.set_new_tip(new_block).await
    }

    /// Return the read-only arguments set at startup.
    #[inline]
    pub fn cli(&self) -> &cli_args::Args {
        &self.cli
    }

    /// retrieve sender for channel from RPC to main loop
    ///
    /// note that the tx_initiator API now uses this sender also.
    pub(crate) fn rpc_server_to_main_tx(&self) -> tokio::sync::mpsc::Sender<RPCServerToMain> {
        self.rpc_server_to_main_tx.clone()
    }

    /// Test helper function for fine control of CLI parameters.
    #[cfg(test)]
    pub async fn set_cli(&mut self, cli: cli_args::Args) {
        self.lock_guard_mut().await.cli = cli.clone();
        self.cli = cli;
    }
}

impl Deref for GlobalStateLock {
    type Target = sync_tokio::AtomicRw<GlobalState>;

    fn deref(&self) -> &Self::Target {
        &self.global_state_lock
    }
}

impl DerefMut for GlobalStateLock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.global_state_lock
    }
}

/// abstracts over lock acquisition types for [GlobalStateLock]
///
/// this enables methods to be written that can accept whatever
/// the caller has.
///
/// such generic methods can be called in series to share an already
/// acquired lock-guard, or to each acquire its own lock-guard
/// in the case of `Lock` variant.
#[derive(Debug)]
pub enum StateLock<'a> {
    /// holds an instance GlobalStateLock. can be used to
    Lock(Box<GlobalStateLock>),
    ReadGuard(AtomicRwReadGuard<'a, GlobalState>),
    WriteGuard(AtomicRwWriteGuard<'a, GlobalState>),
}

impl From<GlobalStateLock> for StateLock<'_> {
    fn from(g: GlobalStateLock) -> Self {
        Self::Lock(Box::new(g))
    }
}

impl From<&GlobalStateLock> for StateLock<'_> {
    fn from(g: &GlobalStateLock) -> Self {
        Self::Lock(Box::new(g.clone())) // cheap Arc clone.
    }
}

impl<'a> From<AtomicRwReadGuard<'a, GlobalState>> for StateLock<'a> {
    fn from(g: AtomicRwReadGuard<'a, GlobalState>) -> Self {
        Self::ReadGuard(g)
    }
}

impl<'a> From<AtomicRwWriteGuard<'a, GlobalState>> for StateLock<'a> {
    fn from(g: AtomicRwWriteGuard<'a, GlobalState>) -> Self {
        Self::WriteGuard(g)
    }
}

impl<'a> StateLock<'a> {
    /// instantiates a `StateLock::ReadGuard`
    pub async fn read_guard(gsl: &'a GlobalStateLock) -> Self {
        Self::ReadGuard(gsl.lock_guard().await)
    }

    /// instantiates a `StateLock::WriteGuard`
    pub async fn write_guard(gsl: &'a mut GlobalStateLock) -> Self {
        Self::WriteGuard(gsl.lock_guard_mut().await)
    }

    /// returns a `GlobalState` reference.
    ///
    /// panics: it is wrong-usage to call this method on a
    /// `Lock` variant, and a panic will occur if this happens.
    pub fn gs(&self) -> &GlobalState {
        match self {
            Self::ReadGuard(g) => g,
            Self::WriteGuard(g) => g,
            Self::Lock(_) => panic!("wrong usage: not a guard"),
        }
    }

    /// converts back into `GlobalStateLock`
    ///
    /// panics: it is wrong-usage to call this method on a
    /// variant other than `Lock`. A panic will occur if this happens.
    pub fn into_lock(self) -> GlobalStateLock {
        match self {
            Self::Lock(g) => *g,
            _ => panic!("wrong usage: not a lock"),
        }
    }

    /// converts back into `AtomicRwReadGuard`
    ///
    /// panics: it is wrong-usage to call this method on a
    /// variant other than `ReadGuard`. A panic will occur if this happens.
    pub fn into_read_guard(self) -> AtomicRwReadGuard<'a, GlobalState> {
        match self {
            Self::ReadGuard(g) => g,
            _ => panic!("wrong usage: not a read guard"),
        }
    }

    /// converts back into `AtomicRwWriteGuard`
    ///
    /// panics: it is wrong-usage to call this method on a
    /// variant other than `WriteGuard`. A panic will occur if this happens.
    pub fn into_write_guard(self) -> AtomicRwWriteGuard<'a, GlobalState> {
        match self {
            Self::WriteGuard(g) => g,
            _ => panic!("wrong usage: not a write guard"),
        }
    }

    /// returns present blockchain tip info.
    pub async fn tip(&self) -> Block {
        match self {
            Self::Lock(gsl) => gsl.lock_guard().await.chain.tip().to_owned(),
            Self::WriteGuard(gsm) => gsm.chain.tip().to_owned(),
            Self::ReadGuard(gs) => gs.chain.tip().to_owned(),
        }
    }

    pub fn cli(&self) -> &cli_args::Args {
        match self {
            Self::Lock(gsl) => gsl.cli(),
            Self::WriteGuard(gsm) => gsm.cli(),
            Self::ReadGuard(gs) => gs.cli(),
        }
    }

    pub async fn with<F, R, Args>(&self, func: F, args: Args) -> R
    where
        F: FnOnce(&GlobalState, Args) -> R,
    {
        match self {
            StateLock::Lock(gsl) => {
                let gs = gsl.lock_guard().await;
                func(&gs, args)
            }
            StateLock::ReadGuard(guard) => func(guard, args),
            StateLock::WriteGuard(guard) => func(guard, args),
        }
    }

    pub async fn with_mut<F, R, Args>(&mut self, func: F, args: Args) -> R
    where
        F: FnOnce(&mut GlobalState, Args) -> R,
    {
        match self {
            StateLock::Lock(gsl) => {
                let mut gsm = gsl.lock_guard_mut().await;
                func(&mut gsm, args)
            }
            StateLock::WriteGuard(guard) => func(&mut *guard, args),
            StateLock::ReadGuard(_) => {
                panic!("with_mut can only be used on Lock or WriteGuard variants.")
            }
        }
    }

    // for calling async callbacks, see macros:
    //  state_lock_call_async
    //  state_lock_call_mut_async
}

/// `GlobalState` handles all state of a Neptune node that is shared across its tasks.
///
/// Some fields are only written to by certain tasks.
#[derive(Debug)]
pub struct GlobalState {
    /// The `BlockchainState` may only be updated by the main task.
    pub chain: BlockchainState,

    /// The `NetworkingState` may be updated by both the main task, peer tasks,
    /// and RPC server.
    pub net: NetworkingState,

    /// The `cli_args::Args` are read-only and accessible by all tasks.
    cli: cli_args::Args,

    /// The `Mempool` may only be updated by the main task.
    pub mempool: Mempool,

    /// The `mining_state` can be updated by main task, mining task, or RPC server.
    pub mining_state: MiningState,
}

impl Drop for GlobalState {
    fn drop(&mut self) {
        tracing::debug!("spawning flush db thread");
        std::thread::scope(|s| {
            s.spawn(|| {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    tracing::info!("GlobalState is dropping. flushing database");
                    self.flush_databases().await
                })
                .unwrap();
            });
        });
    }
}

impl GlobalState {
    /// Create a new global state object.
    pub async fn try_new(
        data_directory: DataDirectory,
        genesis: Block,
        cli: cli_args::Args,
    ) -> Result<Self> {
        let archival_state = ArchivalState::new(data_directory.clone(), genesis, &cli).await;
        debug!("Got archival state");

        // Get latest block. Use hardcoded genesis block if nothing is in database.
        let latest_block: Block = archival_state.get_tip().await;

        let peer_map: HashMap<_, PeerInfo> = HashMap::new();
        let peer_databases = NetworkingState::initialize_peer_databases(&data_directory).await?;
        debug!("Got peer databases");

        let net = NetworkingState::new(peer_map, peer_databases);

        let light_state: LightState = LightState::new(latest_block);
        let chain = BlockchainArchivalState {
            light_state,
            archival_state,
        };
        let chain = BlockchainState::Archival(Box::new(chain));
        let mempool = Mempool::new(cli.max_mempool_size, chain.tip());

        Ok(Self::new(chain, net, cli, mempool))
    }

    pub fn new(
        chain: BlockchainState,
        net: NetworkingState,
        cli: cli_args::Args,
        mempool: Mempool,
    ) -> Self {
        Self {
            chain,
            net,
            cli,
            mempool,
            mining_state: MiningState::default(),
        }
    }

    /// Return the [`ConsensusRuleSet`] that applies for current tip.
    pub(crate) fn consensus_rule_set(&self) -> ConsensusRuleSet {
        let tip_height = self.chain.tip_height();
        ConsensusRuleSet::infer_from(self.cli().network, tip_height)
    }

    /// Determine whether the conditions are met to enter into sync mode.
    ///
    /// Specifically, compute a boolean value based on
    ///  - whether the foreign cumulative proof-of-work exceeds that of our own;
    ///  - whether the foreign block has a bigger block height and the height
    ///    difference exceeds the threshold set by the CLI.
    ///
    /// The main loop relies on this criterion to decide whether to enter sync
    /// mode. If the main loop activates sync mode, it affects the entire
    /// application.
    pub(crate) fn sync_mode_threshold_stateless(
        own_block_tip_header: &BlockHeader,
        claimed_height: BlockHeight,
        claimed_cumulative_pow: ProofOfWork,
        sync_mode_threshold: usize,
    ) -> bool {
        own_block_tip_header.cumulative_proof_of_work < claimed_cumulative_pow
            && claimed_height - own_block_tip_header.height > sync_mode_threshold as i128
    }

    /// Determine whether the conditions are met to enter into sync mode.
    ///
    /// Specifically, compute a boolean value based on
    ///  - whether the foreign cumulative proof-of-work exceeds that of our own;
    ///  - whether the foreign block has a bigger block height and the height
    ///    difference exceeds the threshold set by the CLI.
    ///
    /// The main loop relies on this criterion to decide whether to enter sync
    /// mode. If the main loop activates sync mode, it affects the entire
    /// application.
    pub(crate) fn sync_mode_criterion(
        &self,
        claimed_max_height: BlockHeight,
        claimed_cumulative_pow: ProofOfWork,
    ) -> bool {
        let own_block_tip_header = self.chain.tip().header();
        Self::sync_mode_threshold_stateless(
            own_block_tip_header,
            claimed_max_height,
            claimed_cumulative_pow,
            self.cli().sync_mode_threshold,
        )
    }

    /// Returns true iff the incoming block proposal is more favorable than the
    /// one we're currently working on. Returns false if peer is either not
    /// whitelisted, or if all foreign block proposals should be rejected.
    ///
    /// Favor [`Self::favor_incoming_block_proposal`] whenever the digests are
    /// available, as this function can return false positives in case of a
    /// reorganization.
    pub(crate) fn favor_incoming_block_proposal_legacy(
        &self,
        incoming_block_height: BlockHeight,
        incoming_guesser_fee: NativeCurrencyAmount,
    ) -> Result<(), BlockProposalRejectError> {
        let expected_height = self.chain.tip().header().height.next();
        if incoming_block_height != expected_height {
            return Err(BlockProposalRejectError::WrongHeight {
                received: incoming_block_height,
                expected: expected_height,
            });
        }

        if self.mining_state.block_proposal.has_own() {
            return Err(BlockProposalRejectError::HasOwnBlockProposal);
        }

        let maybe_existing_fee = self.mining_state.block_proposal.map(|x| {
            x.body()
                .total_guesser_reward()
                .expect("block in state must be valid")
        });
        if maybe_existing_fee.is_some_and(|current| current >= incoming_guesser_fee)
            || incoming_guesser_fee.is_zero()
        {
            Err(BlockProposalRejectError::InsufficientFee {
                current: maybe_existing_fee,
                received: incoming_guesser_fee,
            })
        } else {
            Ok(())
        }
    }

    /// Returns true if the incoming block proposal is more favorable than the
    /// one we're currently working on. Returns false if block proposal does not
    /// have expected parent.
    pub(crate) fn favor_incoming_block_proposal(
        &self,
        incoming_proposal_prev_block_digest: Digest,
        incoming_guesser_fee: NativeCurrencyAmount,
    ) -> Result<(), BlockProposalRejectError> {
        let current_tip_digest = self.chain.tip().hash();
        if incoming_proposal_prev_block_digest != current_tip_digest {
            return Err(BlockProposalRejectError::WrongParent {
                received: incoming_proposal_prev_block_digest,
                expected: current_tip_digest,
            });
        }

        if self.mining_state.block_proposal.has_own() {
            return Err(BlockProposalRejectError::HasOwnBlockProposal);
        }

        let maybe_existing_fee = self.mining_state.block_proposal.map(|x| {
            x.body()
                .total_guesser_reward()
                .expect("block in state must be valid")
        });
        if maybe_existing_fee.is_some_and(|current| current >= incoming_guesser_fee)
            || incoming_guesser_fee.is_zero()
        {
            Err(BlockProposalRejectError::InsufficientFee {
                current: maybe_existing_fee,
                received: incoming_guesser_fee,
            })
        } else {
            Ok(())
        }
    }

    /// Determine whether the incoming block is more canonical than the current
    /// tip, *i.e.*, wins the fork choice rule.
    ///
    /// If the incoming block equals the current tip, this function returns
    /// false.
    pub fn incoming_block_is_more_canonical(&self, incoming_block: &Block) -> bool {
        let winner = Block::fork_choice_rule(self.chain.tip(), incoming_block);
        winner.hash() != self.chain.tip().hash()
    }

    pub(crate) fn get_own_handshakedata(&self) -> HandshakeData {
        HandshakeData {
            tip_header: *self.chain.tip().header(),
            network: self.cli().network,
            instance_id: self.net.instance_id,
            version: VersionString::new_from_str(VERSION),
            // For now, all nodes are archival nodes
            is_archival_node: self.chain.is_archival_node(),
            is_bootstrapper_node: self.cli().bootstrap,
            timestamp: SystemTime::now(),
            extra_data: Default::default(),
        }
    }

    pub async fn flush_databases(&mut self) -> Result<()> {
        // flush block_index database
        self.chain.archival_state_mut().block_index_db.flush().await;

        // persist archival_mutator_set, with sync label
        let hash = self.chain.archival_state().get_tip().await.hash();
        self.chain
            .archival_state_mut()
            .archival_mutator_set
            .set_sync_label(hash)
            .await;

        self.chain
            .archival_state_mut()
            .archival_mutator_set
            .persist()
            .await;

        self.chain
            .archival_state_mut()
            .archival_block_mmr
            .persist()
            .await;

        // flush peer_standings
        self.net.peer_databases.peer_standings_by_ip.flush().await;

        debug!("Flushed all databases");

        Ok(())
    }

    /// Set the current tip to a stored block, identified by block hash.
    ///
    /// Assumes the block was stored (or is the genesis block), and if it is
    /// not canonical that there is a connecting path. Assumes furthermore that
    /// the node is archival. If any of these assumptions are not met then this
    /// function returns an error.
    ///
    /// # Panics
    ///
    /// - If the stored block is found but does not have a mutator set update.
    pub(crate) async fn set_tip_to_stored_block(&mut self, block_digest: Digest) -> Result<()> {
        ensure!(
            self.chain.is_archival_node(),
            "node must be archival in order to set tip to stored block"
        );

        // Read the block.
        let block = self
            .chain
            .archival_state()
            .get_block(block_digest)
            .await?
            .ok_or(anyhow::Error::msg(format!("unknown block {block_digest}")))?;

        self.set_new_tip_internal(block).await?;

        Ok(())
    }

    /// Update client's state with a new block.
    ///
    /// The new block is assumed to be valid, also wrt. to proof-of-work.
    /// The new block will be set as the new tip, regardless of its
    /// cumulative proof-of-work number.
    ///
    /// Returns a list of update-jobs that should be
    /// performed by this client.
    pub async fn set_new_tip(&mut self, new_block: Block) -> Result<()> {
        self.set_new_tip_internal(new_block).await
    }

    /// Store a block to client's state *without* marking this block as a new
    /// tip. No validation of block happens, as this is the caller's
    /// responsibility.
    pub(crate) async fn store_block_not_tip(&mut self, block: Block) -> Result<()> {
        crate::macros::log_scope_duration!();

        self.chain
            .archival_state_mut()
            .write_block_not_tip(&block)
            .await?;

        // Mempool is not updated, as it's only defined relative to the tip.
        // Wallet is not updated, as it can be synced to tip at any point.

        Ok(())
    }

    /// Update client's state with a new block. Block is assumed to be valid,
    /// also wrt. to PoW. The received block will be set as the new tip,
    /// regardless of its accumulated PoW. or its validity.
    ///
    /// May also be used to set the tip back to any earlier block, including the
    /// genesis block. However, a path from the current tip to the new tip must
    /// be known.
    ///
    /// # Panics
    ///
    /// - If the new tip does not have a mutator set update.
    async fn set_new_tip_internal(&mut self, new_tip: Block) -> Result<()> {
        crate::macros::log_scope_duration!();

        debug!("Applying block to archival state.");
        self.chain
            .archival_state_mut()
            .set_new_tip(&new_tip)
            .await?;

        debug!("Getting parent MSA.");
        let parent_ms_accumulator =
            if new_tip.header().prev_block_digest == self.chain.light_state().tip().hash() {
                // Avoid loading parent block from disk if we don't have to.
                Some(self.chain.light_state().tip_mutator_set_after())
            } else {
                self.chain
                    .archival_state()
                    .get_tip_parent()
                    .await
                    .map(|parent| {
                        parent
                            .mutator_set_accumulator_after()
                            .expect("block from archival state must have mutator set after")
                    })
            };

        debug!("Updating light state.");
        self.chain.light_state_mut().update(new_tip);
        let tip: &Block = self.chain.tip();

        // Update mempool with UTXOs from this block. This is done by
        // removing all transaction that became invalid/was mined by this
        // block. Also returns the list of update-jobs that should be
        // performed by this client.
        debug!("Applying block to mempool.");
        let _mempool_events = self.mempool.update_with_block(tip)?;

        // Sanity check: If no parent is known, new block must be the genesis
        // block.
        if parent_ms_accumulator.is_none() {
            assert_eq!(
                self.chain.archival_state().genesis_block().hash(),
                tip.hash(),
                "If no parent is known, new tip must be the genesis block"
            );
        }

        // Reset block proposal, as that field pertains to the block that
        // was just set as new tip. Also reset set of exported block proposals.
        self.mining_state.block_proposal = BlockProposal::none();
        self.mining_state.exported_block_proposals.clear();

        debug!("Done setting new tip.");
        Ok(())
    }

    pub(crate) async fn response_to_sync_challenge(
        &self,
        sync_challenge: SyncChallenge,
    ) -> Result<SyncChallengeResponse> {
        async fn fetch_block_pair(
            state: &GlobalState,
            child_digest: Digest,
        ) -> Option<(Block, Block)> {
            let child = state
                .chain
                .archival_state()
                .get_block(child_digest)
                .await
                .expect("fetching block from archival state should work.");
            let Some(child) = child else {
                warn!("Got sync challenge for unknown tip");

                return None;
            };
            if child.header().height < 2.into() {
                warn!("Got sync challenge for tip of too low height; cannot send genesis block");

                return None;
            }

            let parent_digest = child.header().prev_block_digest;
            let parent = state
                .chain
                .archival_state()
                .get_block(parent_digest)
                .await
                .expect("fetching block from archival state should work.")
                .expect(
                    "parent of known block from archival state must exist, if height exceeds 1.",
                );

            Some((parent, child))
        }

        let Some((tip_parent, tip)) = fetch_block_pair(self, sync_challenge.tip_digest).await
        else {
            bail!("could not fetch tip and tip predecessor");
        };

        let tip_height = tip.header().height;
        ensure!(
            tip_height >= (SYNC_CHALLENGE_POW_WITNESS_LENGTH as u64).into(),
            "tip height {tip_height} is too small for sync mode",
        );

        let mut block_pairs: Vec<(TransferBlock, TransferBlock)> = vec![];
        let mut block_mmr_mps = vec![];
        for child_height in sync_challenge.challenges {
            ensure!(
                child_height >= 2u64.into(),
                "challenge asks for genesis block",
            );
            ensure!(
                child_height < tip.header().height,
                "challenge asks for height that's not ancestor to tip.",
            );

            let Some(child_digest) = self
                .chain
                .archival_state()
                .archival_block_mmr
                .ammr()
                .try_get_leaf(child_height.into())
                .await
            else {
                bail!("could not get leaf from archival block mmr");
            };
            let Some((p, c)) = fetch_block_pair(self, child_digest).await else {
                bail!("could not fetch indicated block pair");
            };

            // Notice that the MMR membership proofs are relative to an MMR
            // where the tip digest *has* been added. So it is not relative to
            // the block MMR accumulator present in the tip block, as it only
            // refers to its ancestors. Rather, it's relative to the block MMR
            // accumulator present in the tip's child.
            block_mmr_mps.push(
                self.chain
                    .archival_state()
                    .archival_block_mmr
                    .ammr()
                    .prove_membership_relative_to_smaller_mmr(
                        child_height.into(),
                        tip_height.next().into(),
                    )
                    .await,
            );
            block_pairs.push((
                p.try_into()
                    .expect("blocks from archive must be transferable"),
                c.try_into()
                    .expect("blocks from archive must be transferable"),
            ));
        }

        let mut pow_witnesses: Vec<BlockHeaderWithBlockHashWitness> = vec![];
        let mut block_hash = tip.hash();
        while pow_witnesses.len() < SYNC_CHALLENGE_POW_WITNESS_LENGTH {
            let pow_witness = self
                .chain
                .archival_state()
                .block_header_with_hash_witness(block_hash)
                .await
                .unwrap_or_else(|| {
                    panic!("Pow-witness for block with hash {block_hash} must exist")
                });
            block_hash = pow_witness.header.prev_block_digest;
            pow_witnesses.push(pow_witness);
        }

        let response = SyncChallengeResponse {
            tip: tip
                .try_into()
                .expect("All blocks from archival state should be transferable."),
            tip_parent: tip_parent
                .try_into()
                .expect("All blocks from archival state should be transferable."),
            blocks: block_pairs.try_into().unwrap(),
            membership_proofs: block_mmr_mps.try_into().unwrap(),
            pow_witnesses: pow_witnesses.try_into().unwrap(),
        };

        Ok(response)
    }

    #[inline]
    pub fn cli(&self) -> &cli_args::Args {
        &self.cli
    }

    /// Remove one transaction from the mempool and notify wallet of changes.
    pub(crate) async fn mempool_remove(&mut self, transaction_id: TransactionKernelId) {
        let _events = self.mempool.remove(transaction_id);
        // TODO(KaffinPX): remove mempool events or keep it for potential usage on subscription context over RPC
    }

    /// clears all Tx from mempool and notifies wallet of changes.
    pub async fn mempool_clear(&mut self) {
        let _events = self.mempool.clear();
    }

    /// adds Tx to mempool and notifies wallet of change. value represents
    /// the value that the transaction has to caller.
    pub async fn mempool_insert(&mut self, transaction: Transaction) {
        let _events = self.mempool.insert(transaction);
    }

    /// prunes stale tx in mempool and notifies wallet of changes.
    pub async fn mempool_prune_stale_transactions(&mut self) {
        let _events = self.mempool.prune_stale_transactions();
    }

    /// Read all blocks contained in the specified directory and store these to
    /// the archival state.
    ///
    /// Will ignore blocks that are already known to this node but logs a
    /// warning when such blocks are encountered. Will return an error if any
    /// processed block is either invalid or does not have sufficient PoW, iff
    /// block validation is specified.
    ///
    /// Can be used to bootstrap the node without having to download all blocks
    /// from a peer. Assumes the same file structure as is created in the
    /// directory of blocks under normal operations of the node software, i.e.
    /// where blocks are mined locally or received from peers.
    ///
    /// Returns the number of blocks read from the directory.
    pub async fn import_blocks_from_directory(
        &mut self,
        directory: &Path,
        flush_period: usize,
        validate_blocks: bool,
    ) -> Result<usize> {
        debug!(
            "Reading all blocks from directory '{}'",
            directory.to_string_lossy()
        );
        let block_file_paths = ArchivalState::read_block_file_names_from_directory(directory)?;
        let mut num_stored_blocks = 0;
        let mut predecessor = self.chain.tip().clone();
        let network = self.cli.network;

        for block_file_path in block_file_paths {
            let blocks = ArchivalState::blocks_from_file_without_record(&block_file_path).await?;

            // Blocks are assumed to be stored in-order in the file.
            for block in blocks {
                let block_height = block.header().height;

                let block_is_new = self
                    .chain
                    .archival_state()
                    .get_block_header(block.hash())
                    .await
                    .is_none();
                if !block_is_new {
                    warn!(
                        "Attempted to process a block from {} \
                        which was already known. Block height: {block_height}.",
                        block_file_path.to_string_lossy()
                    );
                    continue;
                }

                if validate_blocks {
                    let prev_block_digest = block.header().prev_block_digest;

                    // Ensure we have the right predecessor, in case block data
                    // contains reorganizations.
                    let predecessor = if prev_block_digest == predecessor.hash() {
                        predecessor.clone()
                    } else {
                        match self
                            .chain
                            .archival_state()
                            .get_block(prev_block_digest)
                            .await?
                        {
                            Some(pred) => pred,
                            None => {
                                bail!("Failed to find parent of block of height {block_height}");
                            }
                        }
                    };

                    let validity = block
                        .validate(&predecessor, Timestamp::now(), network)
                        .await;

                    if let Err(error) = validity {
                        bail!(
                            "Attempted to process a block from {} \
                        which is invalid. Block height: {block_height}. Error: {error}",
                            block_file_path.to_string_lossy()
                        );
                    }
                    ensure!(
                        block.has_proof_of_work(network, predecessor.header()),
                        "Attempted to process a block from {} \
                        which does not have required PoW amount. \
                        Block height: {block_height}.",
                        block_file_path.to_string_lossy()
                    );
                }

                self.set_new_tip_internal(block.clone()).await.unwrap();
                info!("Updated state with block of height {block_height}.");
                num_stored_blocks += 1;
                predecessor = block;

                if flush_period != 0 && num_stored_blocks % flush_period == 0 {
                    self.flush_databases().await?;
                    info!("Flushed databases after {num_stored_blocks} blocks.");
                }
            }
        }

        self.flush_databases().await?;

        Ok(num_stored_blocks)
    }
}
