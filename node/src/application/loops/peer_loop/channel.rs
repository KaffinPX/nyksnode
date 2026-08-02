use libp2p::Multiaddr;
use libp2p::PeerId;
use nyks_p2p::peer::peer_block_notifications::BlockProposalNotification;
use nyks_p2p::peer::synchronization_bit_mask::SynchronizationBitMask;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use nyks_consensus::block::block_height::BlockHeight;
use nyks_consensus::block::difficulty_control::ProofOfWork;
use nyks_consensus::block::Block;
use nyks_consensus::transaction::Transaction;
use nyks_p2p::peer::transaction_notification::TransactionNotification;

#[derive(Clone, Debug, strum::Display)]
pub(crate) enum MainToPeerTask {
    Block(Box<Block>),
    BlockProposalNotification(BlockProposalNotification),
    RequestBlockByHeight {
        target_peer: PeerId,
        height: BlockHeight,
    },
    RequestBlockNotification,

    /// sanction a peer for failing to respond to sync request
    PeerSynchronizationTimeout(PeerId),

    /// Publish knowledge of a transaction
    TransactionNotification(TransactionNotification),

    /// Disconnect from a specific peer
    Disconnect(PeerId),

    /// Disconnect from all peers
    DisconnectAll(),

    /// Informs the peer which blocks we have while syncing.
    SyncCoverage {
        coverage: SynchronizationBitMask,
        peer_handle: PeerId,
    },

    /// Sends a syncing peer a block we have downloaded already but not
    /// processed.
    SyncBlock {
        block: Box<Block>,
        peer_handle: PeerId,
    },
}

impl MainToPeerTask {
    pub fn get_type(&self) -> String {
        match self {
            MainToPeerTask::Block(_) => "block",
            MainToPeerTask::RequestBlockByHeight { .. } => "req block by height",
            MainToPeerTask::PeerSynchronizationTimeout(_) => "peer sync timeout",
            MainToPeerTask::TransactionNotification(_) => "transaction notification",
            MainToPeerTask::Disconnect(_) => "disconnect",
            MainToPeerTask::DisconnectAll() => "disconnect all",
            MainToPeerTask::BlockProposalNotification(_) => "block proposal notification",
            MainToPeerTask::RequestBlockNotification => "request for block notification",
            MainToPeerTask::SyncCoverage { .. } => "sync coverage",
            MainToPeerTask::SyncBlock { .. } => "sync block",
        }
        .to_string()
    }

    /// Function to filter out messages that should be ignored when all state
    /// updates have been paused.
    pub(crate) fn ignore_on_freeze(&self) -> bool {
        match self {
            MainToPeerTask::Block(_) => true,
            MainToPeerTask::BlockProposalNotification(_) => true,
            MainToPeerTask::RequestBlockByHeight { .. } => true,
            MainToPeerTask::PeerSynchronizationTimeout(_) => true,
            MainToPeerTask::TransactionNotification(_) => true,
            MainToPeerTask::Disconnect(_) => false,
            MainToPeerTask::DisconnectAll() => false,
            MainToPeerTask::RequestBlockNotification => false,
            MainToPeerTask::SyncCoverage { .. } => true,
            MainToPeerTask::SyncBlock { .. } => true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, strum::Display)]
pub(crate) enum PeerTaskToMain {
    NewBlocks(Vec<Block>),
    AddPeerMaxBlockHeight {
        peer_id: PeerId,
        peer_address: Multiaddr,
        claimed_height: BlockHeight,
        claimed_cumulative_pow: ProofOfWork,

        /// The MMR *after* adding the tip hash, so not the one contained in the
        /// tip, but in its child.
        claimed_block_mmra: MmrAccumulator,
        claimed_block_digest: Digest,
    },

    Transaction(Box<PeerTaskToMainTransaction>),
    BlockProposal(Box<Block>),
    DisconnectFromLongestLivedPeer,
    NewSyncTarget(Box<Block>),
    NewSyncBlock(Box<Block>, PeerId),
    NewPeer(PeerId),
    DroppedPeer(PeerId),
    SyncCoverage(SynchronizationBitMask, PeerId),
    PeerWantsSyncBlock(PeerId, BlockHeight),

    // Node wants to ban the peer. The legacy peer-to-peer stack already takes
    // care of this in the destructor of the peer loop. However, for the ban to
    // have effect at the libp2p network stack as well, this message must reach
    // there. So: send a message to the main loop to be relayed to the
    // NetworkActor.
    Ban(PeerId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerTaskToMainTransaction {
    pub transaction: Transaction,
    pub confirmable_for_block: Digest,
}

impl PeerTaskToMain {
    pub fn get_type(&self) -> String {
        match self {
            PeerTaskToMain::NewBlocks(_) => "new blocks",
            PeerTaskToMain::AddPeerMaxBlockHeight { .. } => "add peer max block height",
            PeerTaskToMain::Transaction(_) => "transaction",
            PeerTaskToMain::BlockProposal(_) => "block proposal",
            PeerTaskToMain::DisconnectFromLongestLivedPeer => "disconnect from longest lived peer",
            PeerTaskToMain::NewSyncTarget(_block) => "new sync target",
            PeerTaskToMain::NewSyncBlock(_block, _socket_addr) => "new sync block",
            PeerTaskToMain::NewPeer { .. } => "new peer",
            PeerTaskToMain::DroppedPeer(_) => "dropped peer",
            PeerTaskToMain::SyncCoverage(_, _) => "sync coverage",
            PeerTaskToMain::PeerWantsSyncBlock(_, _) => "peer wants sync block",
            PeerTaskToMain::Ban(_) => "node wants to ban a malicious peer",
        }
        .to_string()
    }
}
