use futures::channel::oneshot;
use libp2p::Multiaddr;
use nyks_protocol::consensus::block::Block;
use nyks_protocol::consensus::transaction::Transaction;
use tasm_lib::triton_vm::prelude::Digest;

use crate::application::network::overview::NetworkOverview;

/// represents messages that can be sent from RPC server to main loop.
#[derive(Debug, strum::Display)]
pub(crate) enum RPCServerToMain {
    BroadcastMempoolTransactions,
    BroadcastBlockProposal,
    ClearMempool,
    ProofOfWorkSolution(Box<Block>),
    Shutdown,
    SetTipToStoredBlock(Digest),

    // Used by JSON-RPC
    BlockProposal(Box<Block>),
    BroadcastTx(Box<Transaction>),
    Ban(Multiaddr),
    Unban(Multiaddr),
    UnbanAll,
    Dial(Multiaddr),
    ProbeNat,
    ResetRelayReservations,
    GetNetworkOverview(tokio::sync::oneshot::Sender<NetworkOverview>),
}

pub trait Cancelable: Send + Sync {
    fn is_canceled(&self) -> bool;
}

impl<T: Send + Sync> Cancelable for oneshot::Sender<T> {
    fn is_canceled(&self) -> bool {
        self.is_canceled()
    }
}
