use nyks_consensus::transaction::transaction_kernel_id::TransactionKernelId;
use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::key::KeyType;

use crate::state::utxos::MonitoredUtxo;
use crate::state::utxos::UtxoKey;

/// Events emitted by the wallet as a result of sync and scan activity.
#[derive(Debug, Clone)]
pub enum WalletEvent {
    /// A new UTXO was discovered and added to the wallet's UTXO pool.
    UtxoReceived { key: UtxoKey, utxo: MonitoredUtxo },

    /// A previously-tracked UTXO was found to be spent (or otherwise
    /// invalid) while syncing membership proofs, and was evicted from the
    /// pool.
    UtxoInvalidated { key: UtxoKey, utxo: MonitoredUtxo },

    /// A mempool transaction was found to spend one or more of the
    /// wallet's UTXOs. Emitted once per transaction, the first time it's
    /// observed as relevant.
    UtxosOutgoing {
        id: TransactionKernelId,
        utxos: Vec<UtxoKey>,
    },

    /// A new address was derived by the wallet.
    AddressGenerated {
        key_type: KeyType,
        index: u64,
        address: Address,
    },
}

impl WalletEvent {
    pub fn utxo_received(key: UtxoKey, utxo: MonitoredUtxo) -> Self {
        WalletEvent::UtxoReceived { key, utxo }
    }

    pub fn utxo_invalidated(key: UtxoKey, utxo: MonitoredUtxo) -> Self {
        WalletEvent::UtxoInvalidated { key, utxo }
    }

    pub fn utxos_outgoing(id: TransactionKernelId, utxos: Vec<UtxoKey>) -> Self {
        WalletEvent::UtxosOutgoing { id, utxos }
    }
}
