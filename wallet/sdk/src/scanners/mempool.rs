use std::collections::HashMap;
use std::collections::HashSet;

use nyks_consensus::transaction::transaction_kernel_id::TransactionKernelId;
use nyks_rpc_client::block::transaction_kernel::RpcTransactionKernel;
use tracing::info;

use crate::state::utxos::index::UtxoIndex;

#[derive(Clone, Copy, PartialEq, Eq)]
enum TxStatus {
    Relevant,
    Unrelated,
}

/// Scans mempool transactions against the current UTXO pool.
pub struct MempoolScanner {
    index: UtxoIndex,
    // IDs we've already checked.
    cache: HashMap<TransactionKernelId, TxStatus>,
}

impl MempoolScanner {
    pub fn new(index: UtxoIndex) -> Self {
        MempoolScanner {
            index,
            cache: HashMap::new(),
        }
    }

    /// Returns IDs that need to be fetched.
    /// Unrelated transactions are skipped if already cached.
    pub async fn ids_to_fetch(
        &self,
        mempool_ids: &[TransactionKernelId],
    ) -> Vec<TransactionKernelId> {
        mempool_ids
            .iter()
            .filter(|id| match self.cache.get(id) {
                Some(TxStatus::Unrelated) => false,
                Some(TxStatus::Relevant) => true,
                None => true,
            })
            .cloned()
            .collect()
    }

    /// Checks the transactions and updates their status in the cache.
    pub async fn scan(&mut self, transactions: Vec<(TransactionKernelId, RpcTransactionKernel)>) {
        for (id, transaction) in &transactions {
            let mut relevant = false;

            for input in &transaction.inputs {
                if let Some(utxo_key) = self.index.get(&input.absolute_indices).await {
                    info!("{} is being spent on mempool", utxo_key.aocl_index);
                    relevant = true;
                }
            }

            self.cache.insert(
                *id,
                if relevant {
                    TxStatus::Relevant
                } else {
                    TxStatus::Unrelated
                },
            );
        }
    }

    /// Removes transactions that are no longer in the mempool.
    pub async fn evict_stale(&mut self, current_mempool_ids: Vec<TransactionKernelId>) {
        let current_mempool_ids: HashSet<_> = current_mempool_ids.into_iter().collect();
        self.cache.retain(|id, _| current_mempool_ids.contains(id));
    }
}
