use std::collections::HashMap;
use std::collections::HashSet;

use nyks_consensus::transaction::transaction_kernel_id::TransactionKernelId;
use nyks_rpc_client::block::transaction_kernel::RpcTransactionKernel;

use crate::state::utxos::UtxoKey;
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
    // UTXOs currently observed as spent by relevant mempool transactions.
    pub pending_spends: HashMap<UtxoKey, HashSet<TransactionKernelId>>, // Kept supporting multiple txs just in case
}

impl MempoolScanner {
    pub fn new(index: UtxoIndex) -> Self {
        MempoolScanner {
            index,
            cache: HashMap::new(),
            pending_spends: HashMap::new(),
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

    /// Returns true if the given UTXO is currently being spent by a
    /// transaction sitting in the mempool.
    pub fn is_pending_spend(&self, utxo_key: &UtxoKey) -> bool {
        self.pending_spends.contains_key(utxo_key)
    }

    /// Returns the UTXO keys currently observed as spent by a transaction
    /// sitting in the mempool.
    pub fn pending_spend_utxos(&self) -> impl Iterator<Item = &UtxoKey> + '_ {
        self.pending_spends.keys()
    }

    /// Checks the transactions and updates their status in the cache.
    pub async fn scan(&mut self, transactions: Vec<(TransactionKernelId, RpcTransactionKernel)>) {
        for (id, transaction) in &transactions {
            let mut relevant = false;

            for input in &transaction.inputs {
                if let Some(utxo_key) = self.index.get(&input.absolute_indices).await {
                    self.pending_spends.entry(utxo_key).or_default().insert(*id);
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

        // Drop stale tx ids from each UTXO's spender set, and drop the
        // UTXO entry entirely once no live tx is spending it anymore.
        self.pending_spends.retain(|_, spender_ids| {
            spender_ids.retain(|id| current_mempool_ids.contains(id));
            !spender_ids.is_empty()
        });
    }
}
