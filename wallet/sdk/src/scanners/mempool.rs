use std::collections::HashMap;
use std::collections::HashSet;

use nyks_consensus::transaction::transaction_kernel_id::TransactionKernelId;
use nyks_rpc_client::block::transaction_kernel::RpcTransactionKernel;

use crate::state::utxos::UtxoKey;
use crate::state::utxos::index::UtxoIndex;

/// Scans mempool transactions against the current UTXO pool.
pub struct MempoolScanner {
    index: UtxoIndex,
    // IDs we've already checked, relevant or not - never rescanned.
    checked_ids: HashSet<TransactionKernelId>,
    // UTXOs currently observed as spent by relevant mempool transactions.
    pub pending_spends: HashMap<UtxoKey, HashSet<TransactionKernelId>>, // Kept supporting multiple txs just in case
}

impl MempoolScanner {
    pub fn new(index: UtxoIndex) -> Self {
        MempoolScanner {
            index,
            checked_ids: HashSet::new(),
            pending_spends: HashMap::new(),
        }
    }

    /// Returns IDs that need to be fetched, i.e. ones we haven't checked yet.
    pub async fn ids_to_fetch(
        &self,
        mempool_ids: &[TransactionKernelId],
    ) -> Vec<TransactionKernelId> {
        mempool_ids
            .iter()
            .filter(|id| !self.checked_ids.contains(id))
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

    /// Checks the transactions and marks them as checked. Each transaction
    /// is scanned at most once ever; relevant ones are returned only here.
    pub async fn scan(
        &mut self,
        transactions: Vec<(TransactionKernelId, RpcTransactionKernel)>,
    ) -> Vec<(TransactionKernelId, Vec<UtxoKey>)> {
        let mut relevant_transactions = Vec::new();

        for (id, transaction) in &transactions {
            let mut spent_inputs = Vec::new();

            for input in &transaction.inputs {
                if let Some(utxo_key) = self.index.get(&input.absolute_indices).await {
                    self.pending_spends.entry(utxo_key).or_default().insert(*id);
                    spent_inputs.push(utxo_key);
                }
            }

            self.checked_ids.insert(*id);

            if !spent_inputs.is_empty() {
                relevant_transactions.push((*id, spent_inputs));
            }
        }

        relevant_transactions
    }

    /// Removes transactions that are no longer in the mempool.
    pub async fn evict_stale(&mut self, current_mempool_ids: Vec<TransactionKernelId>) {
        let current_mempool_ids: HashSet<_> = current_mempool_ids.into_iter().collect();

        self.checked_ids
            .retain(|id| current_mempool_ids.contains(id));

        // Drop stale tx ids from each UTXO's spender set, and drop the
        // UTXO entry entirely once no live tx is spending it anymore.
        self.pending_spends.retain(|_, spender_ids| {
            spender_ids.retain(|id| current_mempool_ids.contains(id));
            !spender_ids.is_empty()
        });
    }
}
