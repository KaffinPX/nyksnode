use nyks_rpc_client::block::transaction_kernel::RpcTransactionKernel;
use tracing::info;

use crate::state::utxos::index::UtxoIndex;

/// Scans invidual transactions batch independant of chain
/// interacting with current utxo pool
pub struct MempoolScanner {
    index: UtxoIndex,
}

impl MempoolScanner {
    pub fn new(index: UtxoIndex) -> Self {
        MempoolScanner { index }
    }

    pub async fn scan(&self, transactions: Vec<RpcTransactionKernel>) {
        for transaction in &transactions {
            info!("{} inputs", transaction.inputs.len());
            for input in &transaction.inputs {
                if let Some(utxo_key) = self.index.get(&input.absolute_indices).await {
                    info!("{} is being spent on mempool", utxo_key.aocl_index);
                }
            }
        }
    }
}
