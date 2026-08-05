use std::{collections::HashMap, sync::Arc};

use nyks_consensus::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use nyks_rpc_client::block::transaction_kernel::RpcTransactionKernel;
use tokio::sync::RwLock;
use tracing::info;

use crate::state::utxos::UtxoKey;
use crate::state::utxos::pool::UtxoPool;

/// Scans invidual transactions batch independant of chain
/// interacting with current utxo pool
pub struct MempoolScanner {
    utxos: Arc<RwLock<UtxoPool>>,
}

impl MempoolScanner {
    pub fn new(utxos: Arc<RwLock<UtxoPool>>) -> Self {
        MempoolScanner { utxos }
    }

    async fn indices(&self) -> HashMap<AbsoluteIndexSet, UtxoKey> {
        self.utxos
            .read()
            .await
            .utxos
            .iter()
            .map(|(key, utxo)| (utxo.indices(), *key))
            .collect()
    }

    pub async fn scan(&self, transactions: Vec<RpcTransactionKernel>) {
        let current_indices = self.indices().await;

        for transaction in &transactions {
            info!("{} inputs", transaction.inputs.len());
            for input in &transaction.inputs {
                let indices = input.absolute_indices;

                if current_indices.contains_key(&indices) {
                    let utxo_key = current_indices.get(&indices).unwrap();

                    info!("{} is being spent on mempool", utxo_key.aocl_index);
                }
            }
        }
    }
}
