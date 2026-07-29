use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::sync::watch;

use nyks_consensus::transaction::validity::proof_collection::ProofCollection;
use nyks_consensus::transaction::validity::single_proof::SingleProofWitness;
use nyks_prover::JobCancelSender;
use nyks_rpc_client::block::transaction_kernel::RpcTransactionKernelId;
use nyks_rpc_client::wallet::transaction::RpcTransaction;
use nyks_rpc_client::wallet::transaction::RpcTransactionProof;
use tracing::info;

use crate::core::prover::prove_sp_program;

#[derive(Clone)]
pub struct UpgraderQueue {
    transactions: Arc<RwLock<HashMap<RpcTransactionKernelId, RpcTransaction>>>,
    active_task: Arc<RwLock<Option<(RpcTransactionKernelId, JobCancelSender)>>>,
}

impl UpgraderQueue {
    pub fn new() -> Self {
        UpgraderQueue {
            transactions: Arc::new(RwLock::new(HashMap::new())),
            active_task: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn record_transaction(
        &self,
        id: RpcTransactionKernelId,
        transaction: RpcTransaction,
    ) {
        let mut txs = self.transactions.write().await;
        let mutator_set_hash = transaction.kernel.mutator_set_hash;
        match txs.insert(id, transaction) {
            None => info!("Added transaction {} to queue.", id),
            Some(old) if old.kernel.mutator_set_hash != mutator_set_hash => {
                info!("Updated transaction {} on queue.", id);
            }
            _ => {}
        }
    }

    /// Ids currently held in the queue, awaiting upgrade.
    pub async fn tracked_ids(&self) -> Vec<RpcTransactionKernelId> {
        self.transactions.read().await.keys().copied().collect()
    }

    pub async fn forget_transaction(&self, id: &RpcTransactionKernelId) {
        if self.transactions.write().await.remove(id).is_some() {
            info!("Removed transaction {} from queue.", id);
        }

        let mut active = self.active_task.write().await;
        if matches!(&*active, Some((active_id, _)) if active_id == id) {
            active.take();
            info!("Cancelled in-progress proof for transaction {}.", id);
        }
    }

    /// Proves the next queued transaction and returns its id alongside the
    /// upgraded transaction, so callers can track that this id was upgraded
    /// by us (as opposed to being observed as SingleProof from elsewhere).
    pub async fn prove_transaction(&self) -> Option<(RpcTransactionKernelId, RpcTransaction)> {
        let (id, transaction, cancel_rx) = {
            let mut txs = self.transactions.write().await;
            let &id = txs.keys().next()?;
            let transaction = txs.remove(&id).unwrap();
            let (cancel_tx, cancel_rx) = watch::channel(());
            *self.active_task.write().await = Some((id, cancel_tx));
            (id, transaction, cancel_rx)
        };

        info!("Starting upgrading of {}...", id);

        let proof_collection = match transaction.proof {
            RpcTransactionProof::ProofCollection(pc) => ProofCollection::from(*pc),
            _ => panic!("Only proof collection txs can be upgraded"),
        };

        let witness = SingleProofWitness::from_collection(proof_collection);
        let proof = prove_sp_program(witness, cancel_rx).await?;
        self.active_task.write().await.take();

        Some((
            id,
            RpcTransaction {
                kernel: transaction.kernel,
                proof: RpcTransactionProof::SingleProof(proof.into()),
            },
        ))
    }
}
