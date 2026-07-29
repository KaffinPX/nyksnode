use std::collections::HashMap;
use std::sync::Arc;

use itertools::Itertools;
use nyks_consensus::block::Block;
use nyks_consensus::transaction::transaction_kernel::TransactionKernel;
use nyks_consensus::transaction::transaction_kernel::TransactionKernelModifier;
use nyks_consensus::transaction::validity::neptune_proof::Proof;
use nyks_consensus::transaction::validity::single_proof::SingleProofWitness;
use nyks_consensus::transaction::validity::tasm::single_proof::update_branch::UpdateWitness;
use nyks_consensus::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;
use nyks_prover::JobCancelSender;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::block::transaction_kernel::RpcTransactionKernelId;
use nyks_rpc_client::common::BlockSelector;
use nyks_rpc_client::http::HttpClient;
use nyks_rpc_client::wallet::transaction::RpcTransaction;
use nyks_rpc_client::wallet::transaction::RpcTransactionProof;
use tokio::sync::RwLock;
use tokio::sync::watch;
use tracing::info;

use crate::core::prover::prove_sp_program;

#[derive(Clone)]
pub struct Updater {
    client: HttpClient,
    transactions: Arc<RwLock<HashMap<RpcTransactionKernelId, RpcTransaction>>>,
    active_task: Arc<RwLock<Option<(RpcTransactionKernelId, JobCancelSender)>>>,
}

impl Updater {
    pub fn new(client: HttpClient) -> Self {
        Updater {
            client,
            transactions: Arc::new(RwLock::new(HashMap::new())),
            active_task: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn record_transaction(
        &self,
        id: RpcTransactionKernelId,
        transaction: RpcTransaction,
    ) {
        assert!(
            matches!(transaction.proof, RpcTransactionProof::SingleProof(_)),
            "Updater only supports SingleProof transactions"
        );

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

    /// Ids currently held in the update queue (regardless of proving state).
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

    pub async fn sync_transactions(&self) -> Vec<RpcTransaction> {
        let ids: Vec<RpcTransactionKernelId> =
            self.transactions.read().await.keys().copied().collect();
        let mut proved = Vec::with_capacity(ids.len());

        for id in ids {
            if let Some(tx) = self.sync_transaction_by_id(id).await {
                proved.push(tx);
            }
        }

        proved
    }

    /// Bring an arbitrary SingleProof transaction up to date with the
    /// current tip's mutator set, independent of the internal queue.
    pub async fn sync_transaction(&self, transaction: RpcTransaction) -> Option<RpcTransaction> {
        let RpcTransactionProof::SingleProof(proof) = transaction.proof.clone() else {
            panic!("sync_transaction only supports SingleProof transactions");
        };

        let old_kernel: TransactionKernel = transaction.kernel.into();
        let old_proof: Proof = proof.into();

        // Not tracked in active_task/the queue, so there's no way to cancel
        // this externally; keep the sender alive for the duration of the call.
        let (_cancel_tx, cancel_rx) = watch::channel(());

        let (new_kernel, new_proof) = self
            .update_kernel_and_proof(old_kernel, old_proof, cancel_rx)
            .await?;

        Some(RpcTransaction {
            kernel: (&new_kernel).into(),
            proof: RpcTransactionProof::SingleProof(new_proof.into()),
        })
    }

    async fn sync_transaction_by_id(&self, id: RpcTransactionKernelId) -> Option<RpcTransaction> {
        info!("Starting updating mutator set of {}...", id);

        // 1. Snapshot the old transaction
        let (old_kernel, old_proof): (TransactionKernel, Proof) = {
            let mut transactions = self.transactions.write().await;
            let transaction = transactions.remove(&id)?;

            let RpcTransactionProof::SingleProof(proof) = transaction.proof.clone() else {
                unreachable!("record_transaction only stores SingleProof transactions");
            };

            (transaction.kernel.into(), proof.into())
        };

        let (cancel_tx, cancel_rx) = watch::channel(());
        *self.active_task.write().await = Some((id, cancel_tx));
        let result = self
            .update_kernel_and_proof(old_kernel, old_proof, cancel_rx)
            .await;
        self.active_task.write().await.take();

        let (new_kernel, new_proof) = result?;

        Some(RpcTransaction {
            kernel: (&new_kernel).into(),
            proof: RpcTransactionProof::SingleProof(new_proof.into()),
        })
    }

    /// Walk from tip backwards to find the block whose mutator set matches
    /// `old_kernel`'s, then apply every intervening block's mutator set
    /// update to produce an up-to-date kernel, proving once at the end.
    async fn update_kernel_and_proof(
        &self,
        old_kernel: TransactionKernel,
        old_proof: Proof,
        cancel_rx: watch::Receiver<()>,
    ) -> Option<(TransactionKernel, Proof)> {
        // Walk from tip backwards to find the block whose MSA matches the old kernel
        let tip_block: Block = self.client.tip().await.unwrap().block.into();

        if tip_block.mutator_set_accumulator_after().unwrap().hash()
            == old_kernel.mutator_set_hash()
        {
            // Already in sync with tip; nothing to update or re-prove.
            return Some((old_kernel, old_proof));
        }

        let mut blocks_after = Vec::new();
        let mut current_block = tip_block.clone();

        let old_msa = loop {
            let msa = current_block.mutator_set_accumulator_after().unwrap();
            if msa.hash() == old_kernel.mutator_set_hash() {
                break msa;
            }
            blocks_after.push(current_block.clone());
            let prev_digest = current_block.header().prev_block_digest;
            current_block = self
                .client
                .get_block(BlockSelector::Digest(prev_digest))
                .await
                .ok()?
                .block?
                .into();
        };
        blocks_after.reverse(); // Now in chronological order

        // Apply each block's update sequentially to compute the final state.
        let mut msa = old_msa.clone();
        let mut inputs = old_kernel.inputs.clone();
        let mut all_additions = Vec::new();

        for block in &blocks_after {
            let update = block.mutator_set_update().ok()?;
            all_additions.extend(update.additions.clone());

            update
                .apply_to_accumulator_and_records(
                    &mut msa,
                    &mut inputs.iter_mut().collect_vec(),
                    &mut [],
                )
                .unwrap()
        }
        info!(
            "From {} to {}...",
            old_msa.hash().to_hex(),
            msa.hash().to_hex()
        );

        // Build a single AOCL successor proof covering all additions from all blocks
        let aocl_proof = MmrSuccessorProof::new_from_batch_append(
            &old_msa.aocl,
            &all_additions
                .iter()
                .map(|ar| ar.canonical_commitment)
                .collect_vec(),
        );

        // Create the new(updated) kernel and the UpdateWitness
        let new_kernel = TransactionKernelModifier::default()
            .inputs(inputs)
            .mutator_set_hash(msa.hash())
            .clone_modify(&old_kernel);

        let update_witness = UpdateWitness::from_old_transaction(
            old_kernel,
            old_proof,
            old_msa, // original accumulator (before any updates)
            new_kernel.clone(),
            msa, // final accumulator after all updates
            aocl_proof,
        );

        // Prove once
        let witness = SingleProofWitness::from_update(update_witness);
        let new_proof = prove_sp_program(witness, cancel_rx).await?;

        Some((new_kernel, new_proof))
    }
}
