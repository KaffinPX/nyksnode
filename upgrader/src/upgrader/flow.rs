use std::collections::HashSet;
use std::time::Duration;

use nyks_consensus::block::Block;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::block::transaction_kernel::RpcTransactionKernelId;
use nyks_rpc_client::http::HttpClient;
use nyks_rpc_client::wallet::transaction::RpcTransaction;
use nyks_rpc_client::wallet::transaction::RpcTransactionProof;
use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::address::Recipient;
use tracing::info;
use tracing::warn;

use crate::Args;
use crate::upgrader::gobbler::Gobbler;
use crate::upgrader::pipeline::Reapable;
use crate::upgrader::pipeline::updater::Updater;
use crate::upgrader::pipeline::upgrader::UpgraderQueue;

#[derive(Clone)]
pub struct Upgrader {
    client: HttpClient,
    upgrader_queue: UpgraderQueue,
    updater: Updater,
    gobbler: Gobbler,
}

impl Upgrader {
    pub fn new(args: Args, client: HttpClient) -> Self {
        let updater = Updater::new(client.clone());
        let gobbler = Gobbler::new(
            Address::from_bech32m(&args.address, args.network).unwrap(),
            args.fee,
            updater.clone(),
        );

        Upgrader {
            client,
            upgrader_queue: UpgraderQueue::new(),
            updater,
            gobbler,
        }
    }

    pub async fn main_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            self.scan_mempool().await;

            // We first upgrade "one" transaction as "greedy" strategy defines this is more profitable.
            if let Some((id, transaction)) = self.upgrader_queue.prove_transaction().await {
                self.submit_upgraded_transaction(id, transaction).await;
            }

            for tx in self.updater.sync_transactions().await {
                if let Err(e) = self.client.submit_transaction(tx).await {
                    warn!("Failed to resubmit updated transaction: {e}");
                }

                info!("Submitted updated transaction succesfully!");
            }
        }
    }

    /// Sync a freshly-upgraded transaction to the current tip, merge it with
    /// the gobbler's fee-collecting transaction, and submit only that merged
    /// result. We never submit the bare upgraded transaction on its own:
    /// only a gobbled transaction actually pays us a fee, so submitting
    /// anything else would give the upgrade away for free.
    async fn submit_upgraded_transaction(
        &self,
        id: RpcTransactionKernelId,
        transaction: RpcTransaction,
    ) {
        let tip_block: Block = self.client.tip().await.unwrap().block.into();
        let tip_msa = tip_block.mutator_set_accumulator_after().unwrap();

        // Ensure its not stale by now.
        let Some(synced) = self.updater.sync_transaction(transaction).await else {
            warn!("Failed to sync upgraded transaction {} to tip.", id);
            return;
        };

        let Some(gobbled) = self.gobbler.gobble(synced, tip_msa).await else {
            warn!("Failed to gobble upgraded transaction {}.", id);
            return;
        };

        match self.client.submit_transaction(gobbled).await {
            Err(e) => warn!("Failed to submit gobbled transaction: {e}"),
            Ok(_) => info!("Upgraded (and gobbled) transaction {} succesfully!", id),
        }
    }

    // Scans nodes mempool for transaction candidates; if theres any, records it on relevant flows.
    async fn scan_mempool(&self) {
        let response = self.client.transactions().await.unwrap();
        let transactions = response.transactions;
        let tip_mutator_set_hash = response.metadata.tip_mutator_set_hash;
        let seen_ids: HashSet<_> = transactions.iter().copied().collect();

        for id in transactions {
            let kernel = self.client.get_transaction_kernel(id).await.unwrap().kernel;
            let Some(kernel) = kernel else {
                warn!("Kernel of transaction {id} not found.");
                continue;
            };

            let proof = self.client.get_transaction_proof(id).await.unwrap().proof;
            let Some(proof) = proof else {
                warn!("Proof of transaction {id} not found.");
                continue;
            };

            match &proof {
                RpcTransactionProof::ProofCollection(_) => {
                    let transaction = RpcTransaction { kernel, proof };
                    self.upgrader_queue
                        .record_transaction(id, transaction)
                        .await;
                }
                RpcTransactionProof::SingleProof(_) => {
                    self.upgrader_queue.forget_transaction(&id).await;

                    // Only track mutator-set updates for transactions we
                    // upgraded ourselves.
                    if self.gobbler.is_gobbled(&kernel) {
                        if kernel.mutator_set_hash != tip_mutator_set_hash {
                            let transaction = RpcTransaction { kernel, proof };
                            self.updater.record_transaction(id, transaction).await;
                        } else {
                            self.updater.forget_transaction(&id).await;
                        }
                    }
                }
            }
        }

        reap_stale(&self.upgrader_queue, &seen_ids).await;
        reap_stale(&self.updater, &seen_ids).await;
    }
}

/// Drop any tracked id that's no longer present in the mempool.
pub(crate) async fn reap_stale<T: Reapable>(
    tracked: &T,
    seen_ids: &HashSet<RpcTransactionKernelId>,
) {
    let gone: Vec<_> = tracked
        .tracked_ids()
        .await
        .into_iter()
        .filter(|id| !seen_ids.contains(id))
        .collect();

    for id in gone {
        tracked.forget_transaction(&id).await;
    }
}
