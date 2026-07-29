use std::collections::VecDeque;
use std::sync::Arc;

use nyks_consensus::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::transaction::Transaction;
use nyks_consensus::transaction::TransactionProof;
use nyks_consensus::transaction::validity::single_proof::SingleProofWitness;
use nyks_consensus::transaction::validity::tasm::single_proof::merge_branch::MergeWitness;
use nyks_consensus::twenty_first::tip5::Digest;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_rpc_client::block::transaction_kernel::RpcTransactionKernel;
use nyks_rpc_client::wallet::transaction::RpcTransaction;
use nyks_rpc_client::wallet::transaction::RpcTransactionProof;
use nyks_standards::wallet::keys::address::Address;
use nyks_wallet_core::transaction::builder::TransactionBuilder;
use nyks_wallet_core::transaction::builder::input::TxInputList;
use nyks_wallet_core::transaction::builder::output::TxOutput;
use tokio::sync::RwLock;
use tokio::sync::watch;
use tracing::info;

use crate::core::prover::prove_sp_program;
use crate::upgrader::pipeline::updater::Updater;

/// Max number of recent gobbling transactions to cache, keyed by mutator set.
/// Sized to comfortably survive ordinary reorgs without falling back to proving a
/// brand new SingleProof from scratch.
const GOBBLER_CACHE_SIZE: usize = 12;

#[derive(Clone)]
pub struct Gobbler {
    output: TxOutput,
    updater: Updater,
    // Most-recent-first cache of (mutator_set_hash, transaction).
    cache: Arc<RwLock<VecDeque<(Digest, Transaction)>>>,
}

impl Gobbler {
    pub fn new(recipient: Address, amount: NativeCurrencyAmount, updater: Updater) -> Self {
        Gobbler {
            output: TxOutput::onchain_native_currency(amount, Digest::default(), recipient),
            updater,
            cache: Arc::new(RwLock::new(VecDeque::with_capacity(GOBBLER_CACHE_SIZE))),
        }
    }

    pub fn is_gobbled(&self, transaction_kernel: &RpcTransactionKernel) -> bool {
        if transaction_kernel
            .outputs
            .contains(&self.output.addition_record().into())
        {
            return true;
        }

        false
    }

    async fn cache_lookup(&self, hash: Digest) -> Option<Transaction> {
        self.cache
            .read()
            .await
            .iter()
            .find(|(cached_hash, _)| *cached_hash == hash)
            .map(|(_, tx)| tx.clone())
    }

    async fn cache_insert(&self, hash: Digest, transaction: Transaction) {
        let mut cache = self.cache.write().await;
        cache.retain(|(cached_hash, _)| *cached_hash != hash);
        cache.push_front((hash, transaction));
        while cache.len() > GOBBLER_CACHE_SIZE {
            cache.pop_back();
        }
    }

    /// Expensive fallback: prove a fresh gobbling transaction from zero.
    async fn build_from_scratch(
        &self,
        mutator_set_accumulator: MutatorSetAccumulator,
    ) -> Option<Transaction> {
        info!(
            "Creating a gobbler transaction from scratch for {:0x}...",
            mutator_set_accumulator.hash()
        );

        let transaction = TransactionBuilder::new()
            .inputs(TxInputList::empty())
            .outputs(vec![self.output.clone()].into())
            .fee(-self.output.native_currency_amount())
            .timestamp(Timestamp::now())
            .mutator_set_accumulator(mutator_set_accumulator)
            .build()
            .ok()?;
        let transaction = transaction.upgrade();
        let witness =
            SingleProofWitness::from_collection(transaction.proof.as_collection().unwrap());
        let (_cancel_tx, cancel_rx) = watch::channel(());
        let proof = prove_sp_program(witness, cancel_rx).await?;

        Some(Transaction {
            kernel: transaction.kernel,
            proof: TransactionProof::SingleProof(proof),
        })
    }

    async fn fetch_gobbler(
        &self,
        mutator_set_accumulator: MutatorSetAccumulator,
    ) -> Option<Transaction> {
        let target_hash = mutator_set_accumulator.hash();

        // Exact cache hit (e.g. reorg back to a recently-seen block).
        if let Some(transaction) = self.cache_lookup(target_hash).await {
            return Some(transaction);
        }

        // Try updating the most recent cached transaction instead of
        // proving from scratch.
        let most_recent = self.cache.read().await.front().cloned();
        if let Some((_, cached_tx)) = most_recent {
            match self
                .updater
                .sync_transaction(cached_tx.try_into().unwrap())
                .await
            {
                Some(updated) if updated.kernel.mutator_set_hash == target_hash => {
                    let updated_tx: Transaction = updated.try_into().unwrap();
                    self.cache_insert(target_hash, updated_tx.clone()).await;
                    return Some(updated_tx);
                }
                _ => {
                    info!(
                        "Could not update cached gobbling transaction to new tip, rebuilding from scratch."
                    );
                }
            }
        }

        // Fall back to building from scratch.
        let transaction = self.build_from_scratch(mutator_set_accumulator).await?;
        self.cache_insert(target_hash, transaction.clone()).await;
        Some(transaction)
    }

    pub async fn gobble(
        &self,
        transaction: RpcTransaction,
        mutator_set_accumulator: MutatorSetAccumulator,
    ) -> Option<RpcTransaction> {
        let gobbling_transaction = self.fetch_gobbler(mutator_set_accumulator).await?;
        let merge_witness = MergeWitness::from_transactions(
            gobbling_transaction,
            transaction.into(),
            Default::default(),
        );
        let new_kernel = merge_witness.new_kernel.clone();
        let witness = SingleProofWitness::from_merge(merge_witness);

        let (_cancel_tx, cancel_rx) = watch::channel(());
        let proof = prove_sp_program(witness, cancel_rx).await?;

        Some(RpcTransaction {
            kernel: (&new_kernel).into(),
            proof: RpcTransactionProof::SingleProof(proof.into()),
        })
    }
}
