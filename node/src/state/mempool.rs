//! An implementation of a mempool to store broadcast transactions waiting to be
//! mined.
//!
//! The implementation maintains a mapping called `table` between
//! 'transaction digests' and the full 'transactions' object, as well as a
//! double-ended priority queue called `queue` containing sorted pairs of
//! 'transaction digests' and the associated 'fee density'.  The `table` can be
//! seen as an associative cache that provides fast random-lookups, while
//! `queue` maintains transactions id's ordered by 'fee density'. Usually, we
//! are interested in the transaction with either the highest or the lowest 'fee
//! density'.

pub mod mempool_event;
pub(crate) mod merge_input_cache;

use std::collections::HashMap;
use std::collections::HashSet;

use bytesize::ByteSize;
use get_size2::GetSize;
use itertools::Itertools;
/// `FeeDensity` is a measure of 'Fee/Bytes' or 'reward per storage unit' for
/// transactions.  Different strategies are possible for selecting transactions
/// to mine, but a simple one is to pick transactions in descending order of
/// highest `FeeDensity`.
/// Note 1:  The `FeeDensity` is not part of the consensus mechanism, and may
/// even be ignored by the miner.
/// Note 2:  That `FeeDensity` does not exhibit 'greedy choice property':
///
/// # Counterexample
///
/// TransactionA = { Fee: 10, Size: 3 } => FeeDensity: 10/3
/// TransactionB = { Fee: 6,  Size: 2 } => FeeDensity:  6/2
/// TransactionC = { Fee: 6,  Size: 2 } => FeeDensity:  6/2
///
/// If available space is 4, then the greedy choice on `FeeDensity` would select
/// the set { TransactionA } while the optimal solution is { TransactionB,
/// TransactionC }.
use num_rational::BigRational as FeeDensity;
use nyks_consensus::block::Block;
use nyks_consensus::mutator_set::addition_record::AdditionRecord;
use nyks_consensus::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::transaction::transaction_kernel::TransactionKernel;
use nyks_consensus::transaction::transaction_kernel_id::TransactionKernelId;
use nyks_consensus::transaction::transaction_proof::TransactionProofQuality;
use nyks_consensus::transaction::Transaction;
use nyks_consensus::transaction::TransactionProof;
use priority_queue::DoublePriorityQueue;
use tasm_lib::prelude::Digest;
use tracing::debug;
use tracing::error;

use crate::state::mempool::mempool_event::MempoolEvent;
use crate::state::mempool::merge_input_cache::MergeInputCache;
use crate::state::mempool::merge_input_cache::MergeInputCacheElement;

// 72 hours in secs
pub const MEMPOOL_TX_THRESHOLD_AGE_IN_SECS: u64 = 72 * 60 * 60;

pub const TRANSACTION_NOTIFICATION_AGE_LIMIT_IN_SECS: u64 = 60 * 60 * 24;

type LookupItem<'a> = (TransactionKernelId, &'a Transaction);

/// Unpersisted view of valid transactions that have not been confirmed yet.
///
/// Transactions can be inserted into the mempool, and a max size of the
/// mempool can be declared.
///
/// The mempool uses [`TransactionKernelId`] as its main key, meaning that two
/// different transactions with the same [`TransactionKernelId`] can never be
/// stored in the mempool. The mempool keeps a sorted view of which transactions
/// are the most fee-paying as measured by [`FeeDensity`], thus allowing for the
/// least valuable (from a miner's and proof upgrader's perspective)
/// transactions to be dropped. However, the mempool always favors transactions
/// of higher "proof-quality" such that a single-proof backed transaction will
/// always replace a primitive-witness or proof-collection backed transaction,
/// without considering fee densities. This is because a) single-proof backed
/// transactions can always be synced to the latest block (assuming no
/// reorganization has occurred), and b) because single-proof backed
/// transactions are more likely to be picked for inclusion in the next block.
///
/// The mempool also keeps a view of the "upgrade priorities" of transactions,
/// from the perspective the the caller inserting the transaction. However, this
/// value is not used to determine which transactions gets to stay in the
/// mempool in the case of a full mempool, since such a value is subjective,
/// and a goal is to have different nodes running with the same mempool policy
/// to agree on the content of the mempool at any time, up to networking
/// conditions.
///
/// The mempool does not attempt to confirm validity or confirmability of its
/// transactions, that must be handled by the caller. It does, however,
/// guarantee that no conflicting transactions can be contained in the mempool.
/// This means that two transactions that spend the same input will never be
/// allowed into the mempool simultaneously.
///
/// To prevent valid transactions from being needlessly forgotten the mempool
/// maintains a cache of transactions that have been  deemed "merge inputs".
/// In short, consider the merger of transaction a and b into c. If the mempool
/// sees all three transactions, first a and b, then c, c will replace a and b
/// in the mempool in accordance with the above stated policy of no conflicting
/// transactions. However, a and b are kept around in a cache that's not
/// considered a part of the mempool as they will not e.g. be returned for block
/// construction. The cache is only used to avoid dropping transaction a if b is
/// mined instead of c. See `MergeInputCache` for a more detailed explanation.
///
/// The mempool returns a list of events which should be handled by associated
/// wallets to see unconfirmed balance updates. So all functions that can
/// return events should be invoked from a context where listeners (like
/// wallets) can be informed.
#[derive(Debug, GetSize)]
// *never* use Clone outside of tests as only one instance of the mempool should
// ever be needed by the aplication. Also: The mempool can have a size in the
// gigabytes so any application logic cloning it should have terrible
// performance.
#[cfg_attr(test, derive(Clone))]
pub struct Mempool {
    /// Maximum size this data structure may take up in memory. In bytes.
    max_total_size: usize,

    /// Contains transactions, with a mapping from transaction ID to
    /// transaction. Contains all transactions considered to be "in the
    /// mempool".
    tx_dictionary: HashMap<TransactionKernelId, Transaction>,

    /// Allows the mempool to report transactions sorted by [`FeeDensity`] in
    /// both descending and ascending order. Contains all transactions
    /// considered to be "in the mempool".
    // This is relatively small compared to `tx_dictionary`
    #[get_size(ignore)]
    fee_densities: DoublePriorityQueue<TransactionKernelId, FeeDensity>,

    /// The digest of the chain's tip. Used to discover reorganizations.
    tip_digest: Digest,

    /// The digest of the tip's mutator set hash. Used to check transaction
    /// confirmability.
    tip_mutator_set_hash: Digest,

    /// A list of single-proof backed transactions that were removed from the
    /// mempool because they were inputs to a merge. So they are not in the
    /// mempool because they conflict with another transaction there. When a
    /// new block comes in, however, some of these transactions may become
    /// "unconflicted" again. This list can only grow when [`Self::insert`] is
    /// called and can shrink when [`Self::update_with_block`] is called.
    merge_input_cache: MergeInputCache,
}

/// Enumerate ways that transactions in the mempool can be filtered.
enum TxMatcher<'a> {
    Inputs(&'a HashSet<AbsoluteIndexSet>),
    Outputs(&'a HashSet<AdditionRecord>),
}

impl<'a> TxMatcher<'a> {
    fn is_empty(&self) -> bool {
        match self {
            TxMatcher::Inputs(hash_set) => hash_set.is_empty(),
            TxMatcher::Outputs(hash_set) => hash_set.is_empty(),
        }
    }
}

/// note that all methods that modify state and result in a MempoolEvent
/// notification are private or pub(super).  This enforces that these methods
/// can only be called from/via GlobalState.
///
/// Mempool updates must go through GlobalState so that it can
/// forward mempool events to the wallet in atomic fashion.
impl Mempool {
    /// instantiate a new, empty `Mempool`
    pub fn new(max_total_size: ByteSize, tip: &Block) -> Self {
        let table = Default::default();
        let fee_densities = Default::default();
        let max_total_size = max_total_size.0.try_into().unwrap();
        let tip_digest = tip.hash();
        let tip_mutator_set_hash = tip
            .mutator_set_accumulator_after()
            .expect("Provided block must have mutator set after")
            .hash();
        let merge_input_cache = MergeInputCache::default();

        Self {
            max_total_size,
            tx_dictionary: table,
            fee_densities,
            tip_digest,
            tip_mutator_set_hash,
            merge_input_cache,
        }
    }

    /// Update mempool with chain information.
    ///
    /// Returns an error if the provided block does not have a mutator set
    /// after.
    fn set_sync_labels(&mut self, tip: &Block) -> anyhow::Result<()> {
        self.tip_digest = tip.hash();
        self.tip_mutator_set_hash = tip.mutator_set_accumulator_after()?.hash();
        Ok(())
    }

    /// Check if mempool will accept a transaction for insertion.
    ///
    /// Returns true if the new transaction is either not known, or if it is
    /// known but has a higher proof quality than the one already in the
    /// mempool. Synced transactions (with up-to-date mutator sets) are
    /// considered of higher quality than unsynced transactions.
    ///
    /// Even though this function returns true, a transaction might still be
    /// rejected for insertion if the mempool is full *and* the transaction has
    /// a lower fee density than all transactions in the mempool.
    pub(crate) fn accept_transaction(
        &self,
        new_tx_txid: TransactionKernelId,
        new_tx_proof_quality: TransactionProofQuality,
        new_tx_mutator_set_hash: Digest,
    ) -> bool {
        let Some(transaction) = self.tx_dictionary.get(&new_tx_txid) else {
            // Transaction is not in mempool. Is it in the cache of conflicting
            // transactions?
            return !self.merge_input_cache.contains(&new_tx_txid);
        };

        let mempool_proof_quality = transaction.proof.proof_quality();
        if mempool_proof_quality > new_tx_proof_quality {
            // New tx has lower proof quality.
            false
        } else if mempool_proof_quality == new_tx_proof_quality {
            // New tx has same proof quality. Check if new tx
            // represents a valid mutator set, if it does, return
            // true as the new transaction is more likely to be
            // included in a block when it's synced.
            transaction.kernel.mutator_set_hash != self.tip_mutator_set_hash
                && new_tx_mutator_set_hash == self.tip_mutator_set_hash
        } else {
            // New tx has higher proof quality.
            true
        }
    }

    pub fn tip_mutator_set_hash(&self) -> &Digest {
        &self.tip_mutator_set_hash
    }

    /// check if transaction exists in mempool
    ///
    /// Computes in O(1) from HashMap
    pub fn contains(&self, transaction_id: TransactionKernelId) -> bool {
        self.tx_dictionary.contains_key(&transaction_id)
    }

    /// get transaction from mempool
    ///
    /// Computes in O(1) from HashMap
    pub fn get(&self, transaction_id: TransactionKernelId) -> Option<&Transaction> {
        self.tx_dictionary.get(&transaction_id)
    }

    /// Returns an iterator over mempool items that are in conflict (not
    /// simultaneously confirmable) with the given transaction kernel.
    fn transactions_in_conflict_with(
        &self,
        kernel: &TransactionKernel,
    ) -> impl Iterator<Item = (&TransactionKernelId, &Transaction)> {
        // This check could be made a lot more efficient, for example with an invertible Bloom filter
        let tx_sbf_index_sets: HashSet<_> = kernel
            .inputs
            .iter()
            .map(|x| x.absolute_indices.to_array())
            .collect();

        self.tx_dictionary.iter().filter(move |(_, transaction)| {
            transaction
                .kernel
                .inputs
                .iter()
                .any(|rr| tx_sbf_index_sets.contains(&rr.absolute_indices.to_array()))
        })
    }

    /// Returns an iterator over mempool items that are either confirmed or made
    /// unconfirmable by the given block.
    fn transactions_kicked_by_block(
        &self,
        block: &Block,
    ) -> impl Iterator<Item = (&TransactionKernelId, &Transaction)> {
        self.transactions_in_conflict_with(block.body().transaction_kernel())
    }

    /// Returns an iterator over mempool items that are confirmed by the given
    /// block.
    fn transactions_confirmed_by_block(
        &self,
        block: &Block,
    ) -> impl Iterator<Item = (&TransactionKernelId, &Transaction)> {
        // Only consider transactions confirmed if all of their inputs are in
        // block transaction, and all of their outputs are also. Otherwise we
        // run the risk of mis-classifying transactions with overlapping inputs
        // or outputs.
        let kernel = block.body().transaction_kernel();
        let block_inputs = kernel
            .inputs
            .iter()
            .map(|removal_record| removal_record.absolute_indices)
            .collect::<HashSet<_>>();
        let block_outputs = kernel.outputs.iter().copied().collect::<HashSet<_>>();
        self.transactions_kicked_by_block(block)
            .filter(move |(_, transaction)| {
                transaction
                    .kernel
                    .outputs
                    .iter()
                    .all(|ar| block_outputs.contains(ar))
                    && transaction
                        .kernel
                        .inputs
                        .iter()
                        .all(|rr| block_inputs.contains(&rr.absolute_indices))
            })
    }

    /// Insert a transaction into the mempool. It is the caller's responsibility
    /// to validate the transaction.
    ///
    /// The caller must also ensure that the transaction does not have a
    /// timestamp in the too distant future, as such a transaction cannot be
    /// mined.
    ///
    /// Caller must specify the priority of the transaction to them.
    ///
    /// This method may return:
    ///   n events: RemoveTx,AddTx. Tx replaces a list of older txs with lower
    ///             fee.
    ///   1 event:  AddTx. tx does not replace an older one.
    ///   0 events: tx not added because an older conflicting tx has a higher
    ///             fee.
    pub(super) fn insert(&mut self, new_tx: Transaction) -> Vec<MempoolEvent> {
        fn new_tx_has_higher_proof_quality_than_conflicts(
            new_tx: &Transaction,
            conflicts: &HashMap<TransactionKernelId, &Transaction>,
            current_msa_hash: Digest,
        ) -> bool {
            match &new_tx.proof {
                TransactionProof::ProofCollection(_) => {
                    // ProofCollection transactions now only replace other ProofCollection
                    // transactions when the mutator set has been updated (old tx has stale
                    // hash, new tx has the current hash).
                    conflicts.iter().all(|(_, existing_tx)| {
                        matches!(&existing_tx.proof, TransactionProof::ProofCollection(_))
                            && existing_tx.kernel.mutator_set_hash != current_msa_hash
                            && new_tx.kernel.mutator_set_hash == current_msa_hash
                    })
                }
                TransactionProof::SingleProof(_) => {
                    // A SingleProof-backed transaction kicks out conflicts if
                    // a) any conflicts are not SingleProof, or
                    // b) the conflict (as there can be only one) has the same
                    //    txk-id, which indicates mutator set update, and the
                    //    new transaction has an updated mutator set hash.
                    conflicts.iter().any(|(conflicting_txkid, conflicting_tx)| {
                        !matches!(&conflicting_tx.proof, TransactionProof::SingleProof(_))
                            || *conflicting_txkid == new_tx.kernel.txid()
                                && new_tx.kernel.mutator_set_hash == current_msa_hash
                    })
                }
            }
        }

        // If transaction to be inserted conflicts with transactions already in
        // the mempool, we replace them -- but only if the new transaction has a
        // higher fee-density than the ones already in mempool, or if it has
        // a higher proof-quality, meaning that it's in a state more likely to
        // be picked up by a composer.
        // Consequently, merged transactions always replace those transactions
        // that were merged since the merged transaction is *very* likely to
        // have a higher fee density that the lowest one of the ones that were
        // merged.
        let conflicts: HashMap<TransactionKernelId, &Transaction> = self
            .transactions_in_conflict_with(&new_tx.kernel)
            .map(|(txkid, tx)| (*txkid, tx))
            .collect();

        // Do not insert an existing transaction again, if its an exact copy.
        let txid = new_tx.txid();
        if let Some(existing_tx) = conflicts.get(&txid) {
            if **existing_tx == new_tx {
                return vec![];
            }
        }

        let mut events = vec![];
        let new_tx_has_higher_proof_quality = new_tx_has_higher_proof_quality_than_conflicts(
            &new_tx,
            &conflicts,
            self.tip_mutator_set_hash,
        );
        let min_fee_of_conflicts = conflicts.values().map(|tx| tx.fee_density()).min();
        let conflicts = conflicts
            .into_iter()
            .map(|x| (x.0, x.1.proof.as_single_proof()))
            .collect_vec();
        if let Some(min_fee_of_conflicting_tx) = min_fee_of_conflicts {
            let better_fee_density = min_fee_of_conflicting_tx < new_tx.fee_density();
            let should_replace_conflict = new_tx_has_higher_proof_quality || better_fee_density;
            if should_replace_conflict {
                for (conflicting_txid, single_proof) in conflicts {
                    let e = self.remove(conflicting_txid).unwrap_or_else(|| {
                        panic!("Reported conflict {conflicting_txid} must exist")
                    });
                    let MempoolEvent::RemoveTx(removed) = &e else {
                        panic!("remove must return remove event");
                    };

                    // Conditionally store existing transaction in conflict
                    // cache.
                    if let Some(old_proof) = single_proof {
                        if new_tx.proof.is_single_proof()
                            && TransactionKernel::have_merge_relationship(&new_tx.kernel, removed)
                        {
                            self.merge_input_cache.insert(removed.to_owned(), old_proof);
                        }
                    }

                    events.push(e);
                }
            } else {
                // If new transaction has a lower fee density than the one previous seen,
                // ignore it. Stop execution here.
                debug!(
                    "Attempted to insert transaction into mempool but it's \
                     fee density was eclipsed by another transaction."
                );
                return events;
            }
        }

        // Insert the new transaction, if transaction with this txid already
        // existed, add the implied removal to events list.
        self.fee_densities.push(txid, new_tx.fee_density());
        events.push(MempoolEvent::AddTx(new_tx.kernel.clone()));
        if let Some(removed_tx) = self.tx_dictionary.insert(txid, new_tx) {
            events.push(MempoolEvent::RemoveTx(removed_tx.kernel));
        }

        assert_eq!(
            self.tx_dictionary.len(),
            self.fee_densities.len(),
            "mempool's table and queue length must agree prior to shrink"
        );

        let dropped_bc_size_restriction = self.shrink_to_max_size();
        events.extend(dropped_bc_size_restriction);

        assert_eq!(
            self.tx_dictionary.len(),
            self.fee_densities.len(),
            "mempool's table and queue length must agree after shrink"
        );

        MempoolEvent::normalize(events)
    }

    /// remove a transaction from the `Mempool`
    ///
    /// Does nothing if the transaction cannot be found in the mempool.
    pub(super) fn remove(&mut self, transaction_id: TransactionKernelId) -> Option<MempoolEvent> {
        self.tx_dictionary.remove(&transaction_id).map(|tx| {
            self.fee_densities.remove(&transaction_id);
            debug_assert_eq!(self.tx_dictionary.len(), self.fee_densities.len());
            MempoolEvent::RemoveTx(tx.kernel)
        })
    }

    /// Delete all transactions from the mempool.
    ///
    /// note that this will return a MempoolEvent for every removed Tx.
    /// In the case of a full block, that could be a lot of Tx and
    /// significant memory usage.  Of course the mempool itself will
    /// be emptied at the same time.
    ///
    /// If the mem usage ever becomes a problem we could accept a closure
    /// to handle the events individually as each Tx is removed.
    pub(super) fn clear(&mut self) -> Vec<MempoolEvent> {
        // note: this causes event listeners to be notified of each removed tx.
        self.merge_input_cache.clear();
        self.retain(|_| false)
    }

    /// Return the number of transactions currently stored in the Mempool.
    /// Computes in O(1)
    pub fn len(&self) -> usize {
        self.tx_dictionary.len()
    }

    /// Return the transactions in the mempool matching the selection criteria.
    fn with_matching_puts_inner(
        &self,
        match_method: TxMatcher,
    ) -> Vec<(TransactionKernel, Option<usize>)> {
        if match_method.is_empty() {
            return vec![];
        }

        // Build the matcher closure once
        let is_match: Box<dyn Fn(&Transaction) -> bool> = match match_method {
            TxMatcher::Inputs(index_sets) => Box::new(move |tx| {
                tx.kernel
                    .inputs
                    .iter()
                    .any(|ais| index_sets.contains(&ais.absolute_indices))
            }),
            TxMatcher::Outputs(addition_records) => Box::new(move |tx| {
                tx.kernel
                    .outputs
                    .iter()
                    .any(|ar| addition_records.contains(ar))
            }),
        };

        let mut matching_txs_with_queue_position = vec![];
        let mut queue_count = 0;
        for (txid, _fee_density) in self.fee_density_iter() {
            let tx = self
                .tx_dictionary
                .get(&txid)
                .expect("Txid returned by fee density iter must match tx in mempool");

            let sp_backed_and_synced = tx.proof.is_single_proof()
                && tx.kernel.mutator_set_hash == self.tip_mutator_set_hash;
            if is_match(tx) {
                let queue_position = if sp_backed_and_synced {
                    Some(queue_count)
                } else {
                    None
                };

                matching_txs_with_queue_position.push((tx.kernel.clone(), queue_position));
            }

            if sp_backed_and_synced {
                queue_count += 1;
            }
        }

        matching_txs_with_queue_position
    }

    /// Return (transaction, queue position) pairs for all transactions in the
    /// mempool that have at least one of the specified addition records. Only
    /// single proof-backed transactions with synced/updated proofs have an
    /// associated queue position. If the transaction is not single
    /// proof-backed, or it is not synced, the queue position is `None`.
    pub(crate) fn with_matching_addition_records(
        &self,
        addition_records: &HashSet<AdditionRecord>,
    ) -> Vec<(TransactionKernel, Option<usize>)> {
        self.with_matching_puts_inner(TxMatcher::Outputs(addition_records))
    }

    /// Return (transaction, queue position) pairs for all transactions in the
    /// mempool that have at least one of the specified absolute index sets.
    /// Only single proof-backed transactions with synced/updated proofs have an
    /// associated queue position. If the transaction is not single proof-
    /// backed, or it is not synced, the queue position is `None`.
    pub(crate) fn with_matching_absolute_index_sets(
        &self,
        absolute_index_sets: &HashSet<AbsoluteIndexSet>,
    ) -> Vec<(TransactionKernel, Option<usize>)> {
        self.with_matching_puts_inner(TxMatcher::Inputs(absolute_index_sets))
    }

    /// check if `Mempool` is empty
    ///
    /// Computes in O(1)
    pub fn is_empty(&self) -> bool {
        self.tx_dictionary.is_empty()
    }

    /// Return a vector with copies of the transactions, in descending order by
    /// fee density. Only returns transactions that are
    /// - backed by single proofs, and
    /// - synced to the tip.
    ///
    /// Number of transactions returned can be capped by either size (measured
    /// in bytes), or by transaction count. The function guarantees that neither
    /// of the specified limits will be exceeded.
    pub(crate) fn get_transactions_for_block_composition(
        &self,
        mut remaining_storage: usize,
        max_num_txs: Option<usize>,
    ) -> Vec<Transaction> {
        let mut transactions = vec![];

        for (transaction_digest, _fee_density) in self.fee_density_iter() {
            // No more transactions can possibly be packed
            if remaining_storage == 0 || max_num_txs.is_some_and(|max| transactions.len() == max) {
                break;
            }

            if let Some(transaction_ptr) = self.get(transaction_digest) {
                // Only return transaction synced to tip
                if !self.tx_is_synced(&transaction_ptr.kernel) {
                    continue;
                }

                if !matches!(transaction_ptr.proof, TransactionProof::SingleProof(_)) {
                    continue;
                }

                let transaction_copy = transaction_ptr.to_owned();
                let transaction_size = transaction_copy.get_size();

                // Current transaction is too big
                if transaction_size > remaining_storage {
                    continue;
                }

                // Include transaction
                remaining_storage -= transaction_size;
                transactions.push(transaction_copy)
            }
        }

        transactions
    }

    /// Removes the transaction with the lowest [`FeeDensity`] from the mempool.
    /// Returns the removed value.
    ///
    /// Computes in θ(lg N)
    fn pop_min(&mut self) -> Option<(MempoolEvent, FeeDensity)> {
        if let Some((txkid, fee_density)) = self.fee_densities.pop_min() {
            if let Some(tx) = self.tx_dictionary.remove(&txkid) {
                debug_assert_eq!(self.tx_dictionary.len(), self.fee_densities.len());

                let event = MempoolEvent::RemoveTx(tx.kernel);

                return Some((event, fee_density));
            }
        }
        None
    }

    /// Removes all transactions from the mempool that do not satisfy the
    /// predicate.
    /// Modelled after [HashMap::retain](std::collections::HashMap::retain())
    ///
    /// Computes in O(capacity) >= O(N)
    fn retain<F>(&mut self, mut predicate: F) -> Vec<MempoolEvent>
    where
        F: FnMut(LookupItem) -> bool,
    {
        let mut victims = vec![];

        for (&transaction_id, _fee_density) in &self.fee_densities {
            let transaction = self.get(transaction_id).unwrap();
            if !predicate((transaction_id, transaction)) {
                victims.push(transaction_id);
            }
        }

        let mut events = Vec::with_capacity(victims.len());
        for t in victims {
            if let Some(e) = self.remove(t) {
                events.push(e);
            }
        }

        debug_assert_eq!(self.tx_dictionary.len(), self.fee_densities.len());
        self.shrink_to_fit();

        events
    }

    /// Remove transactions from mempool that are older than the specified
    /// timestamp. Prunes base on the transaction's timestamp.
    ///
    /// Computes in O(n)
    pub(super) fn prune_stale_transactions(&mut self) -> Vec<MempoolEvent> {
        let cutoff = Timestamp::now() - Timestamp::seconds(MEMPOOL_TX_THRESHOLD_AGE_IN_SECS);

        let keep = |(_transaction_id, transaction): LookupItem| -> bool {
            cutoff < transaction.kernel.timestamp
        };

        self.retain(keep)
    }

    /// Remove from the mempool all transactions that become invalid because
    /// of a newly received block. Return a description of the transactions for
    /// which a primitive witness is present such that the caller can update
    /// their mutator set data.
    ///
    /// Fails if the provided block does not have a mutator set after.
    pub(super) fn update_with_block(
        &mut self,
        new_block: &Block,
    ) -> anyhow::Result<Vec<MempoolEvent>> {
        // If the mempool is empty, there is nothing to do.
        if self.is_empty() && self.merge_input_cache.is_empty() {
            self.set_sync_labels(new_block)?;
            return Ok(vec![]);
        }

        // If we discover a reorganization, we currently just clear the mempool,
        // as we don't have the ability to roll transaction removal record integrity
        // proofs back to previous blocks. It would be nice if we could handle a
        // reorganization that's at least a few blocks deep though.
        let mut events: Vec<_> = vec![];
        let previous_block_digest = new_block.header().prev_block_digest;
        if self.tip_digest != previous_block_digest {
            let removed = self.clear();
            events.extend(removed);
        }

        // The general strategy is to check whether the SWBF index set of a
        // given transaction in the mempool is disjoint from (*i.e.*, not
        // contained by) SWBF indices coming from the block transaction. If they
        // are not disjoint, then remove the transaction from the mempool, as
        // it is now a double-spending transaction.
        let block_bf_set_union: HashSet<_> = new_block
            .kernel
            .body
            .transaction_kernel
            .inputs
            .iter()
            .flat_map(|rr| rr.absolute_indices.to_array())
            .collect();
        let still_valid = |(_transaction_id, tx): LookupItem| -> bool {
            let transaction_index_sets: HashSet<_> = tx
                .kernel
                .inputs
                .iter()
                .map(|rr| rr.absolute_indices.to_array())
                .collect();

            transaction_index_sets.iter().all(|index_set| {
                index_set
                    .iter()
                    .any(|index| !block_bf_set_union.contains(index))
            })
        };

        // Remove the transactions that become invalid with this block
        {
            let removed = self.retain(still_valid);
            events.extend(removed);
        }

        // Restore transactions from blocks. Do this prior to the collection of
        // update jobs since we migth restore a transaction that we need to
        // return as an update job, in case one of our own transactions got
        // merged but the merged transaction was not picked up by the composer.
        let restored_from_cache = self
            .merge_input_cache
            .update_with_block(&block_bf_set_union);
        for elem in restored_from_cache {
            let MergeInputCacheElement {
                tx_kernel,
                single_proof,
            } = elem;
            let restored_tx = Transaction {
                kernel: tx_kernel,
                proof: TransactionProof::SingleProof(single_proof),
            };
            let inserted = self.insert(restored_tx);
            events.extend(inserted);
        }

        // Decide which transactions to keep (as we are removing PrimitiveWitness and switching to policy to keep proofcollections probably not needed.).

        {
            let removed = self.shrink_to_max_size();
            events.extend(removed);
        }

        // Update the sync-label to keep track of reorganizations
        self.set_sync_labels(new_block)?;

        let events = MempoolEvent::normalize(events);

        Ok(events)
    }

    /// Shrink the memory pool to the value of its `max_size` field.
    /// Likely computes in O(n).
    ///
    /// Returns events for removed transactions.
    fn shrink_to_max_size(&mut self) -> Vec<MempoolEvent> {
        // Repeately remove the least valuable transaction
        let mut removal_events: Vec<_> = vec![];

        // You have to dereference before calling `get_size` here, otherwise
        // you get the size of the pointer.
        while (*self).get_size() > self.max_total_size {
            const MAX_SIZE_OF_CACHE_FACTOR: usize = 3;
            let dominated_by_cache =
                self.merge_input_cache.get_size() * MAX_SIZE_OF_CACHE_FACTOR > (*self).get_size();
            if dominated_by_cache {
                assert!(
                    self.merge_input_cache.pop_oldest().is_some(),
                    "Dominated by cache but cannot remove element"
                );
            } else {
                let Some((removed, _)) = self.pop_min() else {
                    error!("Mempool is empty but exceeds max allowed size");
                    return removal_events;
                };

                removal_events.push(removed);
            }
        }

        self.shrink_to_fit();

        removal_events
    }

    /// Shrinks internal data structures as much as possible.
    /// Computes in O(n) (Likely)
    fn shrink_to_fit(&mut self) {
        self.fee_densities.shrink_to_fit();
        self.tx_dictionary.shrink_to_fit();
    }

    /// Return whether the transaction is synced to the tip block.
    fn tx_is_synced(&self, transaction_kernel: &TransactionKernel) -> bool {
        self.tip_mutator_set_hash == transaction_kernel.mutator_set_hash
    }

    /// Produce a sorted iterator over a snapshot of the Double-Ended Priority Queue.
    ///
    /// Yields the `transaction_digest` in order of descending `fee_density`, since
    /// users (miner or transaction merger) will likely only care about the most valuable transactions
    /// Computes in O(N lg N)
    pub fn fee_density_iter(
        &self,
    ) -> impl std::iter::DoubleEndedIterator<Item = (TransactionKernelId, FeeDensity)> {
        let dpq_clone = self.fee_densities.clone();
        dpq_clone.into_sorted_iter().rev()
    }
}
