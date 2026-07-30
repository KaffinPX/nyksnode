use std::collections::HashMap;

use num_traits::CheckedSub;
use num_traits::Zero;
use nyks_consensus::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use nyks_consensus::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::http::HttpClient;
use nyks_rpc_client::wallet::mutator_set::RpcMsMembershipProofPrivacyPreserving;

use crate::state::utxos::utxo::IncomingUtxo;
use crate::state::utxos::utxo::MonitoredUtxo;
use crate::state::utxos::utxo::MonitoredUtxoStatus;
use crate::state::utxos::utxo::UtxoKey;

/// Max index sets per `restore_membership_proof` call.
const RESTORE_BATCH_LIMIT: usize = 128;

/// Pool of spendable UTXOs with their mutator-set membership proofs.
///
/// Proofs sync lazily: adding a UTXO only restores its own proof; existing
/// UTXOs' proofs may go stale until needed, e.g. in [`UtxoPool::select_utxos`].
pub struct UtxoPool {
    pub rpc: HttpClient,
    pub utxos: HashMap<UtxoKey, MonitoredUtxo>,
}

/// Result of [`UtxoPool::select_utxos`].
pub struct UtxosSelection {
    /// Selected UTXOs, each valid against `msa`.
    pub utxos: Vec<MonitoredUtxo>,

    /// Amount selected beyond what was requested.
    pub change: NativeCurrencyAmount,

    /// MSA every selected UTXO is valid against.
    pub msa: MutatorSetAccumulator,

    /// UTXOs found spent/invalid during sync and evicted from the pool.
    pub invalidated_utxos: Vec<(UtxoKey, MonitoredUtxo)>,
}

impl UtxoPool {
    pub fn new(rpc: HttpClient) -> Self {
        UtxoPool {
            rpc,
            utxos: HashMap::new(),
        }
    }

    /// Returns true if it was a new UTXO
    pub fn import_utxo(&mut self, utxo: MonitoredUtxo) -> bool {
        self.utxos.insert(UtxoKey::new(&utxo), utxo).is_none()
    }

    /// Ingests UTXOs, restoring proofs only for the new ones.
    ///
    /// Returns the finalized new UTXOs with their keys.
    pub async fn add_utxos(&mut self, utxos: Vec<IncomingUtxo>) -> Vec<(UtxoKey, MonitoredUtxo)> {
        if utxos.is_empty() {
            return vec![];
        }

        let index_sets: Vec<_> = utxos.iter().map(|u| u.indices()).collect();
        let (proofs, _msa) = self.restore_proofs(index_sets).await;

        let mut added_utxos = Vec::with_capacity(proofs.len());

        for (utxo, proof) in utxos.into_iter().zip(proofs) {
            let utxo_msmp = proof
                .extract_ms_membership_proof(
                    utxo.aocl_leaf_index,
                    utxo.sender_randomness,
                    utxo.receiver_preimage,
                )
                .unwrap();
            let utxo = utxo.finalize(utxo_msmp);
            let utxo_key = UtxoKey::new(&utxo);

            self.utxos.insert(utxo_key.clone(), utxo.clone());
            added_utxos.push((utxo_key, utxo));
        }

        added_utxos
    }

    /// Greedily selects UTXOs covering `amount`, syncing only the selected
    /// ones against current chain state.
    ///
    /// Spent UTXOs are evicted and selection retries against the rest; all
    /// evictions are collected and returned. Every returned UTXO is valid
    /// against the returned `msa`.
    pub async fn select_utxos(
        &mut self,
        amount: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> UtxosSelection {
        let mut invalidated_utxos = Vec::new();

        loop {
            // Amounts don't change under mutator-set updates (only spentness
            // does), so selecting on cached amounts is safe without a sync.
            let mut candidate_utxos = Vec::new();
            let mut total_amount = NativeCurrencyAmount::zero();

            for (key, utxo) in self.utxos.iter() {
                if total_amount >= amount {
                    break;
                }

                if !utxo.can_spend_at(timestamp) {
                    continue;
                }

                total_amount += utxo.get_native_currency_amount();
                candidate_utxos.push(*key);
            }

            let excess_amount = total_amount
                .checked_sub(&amount)
                .expect("insufficient funds");

            // Sync only the candidates.
            let index_sets: Vec<_> = candidate_utxos
                .iter()
                .map(|k| {
                    let u = &self.utxos[k];
                    u.membership_proof.compute_indices(u.mutator_set_item())
                })
                .collect();

            let (proofs, msa) = self.restore_proofs(index_sets).await;

            let mut selected_utxos = Vec::with_capacity(candidate_utxos.len());
            let mut spent_utxos = Vec::new();

            for (key, proof) in candidate_utxos.iter().zip(proofs) {
                let existing = self.utxos.get_mut(key).unwrap();
                let old = &existing.membership_proof;
                let new_proof = proof
                    .extract_ms_membership_proof(
                        old.aocl_leaf_index,
                        old.sender_randomness,
                        old.receiver_preimage,
                    )
                    .unwrap();

                if msa.verify(existing.mutator_set_item(), &new_proof) {
                    existing.membership_proof = new_proof;
                    selected_utxos.push(existing.clone());
                } else {
                    tracing::debug!(
                        "UTXO on index {} is spent or invalid after sync; removing from pool.",
                        new_proof.aocl_leaf_index
                    );
                    spent_utxos.push(*key);
                }
            }

            if spent_utxos.is_empty() {
                return UtxosSelection {
                    utxos: selected_utxos,
                    change: excess_amount,
                    msa,
                    invalidated_utxos,
                };
            }

            // Drop spent UTXOs and retry against what remains.
            for key in spent_utxos {
                let mut utxo = self.utxos.remove(&key).expect("key was just selected");
                utxo.status = MonitoredUtxoStatus::SpentInUnknownBlock;

                invalidated_utxos.push((key, utxo));
            }
        }
    }

    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }

    /// With known type scripts.
    pub fn spendable_balance(&self) -> NativeCurrencyAmount {
        let timestamp = Timestamp::now();
        let mut total_amount = NativeCurrencyAmount::zero();

        for (_, utxo) in self.utxos.iter() {
            if !utxo.can_spend_at(timestamp) {
                continue;
            }

            let utxo_amount = utxo.get_native_currency_amount();
            total_amount += utxo_amount;
        }

        total_amount
    }

    /// Total, including timelocked etc.
    pub fn total_balance(&self) -> NativeCurrencyAmount {
        let mut total_amount = NativeCurrencyAmount::zero();

        for (_, utxo) in self.utxos.iter() {
            let utxo_amount = utxo.get_native_currency_amount();
            total_amount += utxo_amount;
        }

        total_amount
    }

    /// Calls `restore_membership_proof` in chunks of at most
    /// [`RESTORE_BATCH_LIMIT`], retrying if the tip changes mid-flight.
    ///
    /// Returns all proofs in original order plus the synced MSA; every proof
    /// is valid against it, since all chunks are pinned to the same `synced_hash`.
    async fn restore_proofs(
        &self,
        index_sets: Vec<AbsoluteIndexSet>,
    ) -> (
        Vec<RpcMsMembershipProofPrivacyPreserving>,
        MutatorSetAccumulator,
    ) {
        assert!(!index_sets.is_empty());

        loop {
            let mut snapshots = Vec::with_capacity(index_sets.len().div_ceil(RESTORE_BATCH_LIMIT));

            for chunk in index_sets.chunks(RESTORE_BATCH_LIMIT) {
                let snapshot = self
                    .rpc
                    .restore_membership_proof(chunk.to_vec())
                    .await
                    .unwrap()
                    .snapshot;
                snapshots.push(snapshot);
            }

            // A synced_hash mismatch means a block arrived mid-flight; retry
            // rather than mix proofs from different MSA states.
            let tip_hash = snapshots[0].synced_hash;
            if snapshots.iter().any(|s| s.synced_hash != tip_hash) {
                continue;
            }

            let msa: MutatorSetAccumulator =
                snapshots.last().unwrap().synced_mutator_set.clone().into();

            let all_proofs = snapshots
                .into_iter()
                .flat_map(|s| s.membership_proofs)
                .collect();

            return (all_proofs, msa);
        }
    }
}
