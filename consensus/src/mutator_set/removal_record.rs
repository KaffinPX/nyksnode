pub mod absolute_index_set;
pub mod chunk;
pub mod chunk_dictionary;
pub mod removal_record_list;

use std::collections::HashMap;
use std::collections::HashSet;
use std::ops::IndexMut;

use absolute_index_set::AbsoluteIndexSet;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Result;
// #[cfg(any(test, feature = "arbitrary-impls"))]
use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::twenty_first::util_types::mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::LeafMutation;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use super::MutatorSetError;
use super::mutator_set_accumulator::MutatorSetAccumulator;
use super::removal_record::chunk_dictionary::ChunkDictionary;
use super::shared::BATCH_SIZE;
use super::shared::CHUNK_SIZE;
use super::shared::get_batch_mutation_argument_for_removal_record;
use super::shared::indices_to_hash_map;
use crate::prelude::twenty_first;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]

pub struct RemovalRecord {
    pub absolute_indices: AbsoluteIndexSet,
    pub target_chunks: ChunkDictionary,
}

impl RemovalRecord {
    /// Update a batch of removal records that are synced to a given mutator set, in anticipation
    /// of one addition to that mutator set. (The addition record
    /// does not matter; all necessary information is in the mutator set.)
    pub fn batch_update_from_addition(
        removal_records: &mut [&mut Self],
        mutator_set: &MutatorSetAccumulator,
    ) {
        let new_item_index = mutator_set.aocl.num_leafs();

        // if window does not slide, do nothing
        if !MutatorSetAccumulator::window_slides(new_item_index) {
            return;
        }

        // window does slide
        let new_chunk = mutator_set.swbf_active.slid_chunk();
        let new_chunk_digest: Digest = Tip5::hash(&new_chunk);

        let next_batch_index = new_item_index / u64::from(BATCH_SIZE);
        let current_batch_index = next_batch_index - 1;
        assert_eq!(
            current_batch_index,
            mutator_set.swbf_inactive.num_leafs(),
            "Number of SWBF MMR leafs must match current batch index"
        );

        // Insert the new chunk digest into the accumulator-version of the
        // SWBF MMR to get its authentication path. It's important to convert the MMR
        // to an MMR Accumulator here, since we don't want to drag around or clone
        // a whole archival MMR for this operation, as the archival MMR can be in the
        // size of gigabytes, whereas the MMR accumulator should be in the size of
        // kilobytes.
        let mut mmra: MmrAccumulator = mutator_set.swbf_inactive.to_accumulator();
        let new_swbf_auth_path: mmr::mmr_membership_proof::MmrMembershipProof =
            mmra.append(new_chunk_digest);

        // Collect all indices for all removal records that are being updated
        let mut chunk_index_to_rr_index: HashMap<u64, Vec<usize>> = HashMap::new();
        removal_records.iter().enumerate().for_each(|(i, rr)| {
            let indices = &rr.absolute_indices;
            let chunks_set: HashSet<u64> = indices
                .to_array()
                .iter()
                .map(|x| (x / u128::from(CHUNK_SIZE)) as u64)
                .collect();

            for chnkidx in chunks_set {
                chunk_index_to_rr_index.entry(chnkidx).or_default().push(i);
            }
        });

        // Find the removal records that need a new dictionary entry for the chunk
        // that's being added to the inactive part by this addition.
        let batch_index = new_item_index / u64::from(BATCH_SIZE);
        let old_window_start_batch_index = batch_index - 1;

        let rrs_for_new_chunk_dictionary_entry: Vec<usize> =
            match chunk_index_to_rr_index.get(&old_window_start_batch_index) {
                Some(vals) => vals.clone(),
                None => vec![],
            };

        // Find the removal records that have dictionary entry MMR membership proofs
        // that need to be updated because of the window sliding.
        let mut rrs_for_batch_append: HashSet<usize> = HashSet::new();
        for (chunk_index, mp_indices) in chunk_index_to_rr_index {
            if chunk_index < old_window_start_batch_index {
                for mp_index in mp_indices {
                    rrs_for_batch_append.insert(mp_index);
                }
            }
        }

        // Perform the updates

        // First insert the new entry into the chunk dictionary for the removal
        // record that need it.
        for i in &rrs_for_new_chunk_dictionary_entry {
            removal_records.index_mut(*i).target_chunks.insert(
                old_window_start_batch_index,
                (new_swbf_auth_path.clone(), new_chunk.clone()),
            );
        }

        // Collect those MMR membership proofs for chunks whose authentication
        // path might need to be updated due to the insertion of a new leaf in the
        // SWBF MMR.
        // This is a bit ugly and a bit slower than it could be. To prevent this
        // for-loop, you probably could collect the `Vec<&mut mp>` in the code above,
        // instead of just collecting the indices into the removal record vector.
        // It is, however, quite acceptable that many of the MMR membership proofs are
        // repeated since the MMR `batch_update_from_append` handles this optimally.
        // So relegating that bookkeeping to this function instead would not be more
        // efficient.
        let mut mmr_membership_proofs_for_append: Vec<
            &mut mmr::mmr_membership_proof::MmrMembershipProof,
        > = vec![];
        let mut leaf_indices = vec![];
        for (i, rr) in removal_records.iter_mut().enumerate() {
            if rrs_for_batch_append.contains(&i) {
                for (chunk_index, (mmr_mp, _chnk)) in rr.target_chunks.iter_mut() {
                    if *chunk_index != old_window_start_batch_index {
                        mmr_membership_proofs_for_append.push(mmr_mp);
                        leaf_indices.push(*chunk_index);
                    }
                }
            }
        }

        // Perform the update of all the MMR membership proofs contained in the removal records
        mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_append(
            &mut mmr_membership_proofs_for_append,
            &leaf_indices,
            mutator_set.swbf_inactive.num_leafs(),
            new_chunk_digest,
            &mutator_set.swbf_inactive.peaks(),
        );
    }

    pub fn batch_update_from_remove(
        removal_records: &mut [&mut Self],
        applied_removal_record: &RemovalRecord,
    ) {
        // Set all chunk values to the new values and calculate the mutation argument
        // for the batch updating of the MMR membership proofs.
        let mut chunk_dictionaries: Vec<&mut ChunkDictionary> = removal_records
            .iter_mut()
            .map(|mp| &mut mp.target_chunks)
            .collect();
        let (_mutated_chunks_by_rr_indices, mutation_argument) =
            get_batch_mutation_argument_for_removal_record(
                applied_removal_record,
                &mut chunk_dictionaries,
            );

        // Collect all the MMR membership proofs from the chunk dictionaries.
        let mut own_mmr_mps: Vec<&mut mmr::mmr_membership_proof::MmrMembershipProof> = vec![];
        let mut leaf_indices = vec![];
        for chunk_dict in &mut chunk_dictionaries {
            for (chunk_index, (mp, _)) in chunk_dict.iter_mut() {
                own_mmr_mps.push(mp);
                leaf_indices.push(*chunk_index);
            }
        }

        // Perform the batch mutation of the MMR membership proofs
        mmr::mmr_membership_proof::MmrMembershipProof::batch_update_from_batch_leaf_mutation(
            &mut own_mmr_mps,
            &leaf_indices,
            mutation_argument
                .iter()
                .map(|(i, p, l)| LeafMutation::new(*i, *l, p.clone()))
                .collect_vec(),
        );
    }

    fn has_required_authenticated_chunks(
        &self,
        mutator_set_accumulator: &MutatorSetAccumulator,
    ) -> bool {
        let Ok((inactive, _)) = self
            .absolute_indices
            .split_by_activity(mutator_set_accumulator)
        else {
            return false;
        };

        let required_chunk_indices: HashSet<u64> = inactive.into_keys().collect();
        let proven_chunk_indices: HashSet<u64> =
            self.target_chunks.all_chunk_indices().into_iter().collect();
        required_chunk_indices == proven_chunk_indices
    }

    /// Validates that a removal record is synchronized against the inactive
    /// part of the SWBF, and that all required chunk/MMR membership proofs are
    /// present.
    pub fn validate(&self, mutator_set: &MutatorSetAccumulator) -> bool {
        self.validate_inner(mutator_set).is_ok()
    }

    /// Same as [`Self::validate`] but with informative error code.
    pub fn validate_inner(
        &self,
        mutator_set: &MutatorSetAccumulator,
    ) -> Result<(), RemovalRecordValidityError> {
        if !self.has_required_authenticated_chunks(mutator_set) {
            return Err(RemovalRecordValidityError::AbsentAuthenticatedChunk);
        }

        let swbfi_peaks = mutator_set.swbf_inactive.peaks();
        let swbfi_leaf_count = mutator_set.swbf_inactive.num_leafs();
        let maybe_invalid_chunk =
            self.target_chunks
                .iter()
                .find(|(chunk_index, (mmr_proof, chunk))| {
                    let leaf_digest = Tip5::hash(chunk);
                    !mmr_proof.verify(*chunk_index, leaf_digest, &swbfi_peaks, swbfi_leaf_count)
                });
        if let Some((chunk_index, _)) = maybe_invalid_chunk {
            return Err(RemovalRecordValidityError::InvalidSwbfiMmrMp {
                chunk_index: *chunk_index,
            });
        }

        Ok(())
    }

    /// Returns a hashmap from chunk index to chunk.
    pub fn get_chunkidx_to_indices_dict(&self) -> HashMap<u64, Vec<u128>> {
        indices_to_hash_map(&self.absolute_indices.to_array())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalRecordValidityError {
    AbsentAuthenticatedChunk,
    InvalidSwbfiMmrMp { chunk_index: u64 },
}
