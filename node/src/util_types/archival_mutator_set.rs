use std::collections::HashMap;
use std::error::Error;

use itertools::Itertools;
use nyks_standards::mutator_set::IndexedAoclAuthPath;
use nyks_standards::mutator_set::MsMembershipProofPrivacyPreserving;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::util_types::archival_mmr::ArchivalMmr;
use nyks_database::storage::storage_vec::traits::*;
use nyks_protocol::consensus::mutator_set::active_window::ActiveWindow;
use nyks_protocol::consensus::mutator_set::addition_record::AdditionRecord;
use nyks_protocol::consensus::mutator_set::ms_membership_proof::MsMembershipProof;
use nyks_protocol::consensus::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use nyks_protocol::consensus::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use nyks_protocol::consensus::mutator_set::removal_record::chunk::Chunk;
use nyks_protocol::consensus::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
use nyks_protocol::consensus::mutator_set::removal_record::RemovalRecord;
use nyks_protocol::consensus::mutator_set::shared::BATCH_SIZE;
use nyks_protocol::consensus::mutator_set::shared::CHUNK_SIZE;
use nyks_protocol::consensus::mutator_set::shared::WINDOW_SIZE;
use nyks_protocol::consensus::mutator_set::MutatorSetError;

#[derive(Debug, Clone)]
pub struct ArchivalMutatorSet<MmrStorage, ChunkStorage>
where
    MmrStorage: StorageVec<Digest> + Send + Sync,
    ChunkStorage: StorageVec<Chunk> + Send + Sync,
{
    pub aocl: ArchivalMmr<MmrStorage>,
    pub swbf_inactive: ArchivalMmr<MmrStorage>,
    pub swbf_active: ActiveWindow,
    pub chunks: ChunkStorage,
}

impl<MmrStorage, ChunkStorage> ArchivalMutatorSet<MmrStorage, ChunkStorage>
where
    MmrStorage: StorageVec<Digest> + Send + Sync,
    ChunkStorage: StorageVec<Chunk> + StorageVecStream<Chunk> + Send + Sync,
{
    pub async fn prove(
        &self,
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> MsMembershipProof {
        MutatorSetAccumulator::new(
            &self.aocl.peaks().await,
            self.aocl.num_leafs().await,
            &self.swbf_inactive.peaks().await,
            &self.swbf_active.clone(),
        )
        .prove(item, sender_randomness, receiver_preimage)
    }

    pub async fn verify(&self, item: Digest, membership_proof: &MsMembershipProof) -> bool {
        let accumulator = self.accumulator().await;
        accumulator.verify(item, membership_proof)
    }

    pub async fn drop(&self, item: Digest, membership_proof: &MsMembershipProof) -> RemovalRecord {
        let accumulator = self.accumulator().await;
        accumulator.drop(item, membership_proof)
    }

    pub async fn add(&mut self, addition_record: &AdditionRecord) {
        let new_chunk: Option<(u64, Chunk)> = self.add_helper(addition_record).await;
        match new_chunk {
            None => (),
            Some((chunk_index, chunk)) => {
                // Sanity check to verify that we agree on the index
                assert_eq!(
                    chunk_index,
                    self.chunks.len().await,
                    "Length/index must agree when inserting a chunk into an archival node"
                );
                self.chunks.push(chunk).await;
            }
        }
    }

    pub async fn remove(&mut self, removal_record: &RemovalRecord) {
        let new_chunks: HashMap<u64, Chunk> = self.remove_helper(removal_record).await;
        self.chunks.set_many(new_chunks).await;
    }

    pub async fn hash(&self) -> Digest {
        self.accumulator().await.hash()
    }

    /// Apply a list of removal records while keeping a list of mutator set
    /// membership proofs up-to-date.
    pub async fn batch_remove(&mut self, removal_records: Vec<RemovalRecord>) {
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);

        // Collect all indices that that are set by the removal records
        let all_removal_records_indices: Vec<u128> = removal_records
            .iter()
            .map(|x| x.absolute_indices.to_vec())
            .concat();

        // Loop over all indices from removal records in order to create a
        // mapping {chunk index => chunk mutation } where "chunk mutation" has
        // the type of `Chunk` but only represents the values which are set by
        // the removal records being handled.
        let mut chunkidx_to_chunk_difference_dict: HashMap<u64, Chunk> = HashMap::new();
        for index in all_removal_records_indices {
            if index >= active_window_start {
                let relative_index = (index - active_window_start) as u32;
                self.swbf_active.insert(relative_index);
            } else {
                chunkidx_to_chunk_difference_dict
                    .entry((index / u128::from(CHUNK_SIZE)) as u64)
                    .or_insert_with(Chunk::empty_chunk)
                    .insert((index % u128::from(CHUNK_SIZE)) as u32);
            }
        }

        // Collect all affected chunks as they look before these removal records
        // are applied. These chunks are part of the removal records, so we
        // fetch them there.
        let mut new_chunks: HashMap<u64, Chunk> = HashMap::new();
        for removal_record in removal_records {
            for (chunk_index, (_, chunk)) in removal_record.target_chunks.dictionary {
                debug_assert!(
                    new_chunks
                        .get(&chunk_index)
                        .is_none_or(|chk| Tip5::hash(chk) == Tip5::hash(&chunk)),
                    "Sanity check: All removal records must agree on chunks"
                );
                new_chunks.insert(chunk_index, chunk);
            }
        }

        // Apply the removal records: the new chunk is obtained by adding the
        // chunk difference
        for (chunk_index, chunk) in &mut new_chunks {
            let new_chunk = chunk
                .clone()
                .combine(chunkidx_to_chunk_difference_dict[chunk_index].clone());
            *chunk = new_chunk.clone();
            self.chunks.set(*chunk_index, new_chunk).await;
        }

        // the Bloom filter such that we can apply a batch-update operation to
        // the MMR through which this part of the Bloom filter is represented.
        let swbf_inactive_mutation_data: Vec<(u64, Digest)> = new_chunks
            .into_iter()
            .map(|(idx, chk)| (idx, Tip5::hash(&chk)))
            .collect();

        // Apply the batch-update to the inactive part of the sliding window Bloom filter.
        // This updates both the inactive part of the SWBF and the MMR membership proofs
        self.swbf_inactive
            .batch_mutate_leaf_and_update_mps(&mut [], swbf_inactive_mutation_data)
            .await;
    }

    /// Clear the mutator set: revert all operations so as to bring it into a
    /// brand new state.
    pub(crate) async fn clear(&mut self) {
        self.aocl.prune_to_num_leafs(0).await;
        self.swbf_inactive.prune_to_num_leafs(0).await;
        self.swbf_active.sbf.clear();
        self.chunks.clear().await;
    }
}

impl<MmrStorage, ChunkStorage> ArchivalMutatorSet<MmrStorage, ChunkStorage>
where
    MmrStorage: StorageVec<Digest> + Send + Sync,
    ChunkStorage: StorageVec<Chunk> + StorageVecStream<Chunk> + Send + Sync,
{
    pub async fn new_empty(
        aocl: MmrStorage,
        swbf_inactive: MmrStorage,
        chunks: ChunkStorage,
    ) -> Self {
        assert_eq!(0, aocl.len().await);
        assert_eq!(0, swbf_inactive.len().await);
        assert_eq!(0, chunks.len().await);
        let aocl: ArchivalMmr<MmrStorage> = ArchivalMmr::new(aocl).await;
        let swbf_inactive: ArchivalMmr<MmrStorage> = ArchivalMmr::new(swbf_inactive).await;
        Self {
            aocl,
            swbf_inactive,
            swbf_active: ActiveWindow::new(),
            chunks,
        }
    }

    /// Returns an authentication path for an element in the append-only commitment list
    pub async fn get_aocl_authentication_path(
        &self,
        index: u64,
    ) -> Result<mmr::mmr_membership_proof::MmrMembershipProof, Box<dyn Error>> {
        if self.aocl.num_leafs().await <= index {
            return Err(Box::new(MutatorSetError::RequestedAoclAuthPathOutOfBounds(
                (index, self.aocl.num_leafs().await),
            )));
        }

        Ok(self.aocl.prove_membership_async(index).await)
    }

    /// Returns an authentication path for a chunk in the sliding window Bloom filter
    pub async fn get_chunk_and_auth_path(
        &self,
        chunk_index: u64,
    ) -> Result<(mmr::mmr_membership_proof::MmrMembershipProof, Chunk), Box<dyn Error>> {
        if self.swbf_inactive.num_leafs().await <= chunk_index {
            return Err(Box::new(MutatorSetError::RequestedSwbfAuthPathOutOfBounds(
                (chunk_index, self.swbf_inactive.num_leafs().await),
            )));
        }

        let chunk_auth_path: mmr::mmr_membership_proof::MmrMembershipProof =
            self.swbf_inactive.prove_membership_async(chunk_index).await;

        // This check should never fail. It would mean that chunks are missing but that the
        // archival MMR has the membership proof for the chunk. That would be a programming
        // error.
        assert!(
            self.chunks.len().await > chunk_index,
            "Chunks must be known if its authentication path is known."
        );
        let chunk = self.chunks.get(chunk_index).await;

        Ok((chunk_auth_path, chunk))
    }

    /// Restore membership_proof. If called on someone else's UTXO, this leaks privacy. In this case,
    /// caller is better off using `get_aocl_authentication_path` and `get_chunk_and_auth_path` for the
    /// relevant indices.
    pub async fn restore_membership_proof(
        &self,
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        aocl_leaf_index: u64,
    ) -> Result<MsMembershipProof, Box<dyn Error>> {
        if self.aocl.is_empty().await {
            return Err(Box::new(MutatorSetError::MutatorSetIsEmpty));
        }

        let auth_path_aocl = self.get_aocl_authentication_path(aocl_leaf_index).await?;
        let swbf_indices =
            AbsoluteIndexSet::compute(item, sender_randomness, receiver_preimage, aocl_leaf_index);

        let batch_index = self.get_batch_index_async().await;
        let window_start = batch_index * u128::from(CHUNK_SIZE);

        let chunk_indices: Vec<u64> = swbf_indices
            .to_array()
            .iter()
            .filter(|bi| **bi < window_start)
            .map(|bi| (*bi / u128::from(CHUNK_SIZE)) as u64)
            .collect();
        let mut target_chunks: ChunkDictionary = ChunkDictionary::default();

        // This is maximum 45 chunks, so it's OK to get all at once. No need
        // to have a stream. Stream didn't work when this function was called
        // from RPC server, so we just collect all here.
        let chunks = self.chunks.get_many(&chunk_indices).await;

        for (chunk_index, chunk) in chunk_indices.into_iter().zip_eq(chunks) {
            assert!(
                self.chunks.len().await > chunk_index,
                "Chunks must be known if its authentication path is known."
            );
            let chunk_membership_proof: mmr::mmr_membership_proof::MmrMembershipProof =
                self.swbf_inactive.prove_membership_async(chunk_index).await;
            target_chunks.insert(chunk_index, (chunk_membership_proof, chunk.to_owned()));
        }

        Ok(MsMembershipProof {
            auth_path_aocl,
            sender_randomness: sender_randomness.to_owned(),
            receiver_preimage: receiver_preimage.to_owned(),
            target_chunks,
            aocl_leaf_index,
        })
    }

    /// Restore a mutator set membership proof in a privacy-preserving manner,
    /// only leaking a fuzzy-timestamp.
    pub(crate) async fn restore_membership_proof_privacy_preserving(
        &self,
        absolute_indices: AbsoluteIndexSet,
    ) -> Result<MsMembershipProofPrivacyPreserving, Box<dyn Error>> {
        let mut aocl_auth_paths = vec![];
        let num_aocl_leafs = self.aocl.num_leafs().await;
        let (aocl_index_min, aocl_index_max) = absolute_indices.aocl_range()?;

        if aocl_index_min >= num_aocl_leafs {
            return Err(Box::new(MutatorSetError::RequestedAoclAuthPathOutOfBounds(
                (aocl_index_min, num_aocl_leafs),
            )));
        }

        // Do not attempt to read past end of AOCL leafs. In other words:
        // restrict AOCL authentication paths to those actually present in
        // mutator set.
        let aocl_index_max = std::cmp::min(aocl_index_max, num_aocl_leafs.saturating_sub(1));
        for leaf_index in aocl_index_min..=aocl_index_max {
            let auth_path = self.get_aocl_authentication_path(leaf_index).await?;
            let auth_path = IndexedAoclAuthPath {
                leaf_index,
                auth_path,
            };
            aocl_auth_paths.push(auth_path); // TODO: After tarpc gets deprecated, use indexed-kind like on json-rpc.
        }

        let mut target_chunks = vec![];
        let batch_index: u64 = self.get_batch_index_async().await.try_into().unwrap();

        for absolute_bf_index in absolute_indices.to_array() {
            let chunk_index: u64 = (absolute_bf_index / u128::from(CHUNK_SIZE)).try_into()?;

            // No auth path exists if chunk is part of active window
            if chunk_index >= batch_index {
                continue;
            }

            // Avoid repeating chunk indices in dictionary.
            if target_chunks
                .iter()
                .any(|(chk_idx, _)| *chk_idx == chunk_index)
            {
                continue;
            }

            target_chunks.push((
                chunk_index,
                self.get_chunk_and_auth_path(chunk_index).await?,
            ));
        }

        Ok(MsMembershipProofPrivacyPreserving {
            aocl_auth_paths,
            target_chunks: ChunkDictionary::new(target_chunks),
        })
    }

    /// Revert the `RemovalRecord` by removing the indices that
    /// were inserted by it. These live in either the active window, or
    /// in a relevant chunk.
    ///
    /// # Panics
    ///
    /// - If the supplied removal record does not have all its index set, i.e.
    ///   if the supplied removal record was not already applied to the mutator
    ///   set.
    pub async fn revert_remove(&mut self, removal_record: &RemovalRecord) {
        let removal_record_indices: Vec<u128> = removal_record.absolute_indices.to_vec();
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);
        let mut chunkidx_to_difference_dict: HashMap<u64, Chunk> = HashMap::new();

        // Populate the dictionary by iterating over all the removal
        // record's indices and inserting them into the correct
        // chunk in the dictionary, if the index is in the inactive
        // part. Otherwise, remove the index from the active window.
        for rr_index in removal_record_indices {
            if rr_index >= active_window_start {
                let relative_index = (rr_index - active_window_start) as u32;
                self.swbf_active.remove(relative_index);
            } else {
                let chunkidx = (rr_index / u128::from(CHUNK_SIZE)) as u64;
                let relative_index = (rr_index % u128::from(CHUNK_SIZE)) as u32;
                chunkidx_to_difference_dict
                    .entry(chunkidx)
                    .or_insert_with(Chunk::empty_chunk)
                    .insert(relative_index);
            }
        }

        for (chunk_index, revert_chunk) in chunkidx_to_difference_dict {
            // For each chunk, subtract the difference from the chunk.
            let previous_chunk = self.chunks.get(chunk_index).await;
            let mut new_chunk = previous_chunk;
            new_chunk.subtract(revert_chunk.clone());

            // update archival mmr
            self.swbf_inactive
                .mutate_leaf(chunk_index, Tip5::hash(&new_chunk))
                .await;

            self.chunks.set(chunk_index, new_chunk).await;
        }
    }

    /// Determine whether the given `AdditionRecord` can be reversed.
    /// Equivalently, determine if it was added last.
    pub async fn add_is_reversible(&mut self, addition_record: &AdditionRecord) -> bool {
        let leaf_index = self.aocl.num_leafs().await - 1;
        let digest = self.aocl.get_leaf_async(leaf_index).await;
        addition_record.canonical_commitment == digest
    }

    /// Revert the `AdditionRecord`s in a block by
    ///
    /// - Removing the last leaf in the append-only commitment list
    /// - If at a boundary where the active window slides, remove a chunk
    ///   from the inactive window, and slide window back by putting the
    ///   last inactive chunk in the active window.
    pub async fn revert_add(&mut self, addition_record: &AdditionRecord) {
        let removed_add_index = self.aocl.num_leafs().await - 1;

        // 1. Remove last leaf from AOCL
        let digest = self.aocl.remove_last_leaf_async().await.unwrap();
        assert_eq!(addition_record.canonical_commitment, digest);

        // 2. Possibly shrink bloom filter by moving a chunk back into active window
        //
        // This happens when the batch index changes (i.e. every `BATCH_SIZE` addition).
        if !MutatorSetAccumulator::window_slides_back(removed_add_index) {
            return;
        }

        // 2.a. Remove a chunk from inactive window
        let _digest = self.swbf_inactive.remove_last_leaf_async().await;
        let last_inactive_chunk = self.chunks.pop().await.unwrap();

        // 2.b. Slide active window back by putting `last_inactive_chunk` back
        self.swbf_active.slide_window_back(&last_inactive_chunk);
    }

    /// Return true if index is set in the Bloom filter. Uses only one database
    /// lookup as opposed to the naive implementation which would need two.
    ///
    /// Returns false if the index is a future index. So this function can never
    /// panic if the mutator set is well-formed.
    #[inline]
    async fn bloom_filter_contains_inner(&self, index: u128, active_window_start: u128) -> bool {
        if index >= active_window_start {
            let relative_index = (index - active_window_start) as u32;
            if relative_index >= WINDOW_SIZE {
                return false;
            }

            self.swbf_active.contains(relative_index)
        } else {
            let chunk_index = (index / u128::from(CHUNK_SIZE)) as u64;
            let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
            if relative_index >= CHUNK_SIZE {
                return false;
            }

            let relevant_chunk = self.chunks.get(chunk_index).await;
            relevant_chunk.contains(relative_index)
        }
    }

    /// Returns true iff all indices in the absolute index set are set.
    ///
    /// Returns false if any index is a future index.
    #[inline]
    pub async fn absolute_index_set_was_applied(&self, absolute_indices: AbsoluteIndexSet) -> bool {
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);

        // Returns once the first not-set index is found. Should be optimal
        // from a performance perspective.
        for index in absolute_indices.iter() {
            if !self
                .bloom_filter_contains_inner(index, active_window_start)
                .await
            {
                return false;
            }
        }

        true
    }

    /// Determine whether the index `index` is set in the Bloom
    /// filter, whether in the active window, or in some chunk.
    pub async fn bloom_filter_contains(&self, index: u128) -> bool {
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);

        self.bloom_filter_contains_inner(index, active_window_start)
            .await
    }

    pub async fn accumulator(&self) -> MutatorSetAccumulator {
        MutatorSetAccumulator {
            aocl: MmrAccumulator::init(self.aocl.peaks().await, self.aocl.num_leafs().await),
            swbf_inactive: MmrAccumulator::init(
                self.swbf_inactive.peaks().await,
                self.swbf_inactive.num_leafs().await,
            ),
            swbf_active: self.swbf_active.clone(),
        }
    }

    /// The number of times the active window has slid. Equal to the number of
    /// leafs in the inactive part of the sliding-window Bloom filter.
    #[inline]
    pub async fn get_batch_index_async(&self) -> u128 {
        u128::from(self.aocl.num_leafs().await.saturating_sub(1)) / u128::from(BATCH_SIZE)
    }

    /// Helper function. Like `add` but also returns the chunk that
    /// was added to the inactive SWBF if the window slid (and None
    /// otherwise) since this is needed by the archival version of
    /// the mutator set.
    pub async fn add_helper(&mut self, addition_record: &AdditionRecord) -> Option<(u64, Chunk)> {
        // Notice that `add` cannot return a membership proof since `add` cannot know the
        // randomness that was used to create the commitment. This randomness can only be know
        // by the sender and/or receiver of the UTXO. And `add` must be run be all nodes keeping
        // track of the mutator set.

        // add to list
        let item_index = self.aocl.num_leafs().await;
        self.aocl
            .append(addition_record.canonical_commitment.to_owned())
            .await; // ignore auth path

        if !Self::window_slides(item_index) {
            return None;
        }

        // if window slides, update filter
        // First update the inactive part of the SWBF, the SWBF MMR
        let new_chunk: Chunk = self.swbf_active.slid_chunk();
        let chunk_digest: Digest = Tip5::hash(&new_chunk);
        let new_chunk_index = self.swbf_inactive.num_leafs().await;
        self.swbf_inactive.append(chunk_digest).await; // ignore auth path

        // Then move window to the right, equivalent to moving values
        // inside window to the left.
        self.swbf_active.slide_window();

        // Return the chunk that was added to the inactive part of the SWBF.
        // This chunk is needed by the Archival mutator set. The Regular
        // mutator set can ignore it.
        Some((new_chunk_index, new_chunk))
    }

    /// Determine if the window slides before absorbing an item,
    /// given the index of the to-be-added item.
    pub fn window_slides(added_index: u64) -> bool {
        added_index != 0 && added_index.is_multiple_of(u64::from(BATCH_SIZE))

        // example cases:
        //  - index == 0 we don't care about
        //  - index == 1 does not generate a slide
        //  - index == n * BATCH_SIZE generates a slide for any n
    }

    /// Remove a record and return the chunks that have been updated in this process,
    /// after applying the update. Does not mutate the removal record.
    pub async fn remove_helper(&mut self, removal_record: &RemovalRecord) -> HashMap<u64, Chunk> {
        let batch_index = self.get_batch_index_async().await;
        let active_window_start = batch_index * u128::from(CHUNK_SIZE);

        // insert all indices
        let mut new_target_chunks: ChunkDictionary = removal_record.target_chunks.clone();
        let chunkindices_to_indices_dict: HashMap<u64, Vec<u128>> =
            removal_record.get_chunkidx_to_indices_dict();

        for (chunk_index, indices) in chunkindices_to_indices_dict {
            if chunk_index >= batch_index as u64 {
                // index is in the active part, so insert it in the active part of the Bloom filter
                for index in indices {
                    let relative_index = (index - active_window_start) as u32;
                    self.swbf_active.insert(relative_index);
                }

                continue;
            }

            // If chunk index is not in the active part, insert the index into the relevant chunk
            let new_target_chunks_clone = new_target_chunks.clone();
            let count_leaves = self.aocl.num_leafs().await;
            let relevant_chunk = new_target_chunks
                .get_mut(&chunk_index)
                .unwrap_or_else(|| {
                    panic!(
                        "Can't get chunk index {chunk_index} from removal record dictionary! dictionary: {:?}\nAOCL size: {}\nbatch index: {}\nRemoval record: {:?}",
                        new_target_chunks_clone,
                        count_leaves,
                        batch_index,
                        removal_record
                    )
                });
            for index in indices {
                let relative_index = (index % u128::from(CHUNK_SIZE)) as u32;
                relevant_chunk.1.insert(relative_index);
            }
        }

        // update mmr
        // to do this, we need to keep track of all membership proofs
        // If we want to update the membership proof with this removal, we
        // could use the below function.
        self.swbf_inactive
            .batch_mutate_leaf_and_update_mps(&mut [], new_target_chunks.indices_and_leafs())
            .await;

        new_target_chunks.indices_and_chunks().into_iter().collect()
    }
}
