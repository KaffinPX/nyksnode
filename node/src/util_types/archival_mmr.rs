use std::ops::RangeInclusive;

use itertools::Itertools;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::LeafMutation;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::get_authentication_path_node_indices;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::get_peak_heights_and_peak_node_indices;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::leaf_index_to_node_index;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::node_index_to_leaf_index;
use tasm_lib::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;
use tasm_lib::twenty_first::util_types::mmr::shared_basic::right_lineage_length_from_leaf_index;

use nyks_database::storage::storage_schema::DbtVec;
use nyks_database::storage::storage_vec::traits::*;

/// A Merkle Mountain Range is a datastructure for storing a list of hashes.
///
/// Merkle Mountain Ranges only know about hashes. When values are to be associated with
/// MMRs, these values must be stored by the caller, or in a wrapper to this data structure.
#[derive(Debug, Clone)]
pub struct ArchivalMmr<Storage: StorageVec<Digest>> {
    digests: Storage,
}

impl<Storage> ArchivalMmr<Storage>
where
    Storage: StorageVec<Digest>,
{
    /// Calculate the root for the entire MMR
    pub async fn bag_peaks(&self) -> Digest {
        let peaks: Vec<Digest> = self.peaks().await;
        let num_leafs = self.num_leafs().await;
        MmrAccumulator::init(peaks, num_leafs).bag_peaks()
    }

    /// Return the digests of the peaks of the MMR
    pub async fn peaks(&self) -> Vec<Digest> {
        let leaf_count = self.num_leafs().await;
        let (_, peak_node_indices) = get_peak_heights_and_peak_node_indices(leaf_count);
        self.digests.get_many(&peak_node_indices).await
    }

    /// Whether the MMR is empty. Note that since indexing starts at
    /// 1, the `digests` contain must always contain at least one
    /// element: a dummy digest.
    pub async fn is_empty(&self) -> bool {
        self.digests.len().await == 1
    }

    /// Return the number of leaves in the tree
    pub async fn num_leafs(&self) -> u64 {
        node_index_to_leaf_index(self.digests.len().await).unwrap()
    }

    /// Append an element to the archival MMR, return the membership proof of the newly added leaf.
    pub async fn append(&mut self, new_leaf: Digest) -> MmrMembershipProof {
        let mut node_index = self.digests.len().await;
        let leaf_index = node_index_to_leaf_index(node_index).unwrap();
        let right_lineage_length = right_lineage_length_from_leaf_index(leaf_index);
        self.digests.push(new_leaf).await;

        let mut returned_auth_path = vec![];
        let mut acc_hash = new_leaf;
        for height in 0..right_lineage_length {
            let left_sibling_hash = self
                .digests
                .get(shared_advanced::left_sibling(node_index, height))
                .await;
            returned_auth_path.push(left_sibling_hash);
            acc_hash = Tip5::hash_pair(left_sibling_hash, acc_hash);
            self.digests.push(acc_hash).await;
            node_index += 1;
        }

        MmrMembershipProof {
            authentication_path: returned_auth_path,
        }
    }

    /// Mutate an existing leaf.
    pub async fn mutate_leaf(&mut self, leaf_index: u64, new_leaf: Digest) {
        // 1. change the leaf value
        let mut node_index = shared_advanced::leaf_index_to_node_index(leaf_index);
        self.digests.set(node_index, new_leaf).await;
        // leaf_index_to_mt_index_and_peak_index

        // While parent exists in MMR, update parent
        let mut parent_index = shared_advanced::parent(node_index);
        let mut acc_hash = new_leaf;
        while parent_index < self.digests.len().await {
            let (right_lineage_count, height) =
                shared_advanced::right_lineage_length_and_own_height(node_index);
            acc_hash = if right_lineage_count != 0 {
                // node is right child
                Tip5::hash_pair(
                    self.digests
                        .get(shared_advanced::left_sibling(node_index, height))
                        .await,
                    acc_hash,
                )
            } else {
                // node is left child
                Tip5::hash_pair(
                    acc_hash,
                    self.digests
                        .get(shared_advanced::right_sibling(node_index, height))
                        .await,
                )
            };
            self.digests.set(parent_index, acc_hash).await;
            node_index = parent_index;
            parent_index = shared_advanced::parent(parent_index);
        }
    }

    /// Modify a bunch of leafs and keep a set of membership proofs in sync. Notice that this
    /// function is not just the application of `mutate_leaf` multiple times, as it also preserves
    /// a list of membership proofs.
    pub async fn batch_mutate_leaf_and_update_mps(
        &mut self,
        membership_proofs: &mut [&mut MmrMembershipProof],
        mutation_data: Vec<(u64, Digest)>,
    ) -> Vec<usize> {
        assert!(
            mutation_data.iter().map(|md| md.0).all_unique(),
            "Duplicated leaves are not allowed in membership proof updater"
        );

        for (leaf_index, digest) in &mutation_data {
            self.mutate_leaf(*leaf_index, *digest).await;
        }

        let mut modified_mps: Vec<usize> = vec![];
        for ((i, mp), (leaf_index, _old_leaf)) in membership_proofs
            .iter_mut()
            .enumerate()
            .zip(mutation_data.iter())
        {
            let new_mp = self.prove_membership_async(*leaf_index).await;
            if new_mp != **mp {
                modified_mps.push(i);
            }

            **mp = new_mp
        }

        modified_mps
    }

    pub async fn verify_batch_update(
        &self,
        new_peaks: &[Digest],
        appended_leafs: &[Digest],
        leaf_mutations: &[LeafMutation],
    ) -> bool {
        let accumulator: MmrAccumulator = self.to_accumulator_async().await;
        accumulator.verify_batch_update(new_peaks, appended_leafs, leaf_mutations.to_vec())
    }

    pub async fn to_accumulator_async(&self) -> MmrAccumulator {
        MmrAccumulator::init(self.peaks().await, self.num_leafs().await)
    }
}

impl<Storage: StorageVec<Digest>> ArchivalMmr<Storage> {
    /// Create a new archival MMR, or restore one from a database.
    pub async fn new(pv: Storage) -> Self {
        let mut ret = Self { digests: pv };
        ret.fix_dummy_async().await;
        ret
    }

    /// Inserts a dummy digest into the `digests` container. Due to
    /// 1-indexation, this structure must always contain one element
    /// (even if it is never used). Due to the persistence layer,
    /// this data structure can be set to the default vector, which
    /// is the empty vector. This method fixes that.
    pub async fn fix_dummy_async(&mut self) {
        if self.digests.len().await == 0 {
            self.digests.push(Digest::default()).await;
        }
    }

    /// Get a leaf from the MMR, will panic if index is out of range.
    ///
    /// # Panics
    ///
    /// panics if the leaf-index is out-of-bounds.
    pub async fn get_leaf_async(&self, leaf_index: u64) -> Digest {
        // Use debug-assert here to limit this lookup to *one* db-lookup in
        // production. Otherwise, it would be two lookups.
        debug_assert!(
            leaf_index < self.num_leafs().await,
            "Leaf index out-of-bounds. Got leaf index {leaf_index} but num_leafs was {}",
            self.num_leafs().await
        );
        let node_index = shared_advanced::leaf_index_to_node_index(leaf_index);
        self.digests.get(node_index).await
    }

    /// Get a range of leafs from the MMR.
    ///
    /// # Panics
    ///
    ///  - If the range contains out-of-bound indices.
    pub async fn get_leaf_range_inclusive_async(
        &self,
        leaf_index_range: RangeInclusive<u64>,
    ) -> Vec<Digest> {
        // Use debug-assert here to limit this lookup to *one* db-lookup in
        // production. Otherwise, it would be two lookups.
        debug_assert!(
            *leaf_index_range.end() < self.num_leafs().await,
            "Leaf index out-of-bounds. Got leaf index {} but num_leafs was {}",
            leaf_index_range.end(),
            self.num_leafs().await
        );

        let indices = leaf_index_range
            .into_iter()
            .map(shared_advanced::leaf_index_to_node_index)
            .collect_vec();
        self.digests.get_many(&indices).await
    }

    /// Get a leaf from the MMR, returns `None` if index is out of range.
    pub async fn try_get_leaf(&self, leaf_index: u64) -> Option<Digest> {
        if leaf_index >= self.num_leafs().await {
            None
        } else {
            Some(self.get_leaf_async(leaf_index).await)
        }
    }

    /// Return membership proof, as it looks relative to a smaller version of
    /// the MMR which only has `num_leafs` leafs. `num_leafs` may not exceed
    /// the actual number of leafs.
    pub(crate) async fn prove_membership_relative_to_smaller_mmr(
        &self,
        leaf_index: u64,
        num_leafs: u64,
    ) -> MmrMembershipProof {
        // TODO: Replace this local function with the one in `twenty_first` once
        // available through never version.
        fn auth_path_node_indices(num_leafs: u64, leaf_index: u64) -> Vec<u64> {
            assert!(
                leaf_index < num_leafs,
                "Leaf index out-of-bounds: {leaf_index}/{num_leafs}"
            );

            let (mut merkle_tree_index, _) =
                leaf_index_to_mt_index_and_peak_index(leaf_index, num_leafs);
            let mut node_index = leaf_index_to_node_index(leaf_index);
            let mut height = 0;
            let tree_height = u64::BITS - merkle_tree_index.leading_zeros() - 1;
            let mut ret = Vec::with_capacity(tree_height as usize);
            while merkle_tree_index > 1 {
                let is_left_sibling = merkle_tree_index & 1 == 0;
                let height_pow = 1u64 << (height + 1);
                let as_1_or_minus_1: u64 = (2 * i64::from(is_left_sibling) - 1) as u64;
                let signed_height_pow = height_pow.wrapping_mul(as_1_or_minus_1);
                let sibling = node_index
                    .wrapping_add(signed_height_pow)
                    .wrapping_sub(as_1_or_minus_1);

                node_index += 1 << ((height + 1) * u32::from(is_left_sibling));

                ret.push(sibling);
                merkle_tree_index >>= 1;
                height += 1;
            }

            debug_assert_eq!(tree_height, ret.len() as u32, "Allocation must be optimal");

            ret
        }

        assert!(
            num_leafs <= self.num_leafs().await,
            "Cannot find membership proofs relative to bigger MMR"
        );

        let node_indices = auth_path_node_indices(num_leafs, leaf_index);
        let ap_elements = self.digests.get_many(&node_indices).await;

        MmrMembershipProof {
            authentication_path: ap_elements,
        }
    }

    /// Return membership proof
    pub async fn prove_membership_async(&self, leaf_index: u64) -> MmrMembershipProof {
        // A proof consists of an authentication path
        // and a list of peaks
        let num_leafs = self.num_leafs().await;
        assert!(
            leaf_index < num_leafs,
            "Cannot prove membership of leaf outside of range. Got leaf_index {leaf_index}. Leaf count is {}", self.num_leafs().await
        );

        let node_index = shared_advanced::leaf_index_to_node_index(leaf_index);
        let (_, own_index_into_peaks_list) =
            leaf_index_to_mt_index_and_peak_index(leaf_index, num_leafs);
        let (_, peak_indices) = get_peak_heights_and_peak_node_indices(num_leafs);
        let num_nodes = self.digests.len().await;
        let sibling_indices = get_authentication_path_node_indices(
            node_index,
            peak_indices[own_index_into_peaks_list as usize],
            num_nodes,
        )
        .unwrap();

        let authentication_path = self.digests.get_many(&sibling_indices).await;

        MmrMembershipProof::new(authentication_path)
    }

    /// Returns the right-most leaf of the MMR, the leaf that was added the
    /// latest.
    pub(crate) async fn get_latest_leaf(&self) -> Option<Digest> {
        if self.is_empty().await {
            return None;
        }

        let node_index = self.digests.len().await - 1;
        let (_, height) = shared_advanced::right_lineage_length_and_own_height(node_index);
        let node_index = node_index - u64::from(height);

        Some(self.digests.get(node_index).await)
    }

    /// Remove the last leaf from the archival MMR
    pub async fn remove_last_leaf_async(&mut self) -> Option<Digest> {
        if self.is_empty().await {
            return None;
        }

        let node_index = self.digests.len().await - 1;
        let mut ret = self.digests.pop().await.unwrap();
        let (_, mut height) = shared_advanced::right_lineage_length_and_own_height(node_index);
        while height > 0 {
            ret = self.digests.pop().await.unwrap();
            height -= 1;
        }

        Some(ret)
    }

    /// Remove the last leafs of the MMR such that only the specified number
    /// of leafs remain. If initial number of leafs is less than requested,
    /// this MMR is not mutated.
    pub(crate) async fn prune_to_num_leafs(&mut self, num_leafs: u64) {
        let index_of_last_removal = leaf_index_to_node_index(num_leafs);

        while self.digests.len().await > index_of_last_removal {
            // TODO: It would be faster to be able to prune here,
            self.digests.pop().await.unwrap();
        }
    }
}

impl ArchivalMmr<DbtVec<Digest>> {
    /// Delete ephemeral (cache) values, without persisting them.
    ///
    /// Can be used to roll-back ephemeral values to a persisted state.
    pub(crate) async fn delete_cache(&mut self) {
        self.digests.delete_cache().await;
    }
}
