use std::collections::HashMap;
use std::collections::HashSet;

use itertools::Itertools;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::twenty_first::prelude::MerkleTree;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::get_peak_heights;
use tasm_lib::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;
use thiserror::Error;

use super::AbsoluteIndexSet;
use super::RemovalRecord;
use super::chunk::Chunk;
use super::chunk::ChunkUnpackError;
use super::chunk_dictionary::ChunkDictionary;
use crate::mutator_set::aocl_to_swbfi_leaf_counts;
use crate::mutator_set::shared::BATCH_SIZE;
use crate::mutator_set::shared::CHUNK_SIZE;

/// A list of [`RemovalRecords`](crate::mutator_set::removal_record::RemovalRecord)s
/// without redundant Merkle authentication data.
///
/// This is considered a trusted data structure as it's never transmitted over
/// the network and is only ever used internally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovalRecordList {
    /// The unchanged absolute indices of the (unpacked) removal records.
    index_sets: Vec<AbsoluteIndexSet>,

    /// One authentication structure for each tree in the MMR.
    /// If tree has no chunks, the empty list is inserted as element.
    /// The empty list is *also* inserted for the tree of height 0, if it
    /// exists. The list is sorted by ascending tree height, *i.e.*, smallest
    /// tree first.
    authentication_structures: Vec<Vec<Digest>>,

    /// ascending order by chunk index
    chunks: Vec<Chunk>,

    /// The number of leafs in the AOCL at the point in time when the removal
    /// records are supposed to be valid. If the number is not known exactly,
    /// this field is populated with a viable estimate, meaning that the number
    /// is set such that the algorithm should work. More precisely, viable means
    /// that it explains why the SWBF authentication structures have the lengths
    /// they do. If the removal records are correct, it is a lower bound on the
    /// number of AOCL leafs in the mutator set.
    num_leafs_aocl: u64,
}

#[derive(Debug, Error)]
pub enum RemovalRecordListUnpackError {
    #[error("inner decoding error: {0}")]
    InnerDecodingFailure(#[from] Box<dyn core::error::Error + Send + Sync>),
    #[error("Absolute index value cannot exceed 74 bits")]
    AbsoluteIndexTooBig,
    #[error("Illegal tree height: {tree_height}")]
    IllegalTreeHeight { tree_height: u64 },
    #[error("List of tree heights contains duplicates.")]
    DuplicateTreeHeights,
    #[error("Incorrectly sorted tree heights.")]
    IncorrectlySortedTreeHeights,
    #[error("removal records are mutually inconsistent: {0}")]
    Inconsistency(RemovalRecordListInconsistency),
}

#[derive(Debug, Error, PartialEq, Eq)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum RemovalRecordListInconsistency {
    #[error(
        "number of chunks ({num_chunks}) is inconsistent with number of chunk indices ({num_chunk_indices})"
    )]
    Chunks {
        num_chunk_indices: usize,
        num_chunks: usize,
    },
    #[error(
        "number of authentication structures {num_authentication_structures} is inconsistent with the number of trees {total_num_trees}"
    )]
    AuthenticationStructureCount {
        num_authentication_structures: usize,
        total_num_trees: usize,
    },
    #[error(
        "observed lengths of authentication structures ([{}]) does not match with expectation ([{}])",
        observed_authentication_structure_lengths.iter().join(", "),
        expected_authentication_structure_lengths.iter().join(", ")
    )]
    AuthenticationStructureLength {
        expected_authentication_structure_lengths: Vec<usize>,
        observed_authentication_structure_lengths: Vec<usize>,
    },
}

impl RemovalRecordList {
    /// When there are more Chunks than trees, this value is used for the tree
    /// height to indicate it (tree height and authentication structure) should
    /// be ignored.
    const ENCODING_DELIMITER_IGNORE_TREE_HEIGHT: u64 = u64::MAX;

    /// When there are more trees than Chunks, the tree heights are offset by
    /// this value to indicate that the associated Chunk should be ignored. Note
    /// that the associated authentication structure must be empty in this case.
    const ENCODING_TREE_HEIGHT_OFFSET: u64 = 64;

    /// Convert a `Vec` of [`RemovalRecord`]s to a [`RemovalRecordList`].
    ///
    /// The difference between this method and [`Self::convert_from_vec`] is the
    /// second argument, the number of leafs in the AOCL. Producing
    /// this estimate is time-consuming and error-prone (tests notwithstanding),
    /// so it is better to avoid that step if possible.
    ///
    /// This function runs on trusted inputs. It is the caller's responsibility
    /// to ensure that all removal records are valid and mutually consistent.
    ///
    /// # Panics
    ///
    ///  - May (probably) panic if removal records are invalid or mutually
    ///    inconsistent.
    pub fn from_removal_records(removal_records: Vec<RemovalRecord>, num_leafs_aocl: u64) -> Self {
        let num_leafs_swbfi = aocl_to_swbfi_leaf_counts(num_leafs_aocl);
        let all_tree_heights = get_peak_heights(num_leafs_swbfi);
        let index_sets = removal_records
            .iter()
            .map(|rr| rr.absolute_indices)
            .collect_vec();

        let mut mmr_leaf_indices = HashSet::<(u32, u64)>::new();
        let mut chunks = HashMap::<u64, Chunk>::new();
        for removal_record in &removal_records {
            for target_chunk in removal_record.target_chunks.iter() {
                let (chunk_index, (chunk_mmr_mp, chunk)) = target_chunk;
                if let Some(chunk_already_present) = chunks.insert(*chunk_index, chunk.clone()) {
                    assert_eq!(
                        chunk_already_present,
                        chunk.clone(),
                        "removal records are inconsistent: they have distinct chunks for the same chunk index"
                    );
                }
                let tree_height_according_to_authentication_path =
                    chunk_mmr_mp.authentication_path.len() as u32;
                let (_, peak_index) =
                    leaf_index_to_mt_index_and_peak_index(*chunk_index, num_leafs_swbfi);
                let tree_height_according_to_num_leafs = all_tree_heights[peak_index as usize];
                assert_eq!(
                    tree_height_according_to_num_leafs,
                    tree_height_according_to_authentication_path,
                    "removal records are inconsistent: authentication path length disagrees with tree heights according to num leafs"
                );
                mmr_leaf_indices
                    .insert((tree_height_according_to_authentication_path, *chunk_index));
            }
        }

        // compile sparse view of MMR
        let mut sparse_mmr: HashMap<_, Digest> = HashMap::new();
        for removal_record in removal_records {
            for target_chunk in removal_record.target_chunks {
                let (chunk_index, (chunk_mmr_mp, chunk)) = target_chunk;

                // Because of previous assert, we can trust this value for the
                // tree height.
                let tree_height = chunk_mmr_mp.authentication_path.len() as u32;

                let mut running_digest = Tip5::hash(&chunk);
                let (mut merkle_node_index, _) =
                    leaf_index_to_mt_index_and_peak_index(chunk_index, num_leafs_swbfi);

                for sibling_digest in chunk_mmr_mp.authentication_path {
                    if let Some(kickout) =
                        sparse_mmr.insert((tree_height, merkle_node_index), running_digest)
                    {
                        assert_eq!(
                            kickout, running_digest,
                            "removal records are inconsistent: they disagree about internal nodes in the SWBFI MMR"
                        );
                    }

                    if let Some(kickout) =
                        sparse_mmr.insert((tree_height, merkle_node_index ^ 1), sibling_digest)
                    {
                        assert_eq!(
                            kickout, sibling_digest,
                            "removal records are inconsistent: they disagree about internal nodes in the SWBFI MMR"
                        );
                    }

                    if merkle_node_index & 1 == 0 {
                        running_digest = Tip5::hash_pair(running_digest, sibling_digest);
                    } else {
                        running_digest = Tip5::hash_pair(sibling_digest, running_digest);
                    }
                    merkle_node_index >>= 1;
                }

                if let Some(kickout) =
                    sparse_mmr.insert((tree_height, merkle_node_index), running_digest)
                {
                    assert_eq!(
                        kickout, running_digest,
                        "removal records are inconsistent: they disagree about root nodes in the SWBFI MMR"
                    );
                }
            }
        }

        // extract authentication structures
        let mut authentication_structures = vec![];
        for tree_height in all_tree_heights.into_iter().sorted() {
            let mmr_leaf_indices_for_this_tree = mmr_leaf_indices
                .iter()
                .filter(|(height, _index)| *height == tree_height)
                .map(|(_height, index)| *index)
                .collect_vec();
            let merkle_leaf_indices_for_this_tree = mmr_leaf_indices_for_this_tree
                .iter()
                .map(|&li| li & ((1 << tree_height) - 1))
                .collect_vec();
            let node_indices_in_authentication_structure =
                MerkleTree::authentication_structure_node_indices(
                    1_u64 << tree_height,
                    &merkle_leaf_indices_for_this_tree,
                )
                .expect("tree height is guaranteed to be larger than log of biggest index")
                .collect_vec();

            let mut authentication_structure = vec![];
            for node_index in node_indices_in_authentication_structure {
                let digest = *sparse_mmr.get(&(tree_height, node_index)).unwrap();
                authentication_structure.push(digest);
            }
            authentication_structures.push(authentication_structure);
        }

        // coalesce all chunks, in order
        let chunks = chunks
            .into_iter()
            .sorted_by_key(|(chunk_index, _chunk)| *chunk_index)
            .coalesce(|previous, current| {
                if previous.0 == current.0 {
                    assert_eq!(
                        previous.1.clone(),
                        current.1.clone(),
                        "removal records are inconsistent: they disagree about chunks with the same index"
                    );
                    Ok(previous)
                } else {
                    Err((previous, current))
                }
            })
            .map(|(_index, chunk)| chunk)
            .collect_vec();

        Self {
            index_sets,
            authentication_structures,
            chunks,
            num_leafs_aocl,
        }
    }

    /// Compute a minimum viable lower bound on the current number of leafs in
    /// the AOCL given context inferred from removal records, where "current"
    /// means the point in time when the removal records are supposed to be
    /// valid.
    ///
    /// The lower bound is *viable*: it suffices to "explain" why the given
    /// chunks are present and why the authentication paths have the lengths
    /// they do.
    ///
    /// The lower bound is *minimal*: no smaller number satisfies the above
    /// criteria.
    ///
    /// # Panics
    ///
    ///  - If the observed authentication path lengths is not sorted in
    ///    descending order (*i.e.*, largest first).
    ///  - If the observed authentication path lengths contains duplicates.
    fn estimate_num_leafs_aocl(
        observed_chunk_indices: &[u64],
        observed_authentication_path_lengths: &[usize],
    ) -> u64 {
        let largest_observed_chunk_index =
            observed_chunk_indices.iter().copied().max().unwrap_or(0);
        let mut swbfi_leaf_count_estimate = largest_observed_chunk_index;

        assert!(
            observed_authentication_path_lengths
                .iter()
                .rev()
                .is_sorted(),
            "observed authentication path lengths were not sorted: {}",
            observed_authentication_path_lengths.iter().join(", ")
        );
        assert_eq!(
            observed_authentication_path_lengths.iter().dedup().count(),
            observed_authentication_path_lengths.len(),
            "observed authentication path lengths contains duplicates."
        );
        for tree_height in observed_authentication_path_lengths {
            let tree_width = 1u64 << tree_height;
            if swbfi_leaf_count_estimate & tree_width == 0 {
                // set the bit in question
                swbfi_leaf_count_estimate |= tree_width;

                // zero all subsequent bits
                swbfi_leaf_count_estimate &= u64::MAX - (tree_width - 1);
            }
        }

        swbfi_leaf_count_estimate * u64::from(BATCH_SIZE) + 1
    }

    /// Compute a [`ChunkDictionary`], densely encoding all the data about
    /// Chunks, authentication structures, and tree heights. Phrased
    /// differently, compute a [`ChunkDictionary`] that densely encodes all the
    /// information contained in [`Self`] *except* the absolute index sets.
    ///
    /// Should only be used on locally derived [`RemovalRecordList`].
    ///
    /// # Panics
    ///
    ///  - If self is inconsistent.
    fn compressed_chunk_dictionary(&self) -> ChunkDictionary {
        use itertools::EitherOrBoth::Both;
        use itertools::EitherOrBoth::Left;
        use itertools::EitherOrBoth::Right;

        let num_swbf_leafs = aocl_to_swbfi_leaf_counts(self.num_leafs_aocl);
        let tree_heights = get_peak_heights(num_swbf_leafs)
            .into_iter()
            .map(u64::from)
            .rev()
            .collect_vec();

        let chunk_indices = self.observed_chunk_indices();
        assert_eq!(chunk_indices.len(), self.chunks.len());

        let tree_heights_and_authentication_structures = tree_heights.into_iter().zip_eq(
            self.authentication_structures
                .iter()
                .cloned()
                .map(MmrMembershipProof::new),
        );

        let chunk_dictionary = tree_heights_and_authentication_structures
            .zip_longest(self.chunks.iter().map(Chunk::pack))
            .map(|x| match x {
                Both((tree_height, membership_proof), packed_chunk) => {
                    (tree_height, (membership_proof, packed_chunk))
                }
                Left((tree_height, membership_proof)) => (
                    tree_height + Self::ENCODING_TREE_HEIGHT_OFFSET,
                    (membership_proof, Chunk::empty_chunk()),
                ),
                Right(packed_chunk) => (
                    Self::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT,
                    (MmrMembershipProof::new(vec![]), packed_chunk),
                ),
            });
        ChunkDictionary {
            dictionary: chunk_dictionary.collect_vec(),
        }
    }

    /// Encodes a [`RemovalRecordList`] as a `Vec` of [`RemovalRecord`].
    ///
    /// The encoding follows the following rules:
    ///  - The absolute index sets are identical. There is no packing
    ///    of absolute index sets.
    ///  - The first removal record is the only one that contains a non-empty
    ///    chunks dictionary. This dictionary contains tuples of the form
    ///    ```notest
    ///     (
    ///         tree_height: u64,
    ///         (
    ///             authentication_structure: Vec<Digest>,
    ///             chunk: Chunk
    ///         )
    ///     )
    ///     ```
    ///     .
    ///  - If there are more Chunks than trees, tree height
    ///    [`Self::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT`] is used to indicate
    ///    that the associated authentication structure should be ignored. The
    ///    authentication structure will in this case be empty.
    ///  - If there are more trees than Chunks, the tree height is offset by
    ///    [`Self::ENCODING_TREE_HEIGHT_OFFSET`], and the Chunk is empty.
    ///  - All chunks of the [`RemovalRecordList`] are present exactly once. The
    ///    order is the same between self and this dictionary.
    ///  - The authentication structures in this dictionary are the same as
    ///    those from the like-named field of `Self`. The number of
    ///    authentication structures is guaranteed to be equal to the number of
    ///    trees inthe SWBFI MMR, except if there are more Chunks than trees.
    ///    The authentication structures do not correlate with the chunks.
    ///  - The tree heights *do* correlate with the authentication structures:
    ///    they indicate the height of the tree that the authentication
    ///    structure is for.
    ///
    /// See also: [`Self::decode_from_vec`], which computes the inverse of this
    /// function.
    fn encode_as_vec(&self) -> Vec<RemovalRecord> {
        let chunk_dictionaries = vec![self.compressed_chunk_dictionary()]
            .into_iter()
            .chain(std::iter::repeat(ChunkDictionary::empty()));

        self.index_sets
            .iter()
            .copied()
            .zip(chunk_dictionaries)
            .map(|(absolute_indices, target_chunks)| RemovalRecord {
                absolute_indices,
                target_chunks,
            })
            .collect_vec()
    }

    /// Return the list of unique leaf indices into the SWBFI MMR, corresponding
    /// to Chunks referenced in the absolute index sets, in ascending order.
    fn observed_chunk_indices(&self) -> Vec<u64> {
        let swbfi_num_leafs = aocl_to_swbfi_leaf_counts(self.num_leafs_aocl);
        let window_start = u128::from(swbfi_num_leafs) * u128::from(CHUNK_SIZE);
        self.index_sets
            .iter()
            .flat_map(|ais| ais.to_vec())
            .filter(|ai| *ai < window_start)
            .map(|ai| ai / u128::from(CHUNK_SIZE))
            .map(|u| u64::try_from(u).unwrap())
            .unique()
            .sorted()
            .collect_vec()
    }

    /// Computes consistency, with an error code in case of failure.
    ///
    /// Consistency is defined relative to a set of observed chunk indices,
    /// which itself is inferred from the set of all absolute indices after
    /// filtering for location outside of the active window. Relative to this
    /// set of observed chunk indices, consistency is defined as:
    ///  1. the cardinality of the set of observed chunk indices agrees with the
    ///     length of the `chunks` list; and
    ///  2. the number of authentication structures matches with the number of
    ///     peaks; and
    ///  3. for each tree in the MMR, the length of the authentication structure
    ///     matches with the given leaf indices.
    ///
    /// Error type [`RemovalRecordListInconsistency`] has one variant for every
    /// failure case.
    fn validate_consistency(&self) -> Result<(), RemovalRecordListInconsistency> {
        let observed_chunk_indices = self.observed_chunk_indices();

        // 1) cardinality must match
        if observed_chunk_indices.len() != self.chunks.len() {
            return Err(RemovalRecordListInconsistency::Chunks {
                num_chunk_indices: observed_chunk_indices.len(),
                num_chunks: self.chunks.len(),
            });
        }

        // compile a usable view of the MMR's known leafs
        let mut mmr_view = HashSet::new();
        let swbfi_num_leafs = aocl_to_swbfi_leaf_counts(self.num_leafs_aocl);
        let all_peak_heights = get_peak_heights(swbfi_num_leafs);
        for chunk_index in observed_chunk_indices {
            let (merkle_leaf_index, peak_index) =
                leaf_index_to_mt_index_and_peak_index(chunk_index, swbfi_num_leafs);
            let merkle_leaf_index =
                merkle_leaf_index & (u64::MAX ^ (1 << all_peak_heights[peak_index as usize]));
            mmr_view.insert((peak_index, merkle_leaf_index));
        }
        let active_peak_indices = mmr_view.iter().map(|(pi, _mli)| *pi).unique().collect_vec();
        let merkle_leaf_indices_by_tree = all_peak_heights
            .iter()
            .enumerate()
            .map(|(peak_index, peak_height)| {
                let leaf_indices_for_this_tree = mmr_view
                    .iter()
                    .filter(|(pi, _mli)| *pi == u32::try_from(peak_index).unwrap())
                    .map(|(_pi, mli)| *mli)
                    .collect_vec();
                assert!(
                    leaf_indices_for_this_tree
                        .iter()
                        .all(|li| *li < (1 << *peak_height))
                );
                leaf_indices_for_this_tree
            })
            .collect_vec();

        // Assert that number of active trees <= pop count of num leafs.
        // This fact follows from MMR code. (If not, we want to fail as quickly
        // as possible.)
        let total_num_trees = all_peak_heights.len();
        let num_active_trees = active_peak_indices.len();
        assert!(num_active_trees <= total_num_trees);

        // 2) correct number of authentication structures
        let num_authentication_structures = self.authentication_structures.len();
        if num_authentication_structures != total_num_trees {
            return Err(
                RemovalRecordListInconsistency::AuthenticationStructureCount {
                    num_authentication_structures,
                    total_num_trees,
                },
            );
        }

        // 3) for each tree, the authentication structure length is correct
        let expected_authentication_structure_lengths = all_peak_heights
            .into_iter()
            .zip(merkle_leaf_indices_by_tree)
            .map(|(ph, mlis)| {
                MerkleTree::authentication_structure_node_indices(1_u64 << ph, &mlis)
                    .unwrap_or_else(|_| {
                        panic!(
                            "tree height: {} / merkle leaf indices: [{}]",
                            ph,
                            mlis.iter().join(", ")
                        )
                    })
                    .len()
            })
            .sorted()
            .collect_vec();
        let observed_authentication_structure_lengths = self
            .authentication_structures
            .iter()
            .map(|auth_str| auth_str.len())
            .sorted()
            .collect_vec();
        if expected_authentication_structure_lengths != observed_authentication_structure_lengths {
            return Err(
                RemovalRecordListInconsistency::AuthenticationStructureLength {
                    expected_authentication_structure_lengths,
                    observed_authentication_structure_lengths,
                },
            );
        }

        Ok(())
    }

    /// Produce a [`RemovalRecordList`] by decoding a [`Vec`] of
    /// [`RemovalRecord`]. This function computes the inverse of
    /// [`Self::encode_as_vec`].
    fn decode_from_vec(
        removal_records: Vec<RemovalRecord>,
    ) -> Result<RemovalRecordList, RemovalRecordListUnpackError> {
        // This function is not allowed to panic as it's run on untrusted
        // input.
        let mut index_sets = vec![];
        let mut authentication_structures = vec![];
        let mut chunks = vec![];

        let mut tree_heights = vec![];
        for removal_record in removal_records.clone() {
            index_sets.push(removal_record.absolute_indices);
            for (tree_height, (mmr_authentication_path, chunk)) in
                removal_record.target_chunks.iter()
            {
                if *tree_height < Self::ENCODING_TREE_HEIGHT_OFFSET {
                    // Verify that tree heights are sorted correctly
                    if let Some(previous) = tree_heights.last()
                        && *previous > *tree_height
                    {
                        return Err(RemovalRecordListUnpackError::IncorrectlySortedTreeHeights);
                    }

                    // use both authentication structure and chunk
                    tree_heights.push(*tree_height);
                    authentication_structures
                        .push(mmr_authentication_path.authentication_path.clone());
                    let unpacked_chunk = chunk.try_unpack().map_err(Box::new).map_err(
                        |e: Box<ChunkUnpackError>| {
                            RemovalRecordListUnpackError::InnerDecodingFailure(e)
                        },
                    )?;
                    chunks.push(unpacked_chunk);
                } else if *tree_height < 2 * Self::ENCODING_TREE_HEIGHT_OFFSET {
                    // ignore chunk
                    let tree_height = *tree_height - Self::ENCODING_TREE_HEIGHT_OFFSET;
                    tree_heights.push(tree_height);
                    authentication_structures
                        .push(mmr_authentication_path.authentication_path.clone());
                } else if *tree_height == Self::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT {
                    // ignore tree
                    let unpacked_chunk = chunk.try_unpack().map_err(Box::new).map_err(
                        |e: Box<ChunkUnpackError>| {
                            RemovalRecordListUnpackError::InnerDecodingFailure(e)
                        },
                    )?;
                    chunks.push(unpacked_chunk);
                } else {
                    return Err(RemovalRecordListUnpackError::IllegalTreeHeight {
                        tree_height: *tree_height,
                    });
                }

                if tree_heights.len() != tree_heights.iter().unique().count() {
                    return Err(RemovalRecordListUnpackError::DuplicateTreeHeights);
                }
            }
        }

        let observed_chunk_indices =
            Self::observed_chunk_indices_from_index_sets(&index_sets, chunks.len())?;

        let num_leafs_aocl = Self::estimate_num_leafs_aocl(
            &observed_chunk_indices,
            &tree_heights.iter().map(|u| *u as usize).rev().collect_vec(),
        );

        let removal_record_list = Self {
            index_sets,
            authentication_structures,
            chunks,
            num_leafs_aocl,
        };

        removal_record_list
            .validate_consistency()
            .map_err(RemovalRecordListUnpackError::Inconsistency)?;

        Ok(removal_record_list)
    }

    /// Compute the first `number`-many chunk indices corresponding to the given
    /// absolute indices.
    fn observed_chunk_indices_from_index_sets(
        index_sets: &[AbsoluteIndexSet],
        number: usize,
    ) -> Result<Vec<u64>, RemovalRecordListUnpackError> {
        let mut chunk_indices: Vec<u64> = vec![];

        for index_set in index_sets {
            for abs_index in index_set.to_array() {
                let chunk_index = abs_index / u128::from(CHUNK_SIZE);
                let Ok(chunk_index) = u64::try_from(chunk_index) else {
                    return Err(RemovalRecordListUnpackError::AbsoluteIndexTooBig);
                };

                chunk_indices.push(chunk_index);
            }
        }

        chunk_indices.sort_unstable();
        chunk_indices.dedup();
        Ok(chunk_indices.into_iter().take(number).collect_vec())
    }

    /// Compress a [`Vec`] of [`RemovalRecord`]s densely by packing the same
    /// information into another, *smaller*, [`Vec`] of [`RemovalRecord`]s.
    pub fn pack(removal_records: Vec<RemovalRecord>) -> Vec<RemovalRecord> {
        let as_rr_list = Self::convert_from_vec(removal_records);
        as_rr_list.encode_as_vec()
    }

    /// Decompress a [`Vec`] of [`RemovalRecord`]s as packed by [`Self::pack`].
    /// Returns an error if the packing is invalid.
    ///
    /// Never panics, so this function is safe to run on untrusted input.
    pub fn try_unpack(
        removal_records: Vec<RemovalRecord>,
    ) -> Result<Vec<RemovalRecord>, RemovalRecordListUnpackError> {
        let as_removal_record_list = RemovalRecordList::decode_from_vec(removal_records)?;
        Ok(as_removal_record_list.convert_to_vec())
    }

    /// Convert a [`Vec`] of [`RemovalRecord`]s into a [`RemovalRecordList`],
    /// which is a denser representation of the same object. In particular,
    /// there is no loss of information (unless the input is malicious).
    ///
    /// This function assumes that the input is honest. Specifically, that the
    /// removal records are valid and mutually consistent.
    ///
    /// See also [`Self::convert_to_vec`], which computes the inverse of this
    /// function.
    ///
    /// # Panics
    ///
    ///  - May (probably) panic if the removal records are invalid or mutually
    ///    inconsistent.
    fn convert_from_vec(removal_records: Vec<RemovalRecord>) -> Self {
        let observed_chunk_indices = removal_records
            .iter()
            .flat_map(|rr| rr.target_chunks.indices_and_leafs())
            .map(|(idx, _leaf)| idx)
            .sorted()
            .dedup()
            .collect_vec();
        let authentication_path_lengths = removal_records
            .iter()
            .flat_map(|rr| rr.target_chunks.authentication_paths())
            .map(|ap| ap.authentication_path.len())
            .sorted()
            .rev()
            .dedup()
            .collect_vec();
        let num_leafs_aocl = RemovalRecordList::estimate_num_leafs_aocl(
            &observed_chunk_indices,
            &authentication_path_lengths,
        );

        RemovalRecordList::from_removal_records(removal_records, num_leafs_aocl)
    }

    /// Convert a [`RemovalRecordList`] to a (redundant) [`Vec`] of
    /// [`RemovalRecord`]s. This function computes the inverse of
    /// [`Self::convert_from_vec`].
    ///
    /// # Panics
    ///
    ///  - if `self` is inconsistent.
    fn convert_to_vec(self) -> Vec<RemovalRecord> {
        let num_leafs_swbfi = aocl_to_swbfi_leaf_counts(self.num_leafs_aocl);
        let all_tree_heights = get_peak_heights(num_leafs_swbfi);
        assert_eq!(
            all_tree_heights.len(),
            self.authentication_structures.len(),
            "expected one (possibly empty) authentication structure for each \
                tree in the MMR but got {} authentication structures and {} trees",
            self.authentication_structures.len(),
            all_tree_heights.len()
        );

        // populate sparse MMR with chunk hashes
        let mut sparse_mmr: HashMap<_, Digest> = HashMap::new();
        let active_window_start =
            u128::from(self.num_leafs_aocl) / u128::from(BATCH_SIZE) * u128::from(CHUNK_SIZE);
        let all_inactive_indices = self
            .index_sets
            .iter()
            .flat_map(|absolute_index_set| absolute_index_set.to_vec())
            .filter(|&absolute_index| absolute_index < active_window_start);
        let all_chunk_indices = all_inactive_indices
            .map(|absolute_index| {
                u64::try_from(absolute_index / u128::from(CHUNK_SIZE))
                    .expect("absolute indices can never be more than 76 bits")
            })
            .sorted()
            .dedup()
            .take(self.chunks.len())
            .collect_vec();
        let master_chunks_dictionary = all_chunk_indices
            .iter()
            .copied()
            .zip(self.chunks.iter().cloned())
            .collect::<HashMap<_, _>>();
        for (&chunk_index, chunk) in all_chunk_indices.iter().zip(self.chunks.iter()) {
            let chunk_hash = Tip5::hash(chunk);
            let (merkle_tree_node_index, peak_index) =
                leaf_index_to_mt_index_and_peak_index(chunk_index, num_leafs_swbfi);
            let height = all_tree_heights[peak_index as usize];
            sparse_mmr.insert((height, merkle_tree_node_index), chunk_hash);
        }

        // populate sparse MMR with authentication structures
        for (tree_height, authentication_structure) in all_tree_heights
            .iter()
            .sorted()
            .zip_eq(&self.authentication_structures)
        {
            let leaf_indices_for_this_tree = sparse_mmr
                .keys()
                .filter(|(height, _node_index)| *height == *tree_height)
                .map(|(_height, node_index)| *node_index ^ (1 << *tree_height))
                .collect_vec();

            let node_indices_for_authentication_structure =
                MerkleTree::authentication_structure_node_indices(
                    1 << *tree_height,
                    &leaf_indices_for_this_tree,
                )
                .expect(
                    "all leaf indices are guaranteed to be smaller (in log terms) than tree height",
                )
                .collect_vec();
            assert_eq!(
                authentication_structure.len(),
                node_indices_for_authentication_structure.len(),
                "Have authentication structure of len {} but node indices of len {};\nnode indices are: [{}]",
                authentication_structure.len(),
                node_indices_for_authentication_structure.len(),
                node_indices_for_authentication_structure.iter().join(", ")
            );
            for (node_index, node_hash) in node_indices_for_authentication_structure
                .into_iter()
                .zip_eq(authentication_structure.iter())
            {
                sparse_mmr.insert((*tree_height, node_index), *node_hash);
            }
        }

        assert!(
            sparse_mmr
                .values()
                .all(|v| v.to_hex().chars().take(8).collect::<String>() != "be450642")
        );

        // populate sparse MMR by completing families with parents whenever both
        // children are already present
        for &tree_height in &all_tree_heights {
            loop {
                let current_tree_indices = sparse_mmr
                    .keys()
                    .filter(|(height, _node_index)| *height == tree_height)
                    .map(|(_height, node_index)| *node_index)
                    .sorted()
                    .collect_vec();
                let absent_parent_nodes = current_tree_indices
                    .iter()
                    .tuple_windows()
                    .filter(|(nil, nir)| **nil == **nir ^ 1)
                    .map(|(nil, _nir)| *nil >> 1)
                    .filter(|ni| !current_tree_indices.contains(ni))
                    .collect_vec();
                if absent_parent_nodes.is_empty() {
                    break;
                }
                for parent in absent_parent_nodes {
                    let left_child = parent << 1;
                    let right_child = left_child ^ 1;
                    let left_digest = *sparse_mmr
                        .get(&(tree_height, left_child))
                        .expect("presence of left child was verified already");
                    let right_digest = *sparse_mmr
                        .get(&(tree_height, right_child))
                        .expect("presence of right child was verified already");
                    let parent_digest = Tip5::hash_pair(left_digest, right_digest);
                    sparse_mmr.insert((tree_height, parent), parent_digest);
                }
            }
        }

        // Create removal records one by one
        let mut removal_records = vec![];
        for index_set in &self.index_sets {
            let chunk_indices = index_set
                .to_vec()
                .into_iter()
                .filter(|absolute_index| *absolute_index < active_window_start)
                .map(|absolute_index| absolute_index / u128::from(CHUNK_SIZE))
                .map(|u| u64::try_from(u).expect("absolute index can never be more than 72 bits"))
                .sorted()
                .dedup()
                .collect_vec();
            let mut target_chunks = vec![];
            for chunk_index in chunk_indices {
                let chunk = master_chunks_dictionary.get(&chunk_index).expect("master chunks dictionary should contain entries for all possible chunk indices");
                let (mut merkle_node_index, peak_index) =
                    leaf_index_to_mt_index_and_peak_index(chunk_index, num_leafs_swbfi);
                let tree_height = all_tree_heights[peak_index as usize];
                let mut authentication_path = vec![];
                while merkle_node_index != 1 {
                    let digest = sparse_mmr
                        .get(&(tree_height, merkle_node_index ^ 1))
                        .copied()
                        .unwrap_or_else(|| {
                            panic!(
                                "node with node index {} on authentication \
                                    path for tree of height {} must live in sparse \
                                    mmr dictionary, but that dicitonary only has \
                                    nodes with indices {} for that height",
                                merkle_node_index ^ 1,
                                tree_height,
                                sparse_mmr
                                    .iter()
                                    .filter(|((height, _node_index), _)| *height == tree_height)
                                    .map(|((_height, node_index), _)| *node_index)
                                    .sorted()
                                    .join(", ")
                            );
                        });
                    authentication_path.push(digest);
                    merkle_node_index >>= 1;
                }
                target_chunks.push((
                    chunk_index,
                    (
                        MmrMembershipProof {
                            authentication_path,
                        },
                        chunk.clone(),
                    ),
                ));
            }
            removal_records.push(RemovalRecord {
                absolute_indices: *index_set,
                target_chunks: ChunkDictionary::new(target_chunks),
            });
        }

        removal_records
    }
}

impl BFieldCodec for RemovalRecordList {
    type Error = BFieldCodecError;

    fn decode(sequence: &[BFieldElement]) -> Result<Box<Self>, Self::Error> {
        Ok(Box::new(
            Self::decode_from_vec(*Vec::<RemovalRecord>::decode(sequence)?)
                .map_err(Box::new)
                .map_err(|e: Box<RemovalRecordListUnpackError>| {
                    BFieldCodecError::InnerDecodingFailure(e)
                })?,
        ))
    }

    fn encode(&self) -> Vec<BFieldElement> {
        self.encode_as_vec().encode()
    }

    fn static_length() -> Option<usize> {
        None
    }
}
