use std::collections::HashMap;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::prelude::Sponge;

use super::super::mutator_set_accumulator::MutatorSetAccumulator;
use super::super::shared::NUM_TRIALS;
use super::MutatorSetError;
use crate::mutator_set::shared::BATCH_SIZE;
use crate::mutator_set::shared::CHUNK_SIZE;
use crate::mutator_set::shared::WINDOW_SIZE;
use crate::mutator_set::shared::indices_to_hash_map;

/// A set of 45 (=[`NUM_TRIALS`]) sliding window Bloom filter bit indices.
/// The indices live in a window that is at most 2^20 (=[`WINDOW_SIZE`]) wide.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, BFieldCodec, TasmObject, Hash, Serialize, Deserialize,
)]
pub struct AbsoluteIndexSet {
    minimum: u128,

    /// Distances of the indices relative to the minimum. Guaranteed to be in
    /// the range [0; 2^{20}-1].
    #[serde(with = "serde_arrays")]
    distances: [u32; NUM_TRIALS as usize],
}

impl GetSize for AbsoluteIndexSet {
    fn get_stack_size() -> usize {
        std::mem::size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        self.minimum.get_heap_size() + self.distances.get_heap_size()
    }

    fn get_size(&self) -> usize {
        Self::get_stack_size() + GetSize::get_heap_size(self)
    }
}

impl AbsoluteIndexSet {
    /// Construct a new [`AbsoluteIndexSet`] from an array of [`NUM_TRIALS`]-
    /// many `u128`s.
    ///
    /// # Panics
    ///
    ///  - If the array contains elements that are apart by more than
    ///    [`WINDOW_SIZE`].
    pub fn new(absolute_indices: [u128; NUM_TRIALS as usize]) -> Self {
        let minimum = *(absolute_indices.iter().min().unwrap());
        let distances: [u32; NUM_TRIALS as usize] = absolute_indices
            .into_iter()
            .map(|x| x - minimum)
            .map(|x| {
                if x >= WINDOW_SIZE.into() {
                    panic!(
                        "indices must lie less than WINDOW_SIZE apart, but got a distance of {x}"
                    );
                } else {
                    x
                }
            })
            .map(u32::try_from)
            .map(Result::<_, _>::unwrap)
            .collect_vec()
            .try_into()
            .unwrap();

        Self { minimum, distances }
    }

    /// Get the (absolute) indices for removing this item from the mutator set.
    pub fn compute(
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        aocl_leaf_index: u64,
    ) -> Self {
        let batch_index: u128 = u128::from(aocl_leaf_index) / u128::from(BATCH_SIZE);
        let batch_offset: u128 = batch_index * u128::from(CHUNK_SIZE);
        let leaf_index_bfes = aocl_leaf_index.encode();
        let input = [
            item.encode(),
            sender_randomness.encode(),
            receiver_preimage.encode(),
            leaf_index_bfes,
        ]
        .concat();

        let mut sponge = Tip5::init();
        sponge.pad_and_absorb_all(&input);
        let relative_indices = sponge.sample_indices(WINDOW_SIZE, NUM_TRIALS as usize);
        let minimum = *(relative_indices.iter().min().unwrap());
        let distances: [u32; NUM_TRIALS as usize] = relative_indices
            .into_iter()
            .map(|x| x - minimum)
            .collect_vec()
            .try_into()
            .unwrap();

        Self {
            minimum: u128::from(minimum) + batch_offset,
            distances,
        }
    }

    pub fn to_vec(self) -> Vec<u128> {
        self.to_array().to_vec()
    }

    pub fn to_array(self) -> [u128; NUM_TRIALS as usize] {
        // Saturating add to guard overflow caused by malicious absolute index
        // sets. Malicious absolute index sets will not have a valid proof, so
        // there is no risk of applying such objects to the mutator set.
        self.distances
            .map(|x| u128::from(x).saturating_add(self.minimum))
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = u128> + '_ {
        let min = self.minimum;
        self.distances
            .iter()
            .map(move |&d| min.saturating_add(u128::from(d)))
    }

    /// Split the [`AbsoluteIndexSet`] into two parts, one for chunks in the
    /// inactive part of the Bloom filter and another one for chunks in the
    /// active part of the Bloom filter.
    ///
    /// Returns an error if a removal index is a future value, i.e. one that's
    /// not yet covered by the active window.
    #[expect(clippy::type_complexity)]
    pub fn split_by_activity(
        &self,
        mutator_set: &MutatorSetAccumulator,
    ) -> Result<(HashMap<u64, Vec<u128>>, Vec<u128>), MutatorSetError> {
        let (aw_chunk_index_min, aw_chunk_index_max) = mutator_set.active_window_chunk_interval();
        let (inactive, active): (HashMap<_, _>, HashMap<_, _>) =
            indices_to_hash_map(&self.to_array())
                .into_iter()
                .partition(|&(chunk_index, _)| chunk_index < aw_chunk_index_min);

        if let Some(chunk_index) = active.keys().find(|&&k| k > aw_chunk_index_max) {
            return Err(MutatorSetError::AbsoluteRemovalIndexIsFutureIndex {
                current_max_chunk_index: aw_chunk_index_max,
                saw_chunk_index: *chunk_index,
            });
        }

        let active = active.into_values().flatten().collect_vec();

        Ok((inactive, active))
    }

    /// Return the range as a min/max pair (both inclusive) from which the
    /// absolute index set could have come from.
    ///
    /// The return value refers to the AOCL leaf indices from which the
    /// absolute index set could have been derived. In other words, this
    /// function returns the range of possible AOCL leaf indices that this set
    /// of Bloom filter indices spends. So after applying this index set to the
    /// mutator set, an AOCL leaf in this range will have been spent.
    ///
    /// Does not take the actual length of the AOCL into account, so a caller
    /// may want to further restrict the maximum in this range to the actual,
    /// current length of the AOCL.
    pub fn aocl_range(&self) -> Result<(u64, u64), MutatorSetError> {
        let max_offset: u128 = (*self.distances.iter().max().unwrap()).into();
        if max_offset >= u128::from(WINDOW_SIZE) {
            return Err(MutatorSetError::AbsoluteIndexExceedsTheoreticalBound);
        }

        let max_bf_index = max_offset + self.minimum;
        let min_active_window_start_on_insertion = (max_bf_index
            .saturating_sub(u128::from(WINDOW_SIZE) - 1))
        .next_multiple_of(u128::from(CHUNK_SIZE));
        let Ok(min_batch_index_on_insertion): Result<u64, _> =
            (min_active_window_start_on_insertion / (u128::from(CHUNK_SIZE))).try_into()
        else {
            return Err(MutatorSetError::AbsoluteIndexExceedsTheoreticalBound);
        };

        let Some(min_aocl_index) = min_batch_index_on_insertion.checked_mul(u64::from(BATCH_SIZE))
        else {
            return Err(MutatorSetError::AbsoluteIndexExceedsTheoreticalBound);
        };

        let min_bf_index = self.minimum;

        let max_active_window_end_on_insertion = (min_bf_index + (u128::from(WINDOW_SIZE)) + 1)
            .next_multiple_of(u128::from(CHUNK_SIZE))
            - u128::from(CHUNK_SIZE);

        let Ok(max_batch_index_on_insertion): Result<u64, _> = ((max_active_window_end_on_insertion
            .saturating_sub(u128::from(WINDOW_SIZE)))
            / (u128::from(CHUNK_SIZE)))
        .try_into() else {
            return Err(MutatorSetError::AbsoluteIndexExceedsTheoreticalBound);
        };

        let Some(max_aocl_index) = max_batch_index_on_insertion
            .checked_mul(u64::from(BATCH_SIZE))
            .and_then(|prod| prod.checked_add(u64::from(BATCH_SIZE) - 1))
        else {
            return Err(MutatorSetError::AbsoluteIndexExceedsTheoreticalBound);
        };

        Ok((min_aocl_index, max_aocl_index))
    }
}
