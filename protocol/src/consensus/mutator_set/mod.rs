use std::error::Error;
use std::fmt;

use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;

use self::addition_record::AdditionRecord;
use crate::consensus::mutator_set::shared::BATCH_SIZE;

pub mod active_window;
pub mod addition_record;
pub mod authenticated_item;
pub mod mmra_and_membership_proofs;
pub mod ms_membership_proof;
pub mod msa_and_records;
pub mod mutator_set_accumulator;
pub mod removal_record;
pub mod root_and_paths;
pub mod shared;

impl Error for MutatorSetError {}

impl fmt::Display for MutatorSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MutatorSetError {
    RequestedAoclAuthPathOutOfBounds((u64, u64)),
    RequestedSwbfAuthPathOutOfBounds((u64, u64)),
    MutatorSetIsEmpty,
    AbsoluteRemovalIndexIsFutureIndex {
        current_max_chunk_index: u64,
        saw_chunk_index: u64,
    },
    AbsoluteIndexExceedsTheoreticalBound,
    RequestedAoclAuthPathNotContainedInResponse {
        request_aocl_leaf_index: u64,
    },
}

/// Generates an addition record from an item and explicit random-
/// ness. The addition record is itself a commitment to the item.
pub fn commit(item: Digest, sender_randomness: Digest, receiver_digest: Digest) -> AdditionRecord {
    let canonical_commitment =
        Tip5::hash_pair(Tip5::hash_pair(item, sender_randomness), receiver_digest);

    AdditionRecord::new(canonical_commitment)
}

/// Converts a number of leafs in the AOCL into a number of leafs in the
/// SWBF-MMR.
///
/// Common pitfall. The difference by one reflects the timing mismatch: the
/// window slides immediately prior to adding the first element of the new
/// batch, *not* after adding the last element of a batch. The subtraction must
/// be saturating because the empty mutator set is the exception to this rule:
/// no window slides occur when the first element is added to the first batch.
///
/// |             # leafs AOCL              | # leafs SWBFI |
/// |:-------------------------------------:|:-------------:|
/// |                                     0 |             0 |
/// |                        BATCH_SIZE - 1 |             0 |
/// |                            BATCH_SIZE |             0 |
/// |                        BATCH_SIZE + 1 |             1 |
/// |                        k * BATCH_SIZE |         k - 1 |
/// | k * BATCH_SIZE + {1, ..., BATCH_SIZE} |             k |
///
pub fn aocl_to_swbfi_leaf_counts(aocl_leaf_count: u64) -> u64 {
    aocl_leaf_count.saturating_sub(1) / u64::from(BATCH_SIZE)
}
