use itertools::Itertools;
use tasm_lib::prelude::Digest;

use super::ms_membership_proof::MsMembershipProof;
use super::mutator_set_accumulator::MutatorSetAccumulator;
use super::removal_record::RemovalRecord;

/// A [`MutatorSetAccumulator`] with matching [`RemovalRecord`]s.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MsaAndRecords {
    pub mutator_set_accumulator: MutatorSetAccumulator,

    /// Not packed removal records
    removal_records: Vec<RemovalRecord>,
    pub membership_proofs: Vec<MsMembershipProof>,
}

impl MsaAndRecords {
    pub fn unpacked_removal_records(&self) -> Vec<RemovalRecord> {
        self.removal_records.clone()
    }

    pub fn verify(&self, items: &[Digest]) -> bool {
        let all_removal_records_can_remove = self
            .removal_records
            .iter()
            .all(|rr| self.mutator_set_accumulator.can_remove(rr));
        let all_membership_proofs_are_valid = self
            .membership_proofs
            .iter()
            .zip_eq(items.iter())
            .all(|(mp, item)| self.mutator_set_accumulator.verify(*item, mp));

        // Verify that mutator set has expected number of elements in Bloom
        // filter MMR, and other qualities of the mutator set.
        let ms_is_consistent = self.mutator_set_accumulator.is_consistent();

        all_removal_records_can_remove && all_membership_proofs_are_valid && ms_is_consistent
    }
}
