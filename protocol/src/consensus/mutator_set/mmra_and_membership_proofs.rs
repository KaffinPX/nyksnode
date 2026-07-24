use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;

#[derive(Debug, Clone)]
pub struct MmraAndMembershipProofs {
    pub mmra: MmrAccumulator,
    pub membership_proofs: Vec<MmrMembershipProof>,
    pub leaf_indices: Vec<u64>,
}
