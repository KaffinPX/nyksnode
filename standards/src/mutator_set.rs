use nyks_consensus::mutator_set::MutatorSetError;
use nyks_consensus::mutator_set::ms_membership_proof::MsMembershipProof;
use nyks_consensus::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
use nyks_consensus::tasm_lib::prelude::Digest;
use nyks_consensus::tasm_lib::twenty_first::prelude::MmrMembershipProof;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedAoclAuthPath {
    pub leaf_index: u64,
    pub auth_path: MmrMembershipProof,
}

/// Data structure for returning components of a mutator set membership proof
/// from an archival state, without callee learning more than the unmined
/// transaction reveals, namely a fuzzy timestamp of the input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsMembershipProofPrivacyPreserving {
    pub aocl_auth_paths: Vec<IndexedAoclAuthPath>,
    pub target_chunks: ChunkDictionary,
}

impl MsMembershipProofPrivacyPreserving {
    /// Build the required membership proof by supplying the correct AOCL leaf
    /// index to extract the right MMR authentication path and the missing
    /// cryptographic data.
    pub fn extract_ms_membership_proof(
        self,
        aocl_leaf_index: u64,
        sender_randomness: Digest,
        receiver_preimage: Digest,
    ) -> Result<MsMembershipProof, MutatorSetError> {
        let aocl_mmr = self
            .aocl_auth_paths
            .into_iter()
            .find(|x| x.leaf_index == aocl_leaf_index)
            .map(|x| x.auth_path);
        let Some(aocl_mmr) = aocl_mmr else {
            return Err(
                MutatorSetError::RequestedAoclAuthPathNotContainedInResponse {
                    request_aocl_leaf_index: aocl_leaf_index,
                },
            );
        };

        Ok(MsMembershipProof {
            sender_randomness,
            receiver_preimage,
            auth_path_aocl: aocl_mmr,
            aocl_leaf_index,
            target_chunks: self.target_chunks,
        })
    }
}
