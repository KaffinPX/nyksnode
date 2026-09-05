use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumIter;
use tasm_lib::prelude::Digest;

use crate::consensus_rule_set::ConsensusRuleSet;
use crate::network::Network;
#[cfg(not(target_arch = "wasm32"))]
use crate::proof_abstractions::verifier::verify;
use crate::transaction::BFieldCodec;
use crate::transaction::ProofCollection;
use crate::transaction::validity::nyks_proof::NyksProof;
use crate::transaction::validity::single_proof::single_proof_claim;

/// Enumerates the kind of transaction proof that can be shared without the risk
/// of loss of funds.
///
/// SingleProof is the highest quality, as they can be merged with the miner's
/// coinbase transaction, which also is supported by a SingleProof.
/// ProofCollection requires upgrade to a SingleProof before mining, so it is
/// of lover quality.
#[derive(Clone, Copy, EnumIter, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransactionProofQuality {
    // OnlyLockScripts, // TODO: Add this once Transaction has support
    ProofCollection,
    SingleProof,
}

/// represents available types of transaction proofs
///
/// the types are ordered (asc) by proof-generation complexity.
#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, strum::Display)]
#[repr(u8)]
pub enum TransactionProofType {
    // Enumeration here must match that used in TxProvingCapability.
    /// Exposes secrets (keys) and privacy. This proof must not be shared.
    PrimitiveWitness = 0,

    // LockScript = 1,
    /// A proof that does not expose secrets or privacy. Can be shared with
    /// peers, but cannot be confirmed into a block.
    ProofCollection = 2,

    /// Required for confirming a transaction into a block.
    SingleProof = 3,
}

impl From<&TransactionProof> for TransactionProofType {
    fn from(proof: &TransactionProof) -> Self {
        match *proof {
            TransactionProof::ProofCollection(_) => Self::ProofCollection,
            TransactionProof::SingleProof(_) => Self::SingleProof,
        }
    }
}

impl TransactionProofType {
    /// indicates if the proof executes in triton-vm.
    pub fn executes_in_vm(&self) -> bool {
        matches!(self, Self::ProofCollection | Self::SingleProof)
    }

    pub fn is_single_proof(&self) -> bool {
        *self == TransactionProofType::SingleProof
    }
}

/// represents a transaction proof, which can be of different types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
#[allow(clippy::large_enum_variant)]
pub enum TransactionProof {
    /// a strong proof.  required for confirming a transaction into a block.
    SingleProof(NyksProof),
    /// a weak proof that does not expose secrets. can be shared with peers, but cannot be confirmed into a block.
    ProofCollection(ProofCollection),
}

impl TransactionProof {
    pub fn is_proof_collection(&self) -> bool {
        matches!(self, Self::ProofCollection(_))
    }

    pub fn is_single_proof(&self) -> bool {
        matches!(self, Self::SingleProof(_))
    }

    /// Convert a transaction proof into a Triton VM proof.
    ///
    /// # Panics
    ///
    /// - If the proof type is any other than [TransactionProof::SingleProof].
    pub fn into_single_proof(self) -> NyksProof {
        match self {
            TransactionProof::SingleProof(proof) => proof,
            TransactionProof::ProofCollection(_) => {
                panic!("Expected SingleProof, got ProofCollection")
            }
        }
    }

    /// Convert a transaction proof into a Triton VM proof, if the transaction
    /// is single proof backed. Otherwise returns `None`.
    pub fn as_single_proof(&self) -> Option<NyksProof> {
        match self {
            TransactionProof::ProofCollection(_) => None,
            TransactionProof::SingleProof(neptune_proof) => Some(neptune_proof.to_owned()),
        }
    }

    pub fn proof_quality(&self) -> TransactionProofQuality {
        match self {
            TransactionProof::ProofCollection(_) => TransactionProofQuality::ProofCollection,
            TransactionProof::SingleProof(_) => TransactionProofQuality::SingleProof,
        }
    }

    /// verify this proof is valid for a provided transaction id.
    ///
    /// Block height is the height of the block that matches the transaction's
    /// mutator set accumulator.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn verify(
        &self,
        kernel_mast_hash: Digest,
        network: Network,
        consensus_rule_set: ConsensusRuleSet,
    ) -> bool {
        match self {
            TransactionProof::SingleProof(single_proof) => {
                let claim = single_proof_claim(kernel_mast_hash, consensus_rule_set);
                verify(claim, single_proof.clone(), network).await
            }
            TransactionProof::ProofCollection(proof_collection) => {
                proof_collection.verify(kernel_mast_hash, network).await
            }
        }
    }
}

/// error variants associated with a transaction proof
#[derive(Debug, Copy, Clone)]
pub enum TransactionProofError {
    CannotUpdateProofVariant,
    CannotUpdatePrimitiveWitness,
    CannotUpdateSingleProof,
    ProverLockWasTaken,
}
