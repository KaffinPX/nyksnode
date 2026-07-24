use nyks_protocol::consensus::transaction::Transaction;
use nyks_protocol::consensus::transaction::TransactionProof;
use nyks_protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use nyks_protocol::consensus::transaction::validity::neptune_proof::NeptuneProof;
use nyks_protocol::consensus::transaction::validity::proof_collection::ProofCollection;
use thiserror::Error;

use crate::transaction::primitive_witness::PrimitiveWitness;

pub mod builder;
pub mod primitive_witness;
pub mod utxo;

/// Represents a builder transaction proof, which can be of different types.
///
/// These are usually not for broadcasting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuilderTransactionProof {
    /// A strong proof. required for confirming a transaction into a block.
    SingleProof(NeptuneProof),
    /// A weak proof that does not expose secrets. can be shared with peers, but cannot be confirmed into a block.
    ProofCollection(ProofCollection),
    /// A primitive-witness. exposes secrets (keys). this is not an actual proof and cannot be shared.
    Witness(PrimitiveWitness),
}

impl BuilderTransactionProof {
    /// Extract transaction proof into a witness.
    ///
    /// Its usually used for checking if transaction is valid.
    pub fn as_witness(self) -> Option<PrimitiveWitness> {
        match self {
            BuilderTransactionProof::Witness(c) => Some(c),
            _ => panic!("expected Witness"),
        }
    }

    /// Extract transaction proof into a proof collection.
    ///
    /// Its usually used for off-process proving to a SingleProof.
    pub fn as_collection(self) -> Option<ProofCollection> {
        match self {
            BuilderTransactionProof::ProofCollection(c) => Some(c),
            _ => panic!("expected ProofCollection"),
        }
    }
}

pub struct BuilderTransaction {
    pub kernel: TransactionKernel,
    pub proof: BuilderTransactionProof,
}

impl BuilderTransaction {
    /// Upgrades the transaction proof to a level that can be broadcasted.
    pub fn upgrade(self) -> Self {
        let new_proof = match self.proof {
            BuilderTransactionProof::Witness(witness) => {
                BuilderTransactionProof::ProofCollection(witness.prove().unwrap())
            }
            // Other types are not supported yet, still investigating DX and use cases...
            _ => unimplemented!(),
        };

        BuilderTransaction {
            kernel: self.kernel,
            proof: new_proof,
        }
    }
}

#[derive(Debug, Error)]
pub enum BuilderTransactionConversionError {
    #[error("cannot convert witness into consensus transaction")]
    WitnessNotConvertible,
}

impl TryFrom<BuilderTransaction> for Transaction {
    type Error = BuilderTransactionConversionError;

    fn try_from(tx: BuilderTransaction) -> Result<Self, Self::Error> {
        let proof = match tx.proof {
            BuilderTransactionProof::SingleProof(proof) => TransactionProof::SingleProof(proof),
            BuilderTransactionProof::ProofCollection(collection) => {
                TransactionProof::ProofCollection(collection)
            }
            BuilderTransactionProof::Witness(_) => {
                return Err(BuilderTransactionConversionError::WitnessNotConvertible);
            }
        };

        Ok(Transaction {
            kernel: tx.kernel,
            proof,
        })
    }
}
