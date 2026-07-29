#[cfg(test)]
use std::sync::Arc;

use crate::network::Network;
use crate::proof_abstractions::mast_hash::MastHash;
use crate::transaction::transaction_kernel_id::TransactionKernelId;

pub mod announcement;
pub mod lock_script;
pub mod salted_utxos;
pub mod transaction_kernel;
pub mod transaction_kernel_id;
pub mod transaction_proof;
pub mod utxo;
pub mod utxo_triple;
pub mod validity;

use anyhow::Result;
use get_size2::GetSize;
use num_bigint::BigInt;
use num_rational::BigRational;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
pub use transaction_proof::TransactionProof;
use validity::proof_collection::ProofCollection;
use validity::tasm::single_proof::merge_branch::MergeWitness;

use self::transaction_kernel::TransactionKernel;
use self::transaction_kernel::TransactionKernelProxy;
use super::consensus_rule_set::ConsensusRuleSet;
use crate::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::transaction::validity::neptune_proof::Proof;
use crate::triton_vm::proof::Claim;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct Transaction {
    pub kernel: TransactionKernel,
    pub proof: TransactionProof,
}

// for simpler Arc compatibility with existing tests.
#[cfg(test)]
impl From<Arc<Transaction>> for Transaction {
    fn from(t: Arc<Transaction>) -> Self {
        (*t).clone()
    }
}

impl Transaction {
    /// return transaction id.
    ///
    /// note that transactions created by users are temporary.  Once confirmed
    /// into a block they are merged into a single block transaction.  So this
    /// id will not correspond to anything on the blockchain except for the
    /// single transaction in each block.
    ///
    /// These id are useful for referencing transactions in the mempool however.
    pub fn txid(&self) -> TransactionKernelId {
        self.kernel.txid()
    }

    /// Determine whether the transaction is valid but not necessarily
    /// confirmable.
    ///
    /// This method tests the transaction's internal consistency in isolation,
    /// without the context of the canonical chain.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn is_valid(&self, network: Network, consensus_rule_set: ConsensusRuleSet) -> bool {
        let kernel_hash = self.kernel.mast_hash();
        self.proof
            .verify(kernel_hash, network, consensus_rule_set)
            .await
    }

    /// Merge two transactions. Both input transactions must have a valid
    /// Proof witness for this operation to work. The `self` argument can be
    /// a transaction with a negative fee.
    ///
    /// # Panics
    ///
    /// Panics if the two transactions cannot be merged, if e.g. the mutator
    /// set hashes are not the same, if both transactions have coinbase a
    /// coinbase UTXO, if either of the transactions are *not* a single
    /// proof, or if the RHS (`other`) has a negative fee.
    pub async fn merge_with(
        self,
        other: Transaction,
        shuffle_seed: [u8; 32],
        _consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Transaction> {
        assert_eq!(
            self.kernel.mutator_set_hash, other.kernel.mutator_set_hash,
            "Mutator sets must be equal for transaction merger."
        );

        assert!(
            self.kernel.coinbase.is_none() && other.kernel.coinbase.is_none(),
            "Don't use me for coinbase transactions, por favor"
        );

        let merge_witness = MergeWitness::from_transactions(self, other, shuffle_seed);
        MergeWitness::merge(merge_witness)
    }

    /// Calculates a fraction representing the fee-density, defined as:
    /// `transaction_fee/transaction_size`.
    pub fn fee_density(&self) -> BigRational {
        let transaction_as_bytes = bincode::serialize(&self).unwrap();
        let transaction_size = BigInt::from(transaction_as_bytes.get_size());
        let transaction_fee = self.kernel.fee.to_nau();
        BigRational::new_raw(transaction_fee.into(), transaction_size)
    }

    /// Determine if the transaction can be validly confirmed if the block has
    /// the given mutator set accumulator. Specifically, test whether the
    /// removal records determine indices absent in the mutator set sliding
    /// window Bloom filter, and whether the MMR membership proofs are valid.
    ///
    /// Why not testing AOCL MMR membership proofs? These are being verified in
    /// PrimitiveWitness::validate and ProofCollection/RemovalRecordsIntegrity.
    /// AOCL membership is a feature of *validity*, which is a pre-requisite to
    /// confirmability.
    pub fn is_confirmable_relative_to(
        &self,
        mutator_set_accumulator: &MutatorSetAccumulator,
    ) -> bool {
        self.kernel
            .is_confirmable_relative_to(mutator_set_accumulator)
            .is_ok()
    }
}
