use std::ops::Deref;

use crate::consensus_rule_set::ConsensusRuleSet;
use crate::transaction::Transaction;
use crate::transaction::TransactionProof;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::validity::tasm::single_proof::merge_branch::MergeWitness;

/// Newtype for [`TransactionKernel`] where removal records are packed. For use
/// in the context of [`BlockTransaction`]s. See [`BlockTransaction`] for more
/// documentation. The difference between regular [`Transaction`]s and
/// [`BlockTransaction`]s is contained in the kernel, which is why
/// [`BlockTransaction`] has a custom kernel type but not a custom proof type.
#[derive(Debug, Clone)]
pub struct BlockTransactionKernel(TransactionKernel);

impl Deref for BlockTransactionKernel {
    type Target = TransactionKernel;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<BlockTransactionKernel> for TransactionKernel {
    fn from(value: BlockTransactionKernel) -> Self {
        value.0
    }
}

impl TryFrom<TransactionKernel> for BlockTransactionKernel {
    type Error = ();

    fn try_from(value: TransactionKernel) -> Result<Self, Self::Error> {
        match value.merge_bit {
            true => Ok(Self(value)),
            false => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum BlockOrRegularTransactionKernel {
    Block(BlockTransactionKernel),
    Regular(TransactionKernel),
}

impl From<BlockOrRegularTransactionKernel> for TransactionKernel {
    fn from(value: BlockOrRegularTransactionKernel) -> Self {
        match value {
            BlockOrRegularTransactionKernel::Block(block_transaction_kernel) => {
                block_transaction_kernel.0
            }
            BlockOrRegularTransactionKernel::Regular(transaction_kernel) => transaction_kernel,
        }
    }
}

/// Essentially a newtype for [`Transaction`], specifically for use in the
/// context of *the* transaction in a given block. Contains packed removal
/// records.
///
/// The point about packing is that it does not change type: this operation maps
/// a `Vec<RemovalRecord>` to a `Vec<RemovalRecord>` purely by removing
/// redundant information that can later be added back cheaply.
#[derive(Debug, Clone)]
pub struct BlockTransaction {
    pub kernel: BlockTransactionKernel,
    pub proof: TransactionProof,
}

impl TryFrom<Transaction> for BlockTransaction {
    type Error = ();

    fn try_from(value: Transaction) -> Result<Self, Self::Error> {
        Ok(Self {
            kernel: value.kernel.try_into()?,
            proof: value.proof,
        })
    }
}

impl From<BlockTransaction> for Transaction {
    fn from(value: BlockTransaction) -> Self {
        Self {
            kernel: value.kernel.0,
            proof: value.proof,
        }
    }
}

/// A transaction, but when it is undefined or unknown whether it is a
/// regular [`Transaction`] or a [`BlockTransaction`].
#[derive(Debug, Clone)]
pub enum BlockOrRegularTransaction {
    Block(BlockTransaction),
    Regular(Transaction),
}

impl BlockOrRegularTransaction {
    pub fn kernel(&self) -> BlockOrRegularTransactionKernel {
        match self {
            BlockOrRegularTransaction::Block(block_transaction) => {
                BlockOrRegularTransactionKernel::Block(block_transaction.kernel.clone())
            }
            BlockOrRegularTransaction::Regular(transaction) => {
                BlockOrRegularTransactionKernel::Regular(transaction.kernel.clone())
            }
        }
    }

    pub fn proof(&self) -> TransactionProof {
        match self {
            BlockOrRegularTransaction::Block(block_transaction) => block_transaction.proof.clone(),
            BlockOrRegularTransaction::Regular(transaction) => transaction.proof.clone(),
        }
    }
}

impl From<Transaction> for BlockOrRegularTransaction {
    fn from(value: Transaction) -> Self {
        BlockOrRegularTransaction::Regular(value)
    }
}

impl From<BlockTransaction> for BlockOrRegularTransaction {
    fn from(value: BlockTransaction) -> Self {
        BlockOrRegularTransaction::Block(value)
    }
}

impl TryFrom<BlockOrRegularTransaction> for BlockTransaction {
    type Error = ();

    fn try_from(value: BlockOrRegularTransaction) -> Result<Self, Self::Error> {
        match value {
            BlockOrRegularTransaction::Block(block_transaction) => Ok(block_transaction),
            BlockOrRegularTransaction::Regular(_) => Err(()),
        }
    }
}

impl From<BlockOrRegularTransaction> for Transaction {
    fn from(value: BlockOrRegularTransaction) -> Self {
        match value {
            BlockOrRegularTransaction::Block(block_transaction) => Self {
                kernel: block_transaction.kernel.into(),
                proof: block_transaction.proof,
            },
            BlockOrRegularTransaction::Regular(transaction) => transaction,
        }
    }
}

impl BlockTransaction {
    /// Merge a [`BlockTransaction`] or a regular [`Transaction`] with a
    /// regular [`Transaction`], resulting in a [`BlockTransaction`].
    ///
    /// See also: [`Transaction::merge_with`], which should be used if
    ///  - a) the arguments are two regular [`Transaction`]s; and
    ///  - b) the result must be a regular [`Transaction`] as well.
    pub fn merge(
        coinbase: BlockOrRegularTransaction,
        other: Transaction,
        shuffle_seed: [u8; 32],
        #[expect(unused_variables, reason = "anticipate future fork")]
        consensus_rule_set: ConsensusRuleSet,
    ) -> anyhow::Result<BlockTransaction> {
        let merge_witness = MergeWitness::for_composition(coinbase, other, shuffle_seed);
        let tx = MergeWitness::merge(merge_witness)?;

        Ok(tx.try_into().expect("Must have merge bit set"))
    }
}
