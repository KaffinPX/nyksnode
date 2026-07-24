use std::fmt::Display;
use std::str::FromStr;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::triton_vm::prelude::Tip5;
use tasm_lib::twenty_first::prelude::MerkleTree;

use crate::consensus::transaction::transaction_kernel::TransactionKernel;

/// A unique identifier of a transaction whose value is unaffected by a
/// transaction update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, GetSize, Hash, Serialize, Deserialize)]
#[cfg_attr(test, derive(Default, arbitrary::Arbitrary))]
pub struct TransactionKernelId(Digest);

impl Display for TransactionKernelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_hex())
    }
}

impl FromStr for TransactionKernelId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Digest::try_from_hex(s)?))
    }
}

impl From<TransactionKernelId> for Digest {
    fn from(value: TransactionKernelId) -> Self {
        value.0
    }
}

impl TransactionKernelId {
    /// A symmetric operation that takes two transaction kernel IDs to produce
    /// a new transaction kernel ID. The output does not correspond to the
    /// output of the merge operation. The outputted transaction kernel ID has
    /// no independent meaning and offers no guarantees other than it being a
    /// symmetric and deterministic operation.
    pub fn combine(a: Self, b: Self) -> Self {
        let a = a.0.values();
        let b = b.0.values();
        let c: Digest = Digest::new(std::array::from_fn(|i| a[i] + b[i]));

        Self(c)
    }
}

impl TransactionKernel {
    // Return a digest that is unchanged by transaction updates.
    ///
    /// Return a digest that only commits to those fields of the
    /// [TransactionKernel] that are *unchanged* by a transaction update, where
    /// a transaction update makes a transaction valid relative to a new state
    /// of the mutator set. A transaction update refers to the returned
    /// transaction from [new_with_updated_mutator_set_records].
    ///
    ///
    /// [new_with_updated_mutator_set_records]: crate::protocol::consensus::transaction::Transaction
    pub fn txid(&self) -> TransactionKernelId {
        // Since the `Update` program allows permutation of inputs, we must sort
        // the digests of the absolute indices to arrive at a digest that is
        // unchanged by an update.
        let mut index_set_hash = self
            .inputs
            .iter()
            .map(|x| Tip5::hash(&x.absolute_indices))
            .collect_vec();
        index_set_hash.sort_unstable();
        let index_set_hash = index_set_hash
            .into_iter()
            .flat_map(|x| x.values().to_vec())
            .collect_vec();
        let index_set_hash = Tip5::hash_varlen(&index_set_hash);

        // The `Update` consensus program does not permit permutation of outputs
        // so we don't have to sort here.
        let output_hash = self
            .outputs
            .iter()
            .flat_map(|x| x.canonical_commitment.values().to_vec())
            .collect_vec();
        let output_hash = Tip5::hash_varlen(&output_hash);

        // No permutation of announcements allowed
        let announcements_hash = self
            .announcements
            .iter()
            .flat_map(|x| Tip5::hash_varlen(&x.message).values().to_vec())
            .collect_vec();
        let announcements_hash = Tip5::hash_varlen(&announcements_hash);

        let fee_hash = Tip5::hash(&self.fee);

        let coinbase_hash = Tip5::hash(&self.coinbase);

        let merge_bit_hash = Tip5::hash(&self.merge_bit);

        // Build a Merkle tree from all five digests, and treat the root as the
        // digest
        let mut digests = vec![
            index_set_hash,
            output_hash,
            announcements_hash,
            fee_hash,
            coinbase_hash,
            merge_bit_hash,
        ];

        // pad until length is a power of two
        while digests.len() & (digests.len() - 1) != 0 {
            digests.push(Digest::default());
        }

        let as_digest = MerkleTree::par_new(&digests).unwrap().root();

        TransactionKernelId(as_digest)
    }
}
