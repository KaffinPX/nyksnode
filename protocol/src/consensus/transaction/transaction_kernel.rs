use std::collections::HashSet;
use std::sync::OnceLock;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use strum::VariantArray;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::tip5::digest::Digest;

use super::announcement::Announcement;
use crate::consensus::mutator_set::addition_record::AdditionRecord;
use crate::consensus::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::consensus::mutator_set::removal_record::RemovalRecord;
use crate::consensus::mutator_set::removal_record::removal_record_list::RemovalRecordListUnpackError;
use crate::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::proof_abstractions::mast_hash::HasDiscriminant;
use crate::proof_abstractions::mast_hash::MastHash;
use crate::proof_abstractions::timestamp::Timestamp;

/// TransactionKernel is immutable and its hash never changes.
///
/// See [`TransactionKernelModifier`] for generating modified copies.
#[readonly::make]
#[derive(Debug, Clone, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject)]
pub struct TransactionKernel {
    // note: see field descriptions in [`TransactionKernelProxy`]
    pub inputs: Vec<RemovalRecord>,
    pub outputs: Vec<AdditionRecord>,
    pub announcements: Vec<Announcement>,
    pub fee: NativeCurrencyAmount,
    pub coinbase: Option<NativeCurrencyAmount>,
    pub timestamp: Timestamp,
    pub mutator_set_hash: Digest,

    /// Indicates whether the transaction is the result of some merger.
    pub merge_bit: bool,

    // this is only here as a cache for MastHash
    // so that we lazily compute the input sequences at most once.
    #[serde(skip)]
    #[bfield_codec(ignore)]
    #[tasm_object(ignore)]
    #[get_size(ignore)]
    mast_sequences: OnceLock<Vec<Vec<BFieldElement>>>,
}

impl std::fmt::Display for TransactionKernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "
kernel hash: {mast_hash}
inputs: {inputs}
outputs: {outputs}
announcements: {announcements}
coinbase: {coinbase}
timestamp: {timestamp}
mutator_set_hash: {ms_hash}
merge_bit: {merge_bit}
",
            mast_hash = self.mast_hash().to_hex(),
            inputs = self.inputs.len(),
            outputs = self.outputs.len(),
            announcements = self.announcements.len(),
            coinbase = self
                .coinbase
                .unwrap_or_else(|| NativeCurrencyAmount::coins(0)),
            timestamp = self.timestamp,
            ms_hash = self.mutator_set_hash.to_hex(),
            merge_bit = self.merge_bit,
        )
    }
}

// we impl PartialEq manually in order to skip mast_sequences field.
// This could also be achieved with the `derivative` crate that has a
// PartialEq that can skip fields, but this way we avoid an extra dep.
impl PartialEq for TransactionKernel {
    fn eq(&self, o: &Self) -> bool {
        self.inputs == o.inputs
            && self.outputs == o.outputs
            && self.announcements == o.announcements
            && self.fee == o.fee
            && self.coinbase == o.coinbase
            && self.timestamp == o.timestamp
            && self.mutator_set_hash == o.mutator_set_hash
            && self.merge_bit == o.merge_bit

        // mast_sequences intentionally skipped.
    }
}

impl Eq for TransactionKernel {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransactionConfirmabilityError {
    InvalidRemovalRecord(usize),
    DuplicateInputs,
    AlreadySpentInput(usize),
    RemovalRecordUnpackFailure,
}

impl From<RemovalRecordListUnpackError> for TransactionConfirmabilityError {
    fn from(_: RemovalRecordListUnpackError) -> Self {
        Self::RemovalRecordUnpackFailure
    }
}

impl TransactionKernel {
    pub fn mutator_set_hash(&self) -> Digest {
        self.mutator_set_hash
    }

    /// Check if transaction is confirmable. Inputs must be unpacked before this
    /// check is performed.
    pub fn is_confirmable_relative_to(
        &self,
        mutator_set_accumulator: &MutatorSetAccumulator,
    ) -> Result<(), TransactionConfirmabilityError> {
        // check validity of removal records
        //       ^^^^^^^^

        // meaning: a) all required membership proofs exist; and b) are valid.
        let inputs = &self.inputs;
        let maybe_invalid_removal_record = inputs
            .iter()
            .enumerate()
            .find(|(_, rr)| !rr.validate(mutator_set_accumulator));
        if let Some((index, _invalid_removal_record)) = maybe_invalid_removal_record {
            return Err(TransactionConfirmabilityError::InvalidRemovalRecord(index));
        }

        // check for duplicates
        let has_unique_inputs =
            inputs.iter().unique_by(|rr| rr.absolute_indices).count() == inputs.len();
        if !has_unique_inputs {
            return Err(TransactionConfirmabilityError::DuplicateInputs);
        }

        // check for already-spent inputs
        let already_spent_removal_record = inputs
            .iter()
            .enumerate()
            .find(|(_, rr)| !mutator_set_accumulator.can_remove(rr));
        if let Some((index, _already_spent_removal_record)) = already_spent_removal_record {
            return Err(TransactionConfirmabilityError::AlreadySpentInput(index));
        }

        Ok(())
    }

    /// Returns `true` iff the "output" transaction kernel is a merged
    /// transaction that has the "input" transaction as one of its inputs. In
    /// other  words, if there exists an X that is not a nop transaction such
    /// that (input, X) -> output is a valid merge of two transactions this
    /// function returns true.
    ///
    /// The caller must verify that the associated transaction proofs are of
    /// type single proof, as only single proof-backed transactions can be
    /// merged.
    pub fn have_merge_relationship(output: &Self, input: &Self) -> bool {
        // Merge outputs are guaranteed to have merge bit set
        if !output.merge_bit {
            return false;
        }

        // merge output cannot have fewer inputs/outputs/announcements than
        // the two transaction it was merged from.
        if output.inputs.len() < input.inputs.len() {
            return false;
        }

        if output.outputs.len() < input.outputs.len() {
            return false;
        }

        if output.announcements.len() < input.announcements.len() {
            return false;
        }

        // Merge result cannot have timestamp prior to its input transactions.
        if output.timestamp < input.timestamp {
            return false;
        }

        // At least one of the fields, inputs/outputs/announcements must have
        // grown in a proper (i.e. non-nop) merge.
        if output.inputs.len() == input.inputs.len()
            && output.outputs.len() == input.outputs.len()
            && output.announcements.len() == input.announcements.len()
        {
            return false;
        }

        // Inputs/outputs/announcements for existing transaction must all be
        // subsets of new transaction in case of merge.
        let new_txs_outputs: HashSet<_> = output.outputs.clone().into_iter().collect();
        for old_tx_output in &input.outputs {
            if !new_txs_outputs.contains(old_tx_output) {
                return false;
            }
        }

        let new_txs_inputs: HashSet<_> = output.inputs.iter().map(|x| x.absolute_indices).collect();
        for old_tx_input in &input.inputs {
            if !new_txs_inputs.contains(&old_tx_input.absolute_indices) {
                return false;
            }
        }

        let new_txs_announcements: HashSet<_> = output.announcements.clone().into_iter().collect();
        for old_tx_announcement in &input.announcements {
            if !new_txs_announcements.contains(old_tx_announcement) {
                return false;
            }
        }

        true
    }
}

#[derive(VariantArray, Debug, Clone, EnumCount, Copy, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum TransactionKernelField {
    Inputs,
    Outputs,
    Announcements,
    Fee,
    Coinbase,
    Timestamp,
    MutatorSetHash,
    MergeBit,
}

impl HasDiscriminant for TransactionKernelField {
    fn discriminant(&self) -> usize {
        *self as usize
    }
}

impl MastHash for TransactionKernel {
    type FieldEnum = TransactionKernelField;

    /// Return the sequences (= leaf preimages) of the kernel Merkle tree.
    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        self.mast_sequences
            .get_or_init(|| {
                let input_utxos_sequence = self.inputs.encode();

                let output_utxos_sequence = self.outputs.encode();

                let announcements_sequence = self.announcements.encode();

                let fee_sequence = self.fee.encode();

                let coinbase_sequence = self.coinbase.encode();

                let timestamp_sequence = self.timestamp.encode();

                let mutator_set_hash_sequence = self.mutator_set_hash.encode();

                let merge_bit_sequence = self.merge_bit.encode();

                vec![
                    input_utxos_sequence,
                    output_utxos_sequence,
                    announcements_sequence,
                    fee_sequence,
                    coinbase_sequence,
                    timestamp_sequence,
                    mutator_set_hash_sequence,
                    merge_bit_sequence,
                ]
            })
            .clone() // can we refactor to avoid this clone?
    }
}

/// performs instantiation and destructuring of [TransactionKernel]
///
/// [TransactionKernel] is immutable, so it cannot be instantiated
/// by direct field access.  This proxy is mutable, and it has an
/// into_kernel() method that converts it to a [TransactionKernel].
///
/// It is also useful for destructuring kernel fields without cloning.
#[derive(Debug, Clone)]
pub struct TransactionKernelProxy {
    /// contains the transaction inputs.
    pub inputs: Vec<RemovalRecord>,

    /// contains the commitments (addition records) that go into the AOCL
    pub outputs: Vec<AdditionRecord>,

    /// list of public-announcements to include in blockchain
    pub announcements: Vec<Announcement>,

    /// tx fee amount
    pub fee: NativeCurrencyAmount,

    /// optional coinbase.  applies only to miner payments.
    pub coinbase: Option<NativeCurrencyAmount>,

    /// number of milliseconds since unix epoch
    pub timestamp: Timestamp,

    /// mutator set hash *prior* to updating mutator set with this transaction.
    pub mutator_set_hash: Digest,

    /// Indicates whether the transaction is the result of some merger.
    pub merge_bit: bool,
}

impl From<TransactionKernel> for TransactionKernelProxy {
    fn from(k: TransactionKernel) -> Self {
        Self {
            inputs: k.inputs,
            outputs: k.outputs,
            announcements: k.announcements,
            fee: k.fee,
            coinbase: k.coinbase,
            timestamp: k.timestamp,
            mutator_set_hash: k.mutator_set_hash,
            merge_bit: k.merge_bit,
        }
    }
}

impl TransactionKernelProxy {
    pub fn into_kernel(self) -> TransactionKernel {
        TransactionKernel {
            inputs: self.inputs,
            outputs: self.outputs,
            announcements: self.announcements,
            fee: self.fee,
            coinbase: self.coinbase,
            timestamp: self.timestamp,
            mutator_set_hash: self.mutator_set_hash,
            merge_bit: self.merge_bit,
            mast_sequences: Default::default(),
        }
    }
}

/// performs modifications of [TransactionKernel]
///
/// [TransactionKernel] is immutable, so any modifications must
/// generate a new instance.  [TransactionKernelModifier] uses
/// a builder pattern to facilitate that task.
///
/// supports a move/modify operation and a clone/modify operation.
#[derive(Debug, Default, Clone)]
pub struct TransactionKernelModifier {
    pub inputs: Option<Vec<RemovalRecord>>,
    pub outputs: Option<Vec<AdditionRecord>>,
    pub announcements: Option<Vec<Announcement>>,
    pub fee: Option<NativeCurrencyAmount>,
    pub coinbase: Option<Option<NativeCurrencyAmount>>,
    pub timestamp: Option<Timestamp>,
    pub mutator_set_hash: Option<Digest>,
    pub merge_bit: Option<bool>,
}

impl TransactionKernelModifier {
    /// set modified inputs
    pub fn inputs(mut self, inputs: Vec<RemovalRecord>) -> Self {
        self.inputs = Some(inputs);
        self
    }
    /// set modified outputs
    pub fn outputs(mut self, outputs: Vec<AdditionRecord>) -> Self {
        self.outputs = Some(outputs);
        self
    }
    /// set modified public-announcements
    pub fn announcements(mut self, announcements: Vec<Announcement>) -> Self {
        self.announcements = Some(announcements);
        self
    }
    /// set modified fee
    pub fn fee(mut self, fee: NativeCurrencyAmount) -> Self {
        self.fee = Some(fee);
        self
    }
    /// set modified coinbase
    pub fn coinbase(mut self, coinbase: Option<NativeCurrencyAmount>) -> Self {
        self.coinbase = Some(coinbase);
        self
    }
    /// set modified timestamp
    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
    /// set modified mutator-set-hash digest
    pub fn mutator_set_hash(mut self, mutator_set_hash: Digest) -> Self {
        self.mutator_set_hash = Some(mutator_set_hash);
        self
    }
    /// set merge-bit
    pub fn merge_bit(mut self, merge_bit: bool) -> Self {
        self.merge_bit = Some(merge_bit);
        self
    }

    /// perform move+modify operation.
    ///
    /// The input [TransactionKernel] is replaced with a copy
    /// that contains any modifications previously set in the builder.
    ///
    /// Unmodified fields from the input kernel are moved into the
    /// output kernel (no clone).
    pub fn modify(self, k: TransactionKernel) -> TransactionKernel {
        TransactionKernel {
            inputs: self.inputs.unwrap_or(k.inputs),
            outputs: self.outputs.unwrap_or(k.outputs),
            announcements: self.announcements.unwrap_or(k.announcements),
            fee: self.fee.unwrap_or(k.fee),
            coinbase: self.coinbase.unwrap_or(k.coinbase),
            timestamp: self.timestamp.unwrap_or(k.timestamp),
            mutator_set_hash: self.mutator_set_hash.unwrap_or(k.mutator_set_hash),
            merge_bit: self.merge_bit.unwrap_or(k.merge_bit),

            // we must not copy from original, as the modified
            // one must have a different sequence/hash.
            mast_sequences: Default::default(),
        }
    }

    /// perform clone+modify operation.
    ///
    /// The input [TransactionKernel] is replaced with a cloned copy
    /// that contains any modifications previously set in the builder.
    pub fn clone_modify(self, k: &TransactionKernel) -> TransactionKernel {
        self.modify(k.clone())
    }
}
