use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::block_appendix::BlockAppendix;
use super::block_body::BlockBody;
use super::block_header::BlockHeader;
use crate::consensus::block::block_validation_error::BlockValidationError;
use crate::consensus::block::mutator_set_update::MutatorSetUpdate;
use crate::consensus::mutator_set::addition_record::AdditionRecord;
use crate::consensus::mutator_set::commit;
use crate::consensus::mutator_set::removal_record::removal_record_list::RemovalRecordList;
use crate::consensus::transaction::utxo::Utxo;
use crate::proof_abstractions::mast_hash::HasDiscriminant;
use crate::proof_abstractions::mast_hash::MastHash;

/// The kernel of a block contains all data that is not proof data
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct BlockKernel {
    pub header: BlockHeader,
    pub body: BlockBody,

    pub appendix: BlockAppendix,
}

impl BlockKernel {
    pub fn new(header: BlockHeader, body: BlockBody, appendix: BlockAppendix) -> Self {
        Self {
            header,
            body,
            appendix,
        }
    }

    /// Get the block's guesser fee UTXOs.
    ///
    /// The amounts in the UTXOs are taken from the transaction fee.
    ///
    /// The genesis block does not have a guesser reward.
    pub fn guesser_fee_utxos(&self) -> Result<Vec<Utxo>, BlockValidationError> {
        if self.header.height.is_genesis() {
            return Ok(vec![]);
        }

        let total_guesser_reward = self.body.total_guesser_reward()?;
        let coins_unlocked = total_guesser_reward.to_native_coins();
        let lock_script_hash = self.header.guesser_receiver_data.lock_script_hash;
        let unlocked_utxo = Utxo::new(lock_script_hash, coins_unlocked);

        Ok(vec![unlocked_utxo])
    }

    /// Compute the addition records that correspond to the UTXOs generated for
    /// the block's guesser
    ///
    /// The genesis block does not have this addition record.
    pub fn guesser_fee_addition_records(
        &self,
        block_hash: Digest,
    ) -> Result<Vec<AdditionRecord>, BlockValidationError> {
        Ok(self
            .guesser_fee_utxos()?
            .into_iter()
            .map(|utxo| {
                let item = Tip5::hash(&utxo);

                // Adding the block hash to the mutator set here means that no
                // composer can start proving before solving the PoW-race;
                // production of future proofs is impossible as they depend on
                // inputs hidden behind the veil of future PoW.
                let sender_randomness = block_hash;
                let receiver_digest = self.header.guesser_receiver_data.receiver_digest;

                commit(item, sender_randomness, receiver_digest)
            })
            .collect_vec())
    }

    /// Return the mutator set update, including guesser fee outputs, invoked by
    /// this block.
    pub fn mutator_set_update(
        &self,
        block_hash: Digest,
    ) -> Result<MutatorSetUpdate, BlockValidationError> {
        let outputs = self.all_addition_records(block_hash)?;
        let inputs = RemovalRecordList::try_unpack(self.body.transaction_kernel.inputs.clone())
            .map_err(BlockValidationError::from)?;

        Ok(MutatorSetUpdate::new(inputs, outputs))
    }

    /// Return all addition records, including guesser fee outputs, invoked by
    /// this block.
    pub fn all_addition_records(
        &self,
        block_hash: Digest,
    ) -> Result<Vec<AdditionRecord>, BlockValidationError> {
        let mut addition_records = self.body.transaction_kernel.outputs.clone();
        let guesser_addition_records = self.guesser_fee_addition_records(block_hash)?;
        addition_records.extend(guesser_addition_records);

        Ok(addition_records)
    }
}

#[derive(Debug, Copy, Clone, EnumCount)]
pub enum BlockKernelField {
    Header,
    Body,
    Appendix,
}

impl HasDiscriminant for BlockKernelField {
    fn discriminant(&self) -> usize {
        *self as usize
    }
}

impl MastHash for BlockKernel {
    type FieldEnum = BlockKernelField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        let sequences = vec![
            self.header.mast_hash().encode(),
            self.body.mast_hash().encode(),
            self.appendix.encode(),
        ];
        sequences
    }
}
