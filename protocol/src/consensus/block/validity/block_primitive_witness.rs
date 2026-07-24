use std::sync::OnceLock;

use tasm_lib::twenty_first::prelude::Mmr;

use crate::consensus::block::Block;
use crate::consensus::block::block_body::BlockBody;
use crate::consensus::block::block_header::BlockHeader;
use crate::consensus::block::block_transaction::BlockTransaction;
use crate::consensus::block::mutator_set_update::MutatorSetUpdate;
use crate::consensus::mutator_set::removal_record::removal_record_list::RemovalRecordList;
use crate::consensus::network::Network;
use crate::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::proof_abstractions::timestamp::Timestamp;

/// Wraps all information necessary to produce a block.
///
/// Represents the first stage in the block production pipeline, which looks
/// like this:
///
/// ```notest
/// predecessor : Block --------.
///                             |-- new --> BlockPrimitiveWitness
/// transaction : Transaction --'                      |
///                                                    |
///                                                    |---> BlockBody --.------}--.
///                                                    |                 |         |
///        SingleProof : BlockProgram <-- conversion --+-> }             |         |
///         |        ? : BlockProgram <-- conversion --+-> } Appendix ---+------}--|
///         | ...... ? : BlockProgram <-- conversion --'-> }             |         |
///        prove                                                         |         |
///         | prove                                                      |         |
///         |  | prove                                                   |         |
///         |  |  |                                                      |          > Block
///         v  v  v                                                      |         |
/// BlockProofWitness ---------  produce  -----> BlockProof -------------+------}--|
///                                                                      |         |
///                                                                   mining       |
///                                                                      |         |
///                                                                      v         |
///                                                               Blockheader --}--'
/// ```
#[derive(Clone, Debug)]
pub struct BlockPrimitiveWitness {
    pub(super) predecessor_block: Block,

    transaction: BlockTransaction,

    maybe_body: OnceLock<BlockBody>,

    pub(super) network: Network,
}

impl BlockPrimitiveWitness {
    pub fn new(predecessor_block: Block, transaction: BlockTransaction, network: Network) -> Self {
        Self {
            predecessor_block,
            transaction,
            maybe_body: OnceLock::new(),
            network,
        }
    }

    pub fn transaction(&self) -> &BlockTransaction {
        &self.transaction
    }

    pub fn header(&self, timestamp: Timestamp, target_block_interval: Timestamp) -> BlockHeader {
        let parent_header = self.predecessor_block.header();
        let parent_digest = self.predecessor_block.hash();
        BlockHeader::template_header(
            parent_header,
            parent_digest,
            timestamp,
            target_block_interval,
        )
    }

    /// Builds the block body from its witness.
    ///
    /// # Panics
    ///
    ///  - If predecessor has negative transaction fee.
    pub fn body(&self) -> &BlockBody {
        self.maybe_body.get_or_init(|| {
            let predecessor_msa = self
                .predecessor_block
                .mutator_set_accumulator_after()
                .expect("Predecessor must have mutator set after");
            let predecessor_msa_digest = predecessor_msa
                .hash();
            let transaction_kernel = TransactionKernel::from(self.transaction.kernel.clone());
            let tx_msa_digest = transaction_kernel.mutator_set_hash;
            assert_eq!(
                predecessor_msa_digest,
                tx_msa_digest,
                "Mutator set of transaction must agree with mutator set after previous block.\
                \nPredecessor block had {predecessor_msa_digest};\ntransaction had {tx_msa_digest}\n\n"
            );

            let inputs = RemovalRecordList::try_unpack(transaction_kernel.inputs.clone()).expect("Inputs must be packed in block transaction");

            let mutator_set_update = MutatorSetUpdate::new(inputs, self.transaction.kernel.outputs.clone());

            // Due to tests, we don't verify that the removal records can be
            // applied. That is the caller's responsibility to ensure by e.g.
            // checking block validity after constructing a block.
            let mut mutator_set = predecessor_msa;
            mutator_set_update.apply_to_accumulator_unsafe(&mut mutator_set);

            let predecessor_body = self.predecessor_block.body();
            let lock_free_mmr = predecessor_body.lock_free_mmr_accumulator.clone();
            let mut block_mmr = predecessor_body.block_mmr_accumulator.clone();
            block_mmr.append(self.predecessor_block.hash());

            BlockBody::new(
                transaction_kernel.to_owned(),
                mutator_set,
                lock_free_mmr,
                block_mmr,
            )
        })
    }
}
