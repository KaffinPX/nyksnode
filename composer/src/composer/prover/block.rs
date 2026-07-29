use nyks_consensus::block::Block;
use nyks_consensus::block::BlockProof;
use nyks_consensus::block::block_appendix::BlockAppendix;
use nyks_consensus::block::block_transaction::BlockTransaction;
use nyks_consensus::block::validity::block_primitive_witness::BlockPrimitiveWitness;
use nyks_consensus::block::validity::block_program::BlockProgram;
use nyks_consensus::block::validity::block_proof_witness::BlockProofWitness;
use nyks_consensus::consensus_rule_set::ConsensusRuleSet;
use nyks_consensus::proof_abstractions::SecretWitness;
use nyks_consensus::proof_abstractions::mast_hash::MastHash;
use nyks_consensus::proof_abstractions::tasm::program::TritonProgram;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::proof_abstractions::verifier::verify;
use nyks_prover::JobCancelReceiver;
use nyks_prover::ProverJob;
use nyks_prover::ProverJobSettings;
use nyks_prover::ProverProcessCompletion;
use tracing::info;

use crate::core::args::Args;

#[derive(Debug, thiserror::Error)]
pub enum BlockProverError {
    #[error("prove cancelled")]
    Cancelled,

    #[error(transparent)]
    ProverJob(#[from] nyks_prover::ProverJobError),

    #[error(transparent)]
    VmProcess(#[from] nyks_prover::VmProcessError),
}

// Helper for composing and proving blocks for the chain.
//
// Takes a prepared transaction, verifies it, and builds a block on top of
// the current tip. Also generates the zero-knowledge proof required for
// the block’s validity.
//
// The tip can be updated via `set_tip()` and reused.
#[derive(Clone, Debug)]
pub struct BlockProver {
    args: Args,
    tip: Block,
    job_settings: ProverJobSettings,
}

impl BlockProver {
    pub fn new(args: Args, job_settings: ProverJobSettings) -> Self {
        BlockProver {
            tip: Block::genesis(args.network),
            args,
            job_settings,
        }
    }

    pub fn set_tip(&mut self, new_tip: Block) {
        self.tip = new_tip;
    }

    pub async fn compose_block(
        &self,
        transaction: BlockTransaction,
        block_timestamp: Timestamp,
        rx: JobCancelReceiver,
    ) -> Result<Block, BlockProverError> {
        let next_block_height = self.tip.header().height.next();
        let consensus_rule_set = ConsensusRuleSet::infer_from(self.args.network, next_block_height);

        let tx_claim = BlockAppendix::transaction_validity_claim(
            transaction.kernel.mast_hash(),
            consensus_rule_set,
        );

        assert!(
            verify(
                tx_claim.clone(),
                transaction.proof.clone().into_single_proof(),
                self.args.network,
            )
            .await,
            "Transaction proof must be valid to generate a block"
        );
        assert!(
            transaction.kernel.merge_bit,
            "Merge-bit must be set in transactions before they can be included in blocks."
        );

        let primitive_witness =
            BlockPrimitiveWitness::new(self.tip.to_owned(), transaction, self.args.network);

        self.block_from_primitive_witness(primitive_witness, block_timestamp, rx)
            .await
    }

    pub async fn block_from_primitive_witness(
        &self,
        primitive_witness: BlockPrimitiveWitness,
        timestamp: Timestamp,
        rx: JobCancelReceiver,
    ) -> Result<Block, BlockProverError> {
        let body = primitive_witness.body().to_owned();
        let header = primitive_witness.header(timestamp, self.args.network.target_block_interval());

        let block_proof_witness = BlockProofWitness::produce(primitive_witness);
        let appendix = block_proof_witness.appendix();
        let claim = BlockProgram::claim(&body, &appendix);

        info!("Proving the block...");

        let job = ProverJob::new(
            BlockProgram.program(),
            claim,
            block_proof_witness.nondeterminism(),
            self.job_settings.clone(),
        );

        let proof = match job.prove(rx).await? {
            ProverProcessCompletion::Finished(p) => p,
            ProverProcessCompletion::Cancelled => return Err(BlockProverError::Cancelled),
        };

        info!("Block proof generated successfully.");

        Ok(Block::new(
            header,
            body,
            appendix,
            BlockProof::SingleProof(proof),
        ))
    }
}
