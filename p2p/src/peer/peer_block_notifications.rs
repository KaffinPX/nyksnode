use nyks_protocol::consensus::block::Block;
use nyks_protocol::consensus::block::block_height::BlockHeight;
use nyks_protocol::consensus::block::difficulty_control::ProofOfWork;
use nyks_protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_protocol::proof_abstractions::mast_hash::MastHash;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

// Used to tell peers that a new proposal has been generated without having to
// send the entire proposal
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockProposalNotification {
    pub body_mast_hash: Digest,
    pub guesser_fee: NativeCurrencyAmount,
    pub height: BlockHeight,
}

impl From<&Block> for BlockProposalNotification {
    fn from(value: &Block) -> Self {
        Self {
            body_mast_hash: value.body().mast_hash(),
            guesser_fee: value.body().transaction_kernel.fee,
            height: value.header().height,
        }
    }
}

/// Used to tell peers that a new block has been found without having to
/// send the entire block
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerBlockNotification {
    pub hash: Digest,
    pub height: BlockHeight,
    pub cumulative_proof_of_work: ProofOfWork,
}

impl From<&Block> for PeerBlockNotification {
    fn from(block: &Block) -> Self {
        PeerBlockNotification {
            hash: block.hash(),
            height: block.kernel.header.height,
            cumulative_proof_of_work: block.kernel.header.cumulative_proof_of_work,
        }
    }
}
