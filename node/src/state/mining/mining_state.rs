use std::collections::HashMap;

use tasm_lib::prelude::Digest;

use crate::state::BlockProposal;
use crate::Block;

/// Cap to prevent cached block proposals from eating up all RAM. Should never
/// be reached unless node is under some form of attack.
pub const MAX_NUM_EXPORTED_BLOCK_PROPOSAL_STORED: usize = 10_000;

/// State related to the mining (composing and guessing) of the next block.
#[derive(Debug, Default)]
pub struct MiningState {
    /// The most profitable block proposal seen on the network. But not
    /// necessarily the one a guesser is guessing on as the proposal is only
    /// changed when the delta in reward meets a threshold. Only updateable by
    /// main loop.
    pub block_proposal: BlockProposal,

    /// The block proposals that were exported to external guessers. Not
    /// persisted. Only contains block proposals pertaining to the next block
    /// height. All exported proposals are forgotten when a new block is
    /// received.
    ///
    /// TBD: refactorize to store best n proposals/templates
    pub(crate) exported_block_proposals: HashMap<Digest, Block>,
}
