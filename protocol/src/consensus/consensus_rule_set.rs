use crate::consensus::block::MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS;
use crate::consensus::block::block_height::BlockHeight;
use crate::consensus::network::Network;

/// Enumerates all possible sets of consensus rules.
///
/// Specifically, this enum captures *differences* between consensus rules,
/// across
///  - networks, and
///  - hard and soft forks triggered by blocks.
///
/// Consensus logic not captured by this encapsulation lives on
/// [`Transaction::is_valid`][super::transaction::Transaction::is_valid] and
/// ultimately [`Block::is_valid`][super::block::Block::is_valid].
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter, Default, strum::Display)]
pub enum ConsensusRuleSet {
    #[default]
    Launch,
}

impl ConsensusRuleSet {
    /// Infer the [`ConsensusRuleSet`] from the [`Network`] and the
    /// [`BlockHeight`]. The second argument is necessary to take into account
    /// planned hard or soft forks that activate at a given height. The first
    /// argument is necessary because the forks can activate at different
    /// heights based on the network.
    pub fn infer_from(network: Network, _block_height: BlockHeight) -> Self {
        match network {
            Network::Main => ConsensusRuleSet::Launch,
            Network::TestnetMock => ConsensusRuleSet::Launch,
            Network::RegTest => ConsensusRuleSet::Launch,
            Network::Testnet(_) => ConsensusRuleSet::Launch,
        }
    }

    /// Maximum block size in number of BFieldElements
    pub const fn max_block_size(&self) -> usize {
        match self {
            ConsensusRuleSet::Launch => {
                // This size is 8MB which should keep it feasible to run archival nodes for
                // many years without requiring excessive disk space.
                1_000_000
            }
        }
    }

    pub fn max_num_inputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Launch => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub fn max_num_outputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Launch => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub fn max_num_announcements(&self) -> usize {
        match self {
            ConsensusRuleSet::Launch => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
}
