use std::ops::Deref;

use nyks_consensus::block::block_height::BlockHeight;
use nyks_consensus::mutator_set::addition_record::AdditionRecord;
use nyks_consensus::mutator_set::commit;
use nyks_consensus::mutator_set::ms_membership_proof::MsMembershipProof;
use nyks_consensus::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use nyks_consensus::transaction::utxo::Utxo;
use nyks_consensus::twenty_first::tip5::Digest;
use nyks_consensus::twenty_first::tip5::Tip5;
use serde::Deserialize;
use serde::Serialize;

/// A received UTXO that has not yet been anchored with a membership proof.
///
/// Contains the data required to monitor the mutator set and later recover
/// or reconstruct the membership proof.
#[derive(Debug, Clone)]
pub struct IncomingUtxo {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub aocl_leaf_index: u64,

    // A metadata so scanner and wallet can handle reorgs easier.
    pub inclusion_block: Option<(Digest, BlockHeight)>,
}

impl IncomingUtxo {
    pub fn new(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        aocl_leaf_index: u64,
        inclusion_block: Option<(Digest, BlockHeight)>,
    ) -> Self {
        IncomingUtxo {
            utxo,
            sender_randomness,
            receiver_preimage,
            aocl_leaf_index,
            inclusion_block,
        }
    }

    /// Returns the mutator set indices associated with this UTXO.
    ///
    /// These indices can be used to recover the membership proof from
    /// archival nodes.
    pub fn indices(&self) -> AbsoluteIndexSet {
        AbsoluteIndexSet::compute(
            Tip5::hash(&self.utxo),
            self.sender_randomness,
            self.receiver_preimage,
            self.aocl_leaf_index,
        )
    }

    /// Finalize this UTXO with a membership proof.
    ///
    /// Panics if the proof does not match the expected data for this UTXO.
    pub fn finalize(self, membership_proof: MsMembershipProof) -> MonitoredUtxo {
        assert!(
            self.sender_randomness == membership_proof.sender_randomness,
            "Sender randomness doesnt match"
        );
        assert!(
            self.receiver_preimage == membership_proof.receiver_preimage,
            "Receiver digest doesnt match"
        );
        assert!(
            self.aocl_leaf_index == membership_proof.aocl_leaf_index,
            "AOCL leaf index doesnt match"
        );

        MonitoredUtxo {
            utxo: self.utxo,
            membership_proof,
            status: MonitoredUtxoStatus::Unspent,
            inclusion_block: self.inclusion_block,
        }
    }
}

impl Deref for IncomingUtxo {
    type Target = Utxo;

    fn deref(&self) -> &Self::Target {
        &self.utxo
    }
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize)]
pub struct ExpectedUtxo {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub inclusion_block: Option<(Digest, BlockHeight)>,
}

/// Enumerates the possible spent spend-statuses of a monitored UTXO.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MonitoredUtxoStatus {
    /// No spend of this UTXO was ever recorded.
    Unspent,

    /// UTXO is spent but the node does not know in which block it was spent.
    /// To correctly handle reorganizations of the block in which the UTXO was
    /// spent, a check against the archival mutator set must be performed each
    /// time its status is queried.
    SpentInUnknownBlock,

    /// UTXO is spent and the block in which it was spent is known.
    SpentIn {
        block_hash: Digest,
        block_height: BlockHeight,
    },
}

/// A mined [`Utxo`] managed by the wallet.
///
/// The UTXO must, at one point, have been mined, although the block in which
/// it was mined might have been abandoned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitoredUtxo {
    pub utxo: Utxo,

    /// Current membership proof of the UTXO
    pub membership_proof: MsMembershipProof,

    /// Hash and other metadata of the block, if any, in which a spend of this
    /// UTXO was observed.
    pub status: MonitoredUtxoStatus,

    /// Hash and other metadata of the block in which this UTXO was confirmed.
    pub inclusion_block: Option<(Digest, BlockHeight)>,
}

impl MonitoredUtxo {
    /// Return the `item` from the perspective of the mutator set
    pub fn mutator_set_item(&self) -> Digest {
        Tip5::hash(&self.utxo)
    }

    pub fn addition_record(&self) -> AdditionRecord {
        commit(
            self.mutator_set_item(),
            self.membership_proof.sender_randomness,
            self.membership_proof.receiver_preimage.hash(),
        )
    }
}

impl Deref for MonitoredUtxo {
    type Target = Utxo;

    fn deref(&self) -> &Self::Target {
        &self.utxo
    }
}

/// An ID for UTXOs that defines uniqueness of a UTXO even in the case of
/// reorganizations. In the case of reorganizations both the AOCL leaf index and
/// the addition record is required to identify a UTXO across multiple forks. We
/// do not use the block digest in which the UTXO was mined in this definition
//  since a reorganization that repeats some UTXOs at the same location in the
/// AOCL is not considered to introduce new UTXOs, rather the same UTXOs are
/// present, but they were just mined in different blocks.
///
/// From the perspective of the mutator set, two UTXOs with the same
/// [`UtxoKey`] will always have the same lockscript and mutator set
/// membership proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UtxoKey {
    pub addition_record: AdditionRecord,
    pub aocl_index: u64,
}

impl UtxoKey {
    pub fn new(utxo: &MonitoredUtxo) -> Self {
        UtxoKey {
            addition_record: utxo.addition_record(),
            aocl_index: utxo.membership_proof.aocl_leaf_index,
        }
    }
}
