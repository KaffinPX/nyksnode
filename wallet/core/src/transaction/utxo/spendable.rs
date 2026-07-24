use std::ops::Deref;

use nyks_protocol::tasm_lib::prelude::Digest;
use nyks_protocol::tasm_lib::prelude::Tip5;
use serde::Deserialize;
use serde::Serialize;

use nyks_protocol::consensus::mutator_set::ms_membership_proof::MsMembershipProof;
use nyks_protocol::consensus::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use nyks_protocol::consensus::mutator_set::removal_record::RemovalRecord;
use nyks_protocol::consensus::transaction::lock_script::LockScriptAndWitness;
use nyks_protocol::consensus::transaction::utxo::Utxo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendableUtxo {
    pub utxo: Utxo,
    membership_proof: MsMembershipProof,
    lock_script_and_witness: LockScriptAndWitness,
}

impl SpendableUtxo {
    pub fn new(
        utxo: Utxo,
        membership_proof: MsMembershipProof,
        lock_script_and_witness: LockScriptAndWitness,
    ) -> Self {
        Self {
            utxo,
            membership_proof,
            lock_script_and_witness,
        }
    }

    /// Return the `item` from the perspective of the mutator set
    pub fn mutator_set_item(&self) -> Digest {
        Tip5::hash(&self.utxo)
    }

    pub fn membership_proof(&self) -> &MsMembershipProof {
        &self.membership_proof
    }

    pub fn lock_script_and_witness(&self) -> &LockScriptAndWitness {
        &self.lock_script_and_witness
    }

    pub(crate) fn removal_record(&self, mutator_set: &MutatorSetAccumulator) -> RemovalRecord {
        let item = self.mutator_set_item();
        let msmp = self.membership_proof();
        mutator_set.drop(item, msmp)
    }
}

impl Deref for SpendableUtxo {
    type Target = Utxo;

    fn deref(&self) -> &Self::Target {
        &self.utxo
    }
}
