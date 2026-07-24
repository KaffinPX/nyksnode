use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use crate::consensus::mutator_set::addition_record::AdditionRecord;
use crate::consensus::mutator_set::commit;
use crate::consensus::transaction::utxo::Utxo;

/// Represents the preimage of a transaction output, so not just the UTXO but
/// also the randomnesses.
#[derive(Debug, Clone, BFieldCodec)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct UtxoTriple {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_digest: Digest,
}

impl UtxoTriple {
    pub fn new(utxo: Utxo, sender_randomness: Digest, receiver_digest: Digest) -> Self {
        UtxoTriple {
            utxo,
            sender_randomness,
            receiver_digest,
        }
    }

    pub fn addition_record(&self) -> AdditionRecord {
        commit(
            Tip5::hash(&self.utxo),
            self.sender_randomness,
            self.receiver_digest,
        )
    }
}
