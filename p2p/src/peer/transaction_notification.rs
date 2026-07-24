use nyks_protocol::consensus::transaction::Transaction;
use nyks_protocol::consensus::transaction::TransactionProof;
use nyks_protocol::consensus::transaction::transaction_kernel_id::TransactionKernelId;
use nyks_protocol::consensus::transaction::transaction_proof::TransactionProofQuality;
use nyks_protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

/// Data structure for communicating knowledge of transactions.
///
/// A sender broadcasts to all peers a `TransactionNotification` when it has
/// received a transaction with the given `TransactionId`.  It is implied
/// that interested peers can request the full transaction object from this
/// sender.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionNotification {
    /// A unique identifier of the transaction. Matches keys in the [mempool]
    /// data structure.
    ///
    /// [mempool]: crate::state::mempool::Mempool
    pub txid: TransactionKernelId,

    /// The hash of the mutator set under which this transaction is valid.
    /// The receiver can use this to check if it matches their tip. If not, they
    /// can choose to ignore the transaction.
    pub mutator_set_hash: Digest,

    /// The quality of the proof. Denotes how much effort it takes to get the
    /// transaction included in a block. Higher quality means less effort.
    pub proof_quality: TransactionProofQuality,

    /// How much fee is the transaction paying?
    pub fee: NativeCurrencyAmount,

    /// How many inputs does the transaction have?
    pub num_inputs: u64,

    /// How many outputs does the transaction have?
    pub num_outputs: u64,
}

impl From<&Transaction> for TransactionNotification {
    fn from(transaction: &Transaction) -> Self {
        let proof_quality = match &transaction.proof {
            TransactionProof::SingleProof(_) => TransactionProofQuality::SingleProof,
            TransactionProof::ProofCollection(_) => TransactionProofQuality::ProofCollection,
        };

        Self {
            txid: transaction.kernel.txid(),
            mutator_set_hash: transaction.kernel.mutator_set_hash,
            proof_quality,
            fee: transaction.kernel.fee,
            num_inputs: transaction.kernel.inputs.len().try_into().unwrap(),
            num_outputs: transaction.kernel.outputs.len().try_into().unwrap(),
        }
    }
}
