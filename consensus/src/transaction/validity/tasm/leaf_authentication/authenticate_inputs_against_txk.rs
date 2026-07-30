use tasm_lib::data_type::DataType;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;

use crate::proof_abstractions::mast_hash::MastHash;
use crate::transaction::TransactionKernel;
use crate::transaction::transaction_kernel::TransactionKernelField;
use crate::triton_vm::prelude::*;

/// Authenticate transaction inputs against the transaction kernel mast hash.
///
/// Crashes the VM if the inputs and provided non-determinism does not match
/// the MAST hash.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticateInputsAgainstTxk;

impl BasicSnippet for AuthenticateInputsAgainstTxk {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_mast_hash".to_owned()),
            // Type of `inputs` is Vec<RemovalRecord>
            (DataType::VoidPointer, "inputs".to_owned()),
            (DataType::U32, "inputs_size".to_owned()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_authenticate_inputs_against_txk"
            .to_owned()
            .to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();

        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify = library.import(Box::new(MerkleVerify));

        triton_asm!(
            {entrypoint}:
                // _ [root] *inputs inputs_size

                push {TransactionKernelField::Inputs as u32}
                swap 1
                // _ [root] *inputs leaf_index inputs_size

                push {TransactionKernel::MAST_HEIGHT}
                swap 3
                swap 1
                // _ [root] height leaf_index *inputs inputs_size

                call {hash_varlen}
                // _ [root] height leaf_index [inputs_hash]

                call {merkle_verify}
                // _

                return
        )
    }
}
