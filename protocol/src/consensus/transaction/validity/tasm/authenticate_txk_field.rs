use tasm_lib::data_type::DataType;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::proof_abstractions::mast_hash::MastHash;

#[derive(Debug, Clone, Copy)]
pub struct AuthenticateTxkField(pub TransactionKernelField);

impl BasicSnippet for AuthenticateTxkField {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_mast_hash".to_owned()),
            (DataType::VoidPointer, "field".to_owned()),
            (DataType::U32, "field_size".to_owned()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        format!(
            "neptune_transaction_authenticate_field_{}_against_txk_mast_hash",
            self.0
        )
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();

        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify = library.import(Box::new(MerkleVerify));

        triton_asm!(
            {entrypoint}:
                // _ [root] *field field_size

                push {self.0 as u32}
                swap 1
                // _ [root] *field leaf_index field_size

                push {TransactionKernel::MAST_HEIGHT}
                swap 3
                swap 1
                // _ [root] height leaf_index *field field_size

                call {hash_varlen}
                // _ [root] height leaf_index [field_hash]

                call {merkle_verify}
                // _

                return
        )
    }
}
