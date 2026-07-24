use tasm_lib::data_type::DataType;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::mmr::bag_peaks::BagPeaks;
use tasm_lib::prelude::*;
use tasm_lib::twenty_first::prelude::Digest;

use crate::consensus::transaction::TransactionKernel;
use crate::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::proof_abstractions::mast_hash::MastHash;
use crate::triton_vm::prelude::*;

/// Authenticate a mutator set accumulator against a transaction-kernel mast hash
///
/// Crashes the VM if the mutator set does not belong in the Merkle tree from
/// which the transaction-kernel mast hash was built.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticateMsaAgainstTxk;

impl BasicSnippet for AuthenticateMsaAgainstTxk {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "aocl_mmr".to_owned()),
            (DataType::VoidPointer, "swbfi_bagged_ptr".to_owned()),
            (DataType::VoidPointer, "swbfa_digest_ptr".to_owned()),
            (DataType::Digest, "transaction_kernel_digest".to_owned()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_authenticate_msa_against_txk".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();
        let load_digest = triton_asm!(
            // _ *digest

            addi {Digest::LEN - 1}
            // _ *digest_lw

            read_mem {Digest::LEN}
            pop 1
            // _ [digest]
        );

        let swap_top_two_digests = triton_asm!(
            swap 5
            swap 4
            swap 9
            swap 4
            swap 3
            swap 8
            swap 3
            swap 2
            swap 7
            swap 2
            swap 1
            swap 6
            swap 1
        );

        let merkle_verify = library.import(Box::new(MerkleVerify));

        let bag_mmr_peaks = library.import(Box::new(BagPeaks));
        triton_asm!(
            {entrypoint}:
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash]

                push {TransactionKernel::MAST_HEIGHT}
                push {TransactionKernelField::MutatorSetHash as u32}
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i

                dup 8
                {&load_digest}
                hint swbfi_bagged: Digest = stack[0..5]
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [swbfi_bagged]

                dup 14
                call {bag_mmr_peaks}
                hint aocl_bagged: Digest = stack[0..5]
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [swbfi_bagged] [aocl_mmr_bagged]

                hash
                hint left: Digest = stack[0..5]
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left]

                push 0
                push 0
                push 0
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] 0 0 0

                dup 15
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] 0 0 0 *swbfa_digest

                push 0
                push 0
                swap 2
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] [0; digest] *swbfa_digest
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] [default_digest] *swbfa_digest

                {&load_digest}
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] [default_digest] [swbfa_digest]

                hash
                hint right: Digest = stack[0..5]
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [left] [right]

                {&swap_top_two_digests}
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [right] [left]

                hash
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [msah]

                push 0
                push 0
                push 0
                push 0
                push 1
                {&swap_top_two_digests}
                sponge_init
                sponge_absorb
                sponge_squeeze
                swap 5 pop 1
                swap 5 pop 1
                swap 5 pop 1
                swap 5 pop 1
                swap 5 pop 1
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest [txk_mast_hash] h i [msah_digest]

                call {merkle_verify}
                // _ *aocl_mmr *swbfi_bagged *swbfa_digest

                pop 3
                // _

                return
        )
    }
}
