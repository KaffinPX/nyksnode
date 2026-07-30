use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::*;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;

use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::validity::kernel_to_outputs::KernelToOutputs;
use crate::transaction::validity::proof_collection::ProofCollection;
use crate::transaction::validity::tasm::claims::new_claim::NewClaim;

pub struct GenerateK2oClaim;

impl BasicSnippet for GenerateK2oClaim {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_digest".to_owned()),
            (DataType::Bfe, "garb0".to_string()),
            (DataType::Bfe, "garb1".to_string()),
            (DataType::VoidPointer, "proof_collection_pointer".to_owned()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_digest".to_owned()),
            (DataType::Bfe, "garb0".to_string()),
            (DataType::Bfe, "garb1".to_string()),
            (DataType::VoidPointer, "proof_collection_pointer".to_owned()),
            (DataType::VoidPointer, "claim".to_owned()),
        ]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_proof_collection_store_k2o_claim".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        const INPUT_LENGTH: usize = Digest::LEN;
        const OUTPUT_LENGTH: usize = Digest::LEN;

        let entrypoint = self.entrypoint();

        let push_digest = |d: Digest| {
            let [d0, d1, d2, d3, d4] = d.values();
            triton_asm! {
                push {d4}
                push {d3}
                push {d2}
                push {d1}
                push {d0}
            }
        };
        let push_k2os_program_hash = push_digest(KernelToOutputs.program().hash());

        let proof_collection_field_salted_outputs_hash =
            field!(ProofCollection::salted_outputs_hash);

        let load_digest = triton_asm!(
            // _ *digest

            addi {Digest::LEN - 1}
            read_mem {Digest::LEN}
            pop 1
            // _ [digest]
        );

        let new_claim = library.import(Box::new(NewClaim));

        triton_asm!(
            // BEFORE: _ [txk_digest] garb0 garb1 *proof_collection
            // AFTER:  _ [txk_digest] garb0 garb1 *proof_collection *claim
            {entrypoint}:

                push {OUTPUT_LENGTH}
                push {INPUT_LENGTH}
                call {new_claim}
                // _ [txk_digest] garb0 garb1 *proof_collection *claim *output *input *program_digest


                /* put the program digest on stack, then write to memory */
                {&push_k2os_program_hash}
                dup {Digest::LEN}
                write_mem {Digest::LEN}
                pop 2
                // _ [txk_digest] garb0 garb1 *proof_collection *claim *output *input


                /* put input onto stack, then write to memory */
                dup 6
                dup 8
                dup 10
                dup 12
                dup 14
                dup 5
                write_mem {Digest::LEN}
                pop 2
                // _ [txk_digest] garb0 garb1 *proof_collection *claim *output


                /* put output onto stack, then write to memory */
                dup 2

                {&proof_collection_field_salted_outputs_hash}

                {&load_digest}
                // _ [txk_digest] garb0 garb1 *proof_collection *claim *output [salted_outputs_hash]

                dup 5
                write_mem {Digest::LEN}
                pop 2
                // _ [txk_digest] garb0 garb1 *proof_collection *claim

                return
        )
    }
}
