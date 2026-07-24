use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::*;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;

use crate::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrity;
use crate::consensus::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::proof_abstractions::tasm::program::TritonProgram;

/// Generates a `RemovalRecordsIntegrity` `Claim` from a `ProofCollection` object.
///
/// Assumes the transaction kernel MAST hash is on the stack somewhere, but not
/// necessarily immediately preceding the proof collection pointer.
#[derive(Debug, Copy, Clone)]
pub struct GenerateRriClaim;

impl BasicSnippet for GenerateRriClaim {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_digest".to_owned()),
            (DataType::Bfe, "garb1".to_string()),
            (DataType::Bfe, "garb0".to_string()),
            (DataType::VoidPointer, "proof_collection_pointer".to_owned()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "transaction_kernel_digest".to_owned()),
            (DataType::Bfe, "garb1".to_string()),
            (DataType::Bfe, "garb0".to_string()),
            (DataType::VoidPointer, "proof_collection_pointer".to_owned()),
            (DataType::VoidPointer, "claim".to_owned()),
        ]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_proof_collection_store_rri_claim".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
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
        let push_rri_program_hash = push_digest(RemovalRecordsIntegrity.program().hash());

        let proof_collection_field_salted_inputs_hash = field!(ProofCollection::salted_inputs_hash);

        let load_digest = triton_asm!(
            // _ *digest

            addi {Digest::LEN - 1}
            read_mem {Digest::LEN}
            pop 1
            // _ [digest]
        );

        let new_claim = library.import(Box::new(NewClaim));
        let input_length = Digest::LEN;
        let output_length = Digest::LEN;

        triton_asm!(
            // BEFORE: _ [txk_digest] garb garb *proof_collection
            // AFTER:  _ [txk_digest] garb garb *proof_collection *rri_claim
            {entrypoint}:

                push {input_length}
                push {output_length}
                call {new_claim}
                // _ [txk_digest] garb garb *proof_collection *claim *output *input *program_digest


                /* put the program digest on stack, then write to memory */
                {&push_rri_program_hash}
                // _ [txk_digest] garb garb *proof_collection *claim *output *input *program_digest [program_digest]

                dup 5 write_mem 5 pop 2
                // _ [txk_digest] garb garb *proof_collection *claim *output *input


                /* put input on stack, then write to memory */
                dup 6
                dup 8
                dup 10
                dup 12
                dup 14
                // _ [txk_digest] garb garb *proof_collection *claim *output *input [txk_digest_reversed]

                dup 5
                write_mem 5
                pop 2
                // _ [txk_digest] garb garb *proof_collection *claim *output

                /* put the output on stack, then write to memory */
                dup 2 {&proof_collection_field_salted_inputs_hash}
                // _ [txk_digest] garb garb *proof_collection *claim *output *salted_inputs_hash

                {&load_digest}
                // _ [txk_digest] garb garb *proof_collection *claim *output [salted_inputs_hash]

                dup 5 write_mem 5 pop 2
                // _ [txk_digest] garb garb *proof_collection *claim

                return
        )
    }
}
