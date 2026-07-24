use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::new_claim::NewClaim;
use crate::consensus::transaction::validity::proof_collection::ProofCollection;

pub struct GenerateTypeScriptClaimTemplate;

impl BasicSnippet for GenerateTypeScriptClaimTemplate {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*proof_collection".to_string())]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*claim".to_string()),
            (DataType::VoidPointer, "*program_digest".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_generate_type_script_claim_template".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_claim = library.import(Box::new(NewClaim));

        let load_digest = triton_asm!(addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1);
        let reverse_digest = triton_asm!(pick 1 pick 2 pick 3 pick 4);

        let entrypoint = self.entrypoint();
        triton_asm! {
            // BEFORE: _ *proof_collection
            // AFTER:  _ *claim *program_digest
            {entrypoint}:

                push {3 * Digest::LEN}
                push 0
                call {new_claim}
                // _ *proof_collection *claim *output *input *program_digest

                place 2
                // _ *proof_collection *claim *program_digest *output *input


                /* write txk mast hash (reversed) to input */
                dup 4
                {&field!(ProofCollection::kernel_mast_hash)}
                // _ *proof_collection *claim *program_digest *output *input *txkmh

                {&load_digest}
                {&reverse_digest}
                // _ *proof_collection *claim *program_digest *output *input [txkmh_rev]

                pick 5
                write_mem {Digest::LEN}
                // _ *proof_collection *claim *program_digest *output (*input+5)


                /* write salted inputs hash (reversed) to input */
                dup 4
                {&field!(ProofCollection::salted_inputs_hash)}
                // _ *proof_collection *claim *program_digest *output (*input+5) *salted_inputs_hash

                {&load_digest}
                {&reverse_digest}
                // _ *proof_collection *claim *program_digest *output (*input+5) [salted_inputs_hash_reversed]

                pick 5
                write_mem {Digest::LEN}
                // _ *proof_collection *claim *program_digest *output (*input+10)


                /* write salted outputs hash (reversed) to input */
                pick 4
                {&field!(ProofCollection::salted_outputs_hash)}
                // _ *claim *program_digest *output (*input+10) *salted_outputs_hash

                {&load_digest}
                {&reverse_digest}
                // _ *claim *program_digest *output (*input+10) [salted_outputs_hash_reversed]

                pick 5
                write_mem {Digest::LEN}
                // _ *claim *program_digest *output (*input+15)

                pop 2
                // _ *claim *program_digest

                return
        }
    }
}
