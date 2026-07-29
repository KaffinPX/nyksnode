use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::*;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;

use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::validity::collect_lock_scripts::CollectLockScripts;
use crate::transaction::validity::proof_collection::ProofCollection;
use crate::transaction::validity::tasm::claims::new_claim::NewClaim;

pub struct GenerateCollectLockScriptsClaim;

impl BasicSnippet for GenerateCollectLockScriptsClaim {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "proof_collection_pointer".to_owned())]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "claim".to_owned())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_proof_collection_generate_collect_lock_scripts_claim".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();
        let push_collect_lock_scripts_hash = {
            let Digest([d0, d1, d2, d3, d4]) = CollectLockScripts.program().hash();
            triton_asm!(push {d4} push {d3} push {d2} push {d1} push {d0})
        };

        let new_claim = library.import(Box::new(NewClaim));
        let lock_script_hashes_loop = format!("{entrypoint}_lock_script_hashes_loop");

        triton_asm!(
            {entrypoint}:
                // _ *proof_collection

                dup 0
                {&field_with_size!(ProofCollection::lock_script_hashes)}
                // _ *proof_collection *ls_hashes ls_hashes_si

                /* calculate end of `ls_hashes` list */
                dup 1
                dup 1
                add
                addi {Digest::LEN - 1}
                // _ *proof_collection *ls_hashes ls_hashes_si (*ls_hashes[last+1]_lw)

                pick 2
                read_mem 1
                addi {1 + Digest::LEN}
                // _ *proof_collection ls_hashes_si (*ls_hashes[last+1]_lw) ls_hashes_len *ls_hashes[0]_lw

                /* assert correct size indicator */
                pick 1
                push {Digest::LEN}
                mul
                addi 1
                // _ *proof_collection ls_hashes_si (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw (5 * ls_hashes_len + 1)

                dup 3
                eq
                assert
                // _ *proof_collection ls_hashes_si (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw

                pick 2
                addi -1
                hint output_len = stack[0]
                // _ *proof_collection (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw output_len

                push {Digest::LEN}
                place 1
                // _ *proof_collection (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw input_len output_len

                call {new_claim}
                // _ *proof_collection (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw *claim *output *input *program_digest

                {&push_collect_lock_scripts_hash}
                hint collect_lock_scripts_hash: Digest = stack[0..5]
                pick 5
                write_mem {Digest::LEN}
                pop 1
                // _ *proof_collection (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw *claim *output *input

                /* Load claim's input reversed, since given as input in stream-form */
                pick 5
                {&field!(ProofCollection::salted_inputs_hash)}
                addi {Digest::LEN - 1}
                read_mem {Digest::LEN}
                hint salted_inputs_hash: Digest = stack[1..6]
                pop 1
                pick 1 pick 2 pick 3 pick 4
                // _ (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw *claim *output *input [reversed(salted_inputs_hash)]

                pick 5
                write_mem {Digest::LEN}
                pop 1
                // _ (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw *claim *output

                pick 1
                place 3
                // _ *claim (*ls_hashes[last+1]_lw) *ls_hashes[0]_lw *output

                call {lock_script_hashes_loop}
                // _ *claim (*ls_hashes[last+1]_lw) (*ls_hashes[last+1]_lw) *garbage

                pop 3
                return

            // INVARIANT: _ (*ls_hashes[last+1]_lw) *ls_hashes[n]_lw (*claim.output[n])
            {lock_script_hashes_loop}:
                /* Loop end-condition */
                dup 2
                dup 2
                eq
                skiz
                    return

                pick 1
                read_mem {Digest::LEN}
                addi {Digest::LEN * 2}
                place 6
                // _ (*ls_hashes[last+1]_lw) *ls_hashes[n+1]_lw (*claim.output[n]) [ls_hash[n]]

                pick 5
                write_mem {Digest::LEN}
                // _ (*ls_hashes[last+1]_lw) *ls_hashes[n+1]_lw (*claim.output[n+1])

                recurse
        )
    }
}
