use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use crate::type_scripts::amount::total_amount_main_loop::DigestSource;
use crate::type_scripts::amount::total_amount_main_loop::TotalAmountMainLoop;

#[derive(Debug, Clone, Copy)]
pub struct GetTotalAndTimeLockedAmounts {
    type_script_hash: Digest,
}

impl BasicSnippet for GetTotalAndTimeLockedAmounts {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*list_of_utxos".to_string()),
            (DataType::Bfe, "release_date".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U128, "total_amount".to_string()),
            (DataType::U128, "total_timelocked".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_get_total_and_timelocked_amounts".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let release_date_allocation = library.kmalloc(1);
        let total_amount_main_loop = TotalAmountMainLoop {
            digest_source: DigestSource::Hardcode(self.type_script_hash),
            release_date: release_date_allocation,
        };
        let total_amount_main_loop_label = library.import(Box::new(total_amount_main_loop));

        triton_asm! {
            // BEFORE: _ *utxos release_date
            // AFTER: _ [total_amount] [total_timelocked]
            {self.entrypoint()}:
                push {release_date_allocation.write_address()}
                write_mem 1
                pop 1
                // _ *utxos

                read_mem 1 addi 2
                // _ N *utxos[0]_si

                push 0 place 1
                // _ N 0 *utxos[0]_si

                push 0
                push 0
                push 0
                // _ N 0 *utxos[i]_si * * *

                push 0
                push 0
                push 0
                push 0
                // _ N 0 *utxos[i]_si * * * [amount1]

                push 0
                push 0
                push 0
                push 0
                // _ N 0 *utxos[i]_si * * * [amount1] [amount2]

                call {total_amount_main_loop_label}
                // _ N N *eof * * * [amount] [timelocked_amount]

                pick 8 pop 1
                pick 8 pop 1
                pick 8 pop 1
                pick 8 pop 1
                pick 8 pop 1
                pick 8 pop 1
                // _ [amount] [timelocked_amount]

                return
        }
    }
}
