use tasm_lib::data_type::DataType;
use tasm_lib::field_with_size;
use tasm_lib::library::StaticAllocation;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use crate::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::consensus::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField;
use crate::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

const UNEQUAL_DISCRIMINANT_ERROR: i128 = 1_000_020;
const UNEQUAL_VALUE_ERROR: i128 = 1_000_021;
const RIGHT_INPUT_COINBASE_ERROR: i128 = 1_000_022;

/// Authenticate coinbase fields of left, right, and new kernels. Verify that
/// at most one from (left, right) is set. Verify that the one that is set (if
/// any) matches new.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticateCoinbaseFields {
    left_txk_mast_hash_alloc: StaticAllocation,
    right_txk_mast_hash_alloc: StaticAllocation,
    new_txk_mast_hash_alloc: StaticAllocation,
}

impl AuthenticateCoinbaseFields {
    pub fn new(
        left_txk_mast_hash_alloc: StaticAllocation,
        right_txk_mast_hash_alloc: StaticAllocation,
        new_txk_mast_hash_alloc: StaticAllocation,
    ) -> Self {
        assert_eq!(Digest::LEN as u32, left_txk_mast_hash_alloc.num_words());
        assert_eq!(Digest::LEN as u32, right_txk_mast_hash_alloc.num_words());
        assert_eq!(Digest::LEN as u32, new_txk_mast_hash_alloc.num_words());
        Self {
            left_txk_mast_hash_alloc,
            right_txk_mast_hash_alloc,
            new_txk_mast_hash_alloc,
        }
    }
}

impl BasicSnippet for AuthenticateCoinbaseFields {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "left_tx_kernel".to_owned()),
            (DataType::VoidPointer, "right_tx_kernel".to_owned()),
            (DataType::VoidPointer, "new_tx_kernel".to_owned()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_merge_authenticate_coinbase_fields".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        const DISCRIMINANT_SIZE: usize = 1;

        let entrypoint = self.entrypoint();

        let kernel_field_coinbase_and_size = field_with_size!(TransactionKernel::coinbase);

        let authenticate_txk_coinbase_field = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Coinbase,
        )));

        let some_coinbase_field_size =
            NativeCurrencyAmount::static_length().unwrap() + DISCRIMINANT_SIZE;
        let compare_some_coinbases = DataType::compare_elem_of_stack_size(some_coinbase_field_size);

        let assert_coinbase_equality_label = format!("{entrypoint}_assert_eq");
        let assert_coinbase_equality = triton_asm!(
            // BEFORE: _  *coinbase_a *coinbase_b
            // AFTER:  _  *coinbase_a *coinbase_b
            {assert_coinbase_equality_label}:
                // _ *coinbase_a *coinbase_b

                /* Assert discriminant equality */
                read_mem 1
                addi 1
                // _  *coinbase_a b_discriminant *coinbase_b

                swap 2
                read_mem 1
                addi 1
                // _  *coinbase_b b_discriminant a_discriminant *coinbase_a

                place 3
                // _  *coinbase_a *coinbase_b b_discriminant a_discriminant

                dup 1
                eq
                assert error_id {UNEQUAL_DISCRIMINANT_ERROR}
                // _  *coinbase_a *coinbase_b discriminant

                /* If discriminant == 0, we are done (coinbase == None) */
                push 0
                eq
                skiz
                    return

                /* Coinbase is Some(cb); assert value equality */
                // _  *coinbase_a *coinbase_b

                dup 1
                addi {some_coinbase_field_size - 1}
                read_mem {some_coinbase_field_size}
                pop 1
                // _  *coinbase_a *coinbase_b [coinbase_a; 5]

                dup 5
                addi {some_coinbase_field_size - 1}
                read_mem {some_coinbase_field_size}
                pop 1
                // _  *coinbase_a *coinbase_b [coinbase_a; 5] [coinbase_b; 5]

                {&compare_some_coinbases}
                // _ *coinbase_a *coinbase_b (coinbase_a == coinbase_b)

                assert error_id {UNEQUAL_VALUE_ERROR}
                // _ *coinbase_a *coinbase_b

                return
        );

        let assert_coinbases_right_not_set = triton_asm! {
                // _ *new_txk *left_coinbase *right_coinbase
                dup 0
                read_mem 1
                pop 1
                // _ *new_txk *left_coinbase *right_coinbase right_coinbase_discriminant

                push 0
                eq
                // _ *new_txk *left_coinbase *right_coinbase right_coinbase.is_none()

                assert error_id {RIGHT_INPUT_COINBASE_ERROR}
                // _ *new_txk *left_coinbase *right_coinbase
        };

        triton_asm!(
            {entrypoint}:
                /*
                    1. Get left coinbase field and authenticate
                    2. Get right coinbase field and authenticate
                    3. Assert that not both coinbase fields are set (Genesis)
                    3. Assert that right coinbase is not set (HardFork2)
                    4. Verify that the one set (if set) matches new
                    5. Authenticate calculated new against new_txkmh
                 */

                // _ *left_txk *right_txk *new_txk


                /* 1. */
                push {self.left_txk_mast_hash_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                pick 7
                // _ *right_txk *new_txk [left_txkmh] *left_txk

                {&kernel_field_coinbase_and_size}
                // _ *right_txk *new_txk [left_txkmh] *left_coinbase size

                dup 1
                place 7
                // _ *right_txk *new_txk *left_coinbase [left_txkmh] *left_coinbase size

                call {authenticate_txk_coinbase_field}
                // _ *right_txk *new_txk *left_coinbase


                /* 2. */
                push {self.right_txk_mast_hash_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ *right_txk *new_txk *left_coinbase [right_txkmh]

                pick 7
                // _ *new_txk *left_coinbase [right_txkmh] *right_txk

                {&kernel_field_coinbase_and_size}
                // _ *new_txk *left_coinbase [right_txkmh] *right_coinbase size

                dup 1
                place 7
                // _ *new_txk *left_coinbase *right_coinbase [right_txkmh] *right_coinbase size

                call {authenticate_txk_coinbase_field}
                // _ *new_txk *left_coinbase *right_coinbase


                /* 3. */
                {&assert_coinbases_right_not_set}
                // _ *new_txk *left_coinbase *right_coinbase


                /*  Goal: Put the `maybe` coinbase on top */
                pop 1
                // _ *new_txk *maybe_coinbase

                /* maybe_coinbase must match that in `new_txk` */
                swap 1
                // _ *maybe_coinbase *new_txk

                {&kernel_field_coinbase_and_size}
                // _ *maybe_coinbase *new_coinbase new_cb_size

                place 2
                // _ new_cb_size *maybe_coinbase *new_coinbase

                /* Assert equality */
                call {assert_coinbase_equality_label}
                // _ new_cb_size *new_coinbase *new_coinbase

                pop 1
                // _ new_cb_size *new_coinbase

                /* Authenticate new_coinbase against txkmh */
                push {self.new_txk_mast_hash_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ new_cb_size *new_coinbase [new_txkmh]

                pick 5
                pick 6
                // _ [new_txkmh] *new_coinbase new_cb_size

                call {authenticate_txk_coinbase_field}
                // _

                return

                {&assert_coinbase_equality}
        )
    }
}
