use tasm_lib::data_type::DataType;
use tasm_lib::library::Library;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::triton_vm::prelude::*;

use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

pub struct CoinbaseAmount;

impl CoinbaseAmount {
    pub const ILLEGAL_COINBASE_AMOUNT_ERROR: i128 = 1_000_200;
}

/// Map a pointer to a coinbase object to its amount (if some) or (if none)
/// zero.
///
/// Panics if coinbase amount is negative.
impl BasicSnippet for CoinbaseAmount {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*coinbase".to_owned())]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::U128, "coinbase_amount".to_owned())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_coinbase_amount".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();

        // `Coinbase` has type `Option<NativeCurrencyAmount>` where the
        // discriminant from `Option` is one word, and `NativeCurrencyAmount` is
        // four words, as it is represented by a u128.
        let size_minus_one = NativeCurrencyAmount::static_length().unwrap();

        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();
        let u128_lt = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));

        let has_coinbase_label = format!("{entrypoint}_has_coinbase");
        let has_coinbase = triton_asm!(
            {has_coinbase_label}:
                // _ *coinbase 1

                pop 1
                push {size_minus_one}
                add
                // _ *coinbase_lw

                read_mem {size_minus_one}
                pop 1
                // _ [coinbase_amount]

                /* assert 0 <= coinbase < max_amount */
                dup 3
                dup 3
                dup 3
                dup 3
                {&push_max_amount}
                call {u128_lt}
                push 0 eq
                // _ [coinbase_amount] (coinbase_amount <= max)

                assert error_id {Self::ILLEGAL_COINBASE_AMOUNT_ERROR}
                // _ [coinbase_amount]

                push 0
                // _ [coinbase_amount] 0

                return
        );

        let no_coinbase_label = format!("{entrypoint}_no_coinbase");
        let no_coinbase = triton_asm!(
            {no_coinbase_label}:
                // _ *coinbase

                pop 1
                // _

                push 0
                push 0
                push 0
                push 0
                // _ [0]

                return
        );

        let assert_discriminant = triton_asm!(
            // _ coinbase_discriminant

            dup 0
            push 0
            eq
            // _ coinbase_discriminant (coinbase_discriminant == 0)

            swap 1
            push 1
            eq
            // _ (coinbase_discriminant == 0) (coinbase_discriminant == 1)

            add
            // _ (coinbase_discriminant == 0 || coinbase_discriminant == 1)

            assert
            // _
        );

        triton_asm!(
            {entrypoint}:
                // _ *coinbase

                dup 0
                read_mem 1
                pop 1
                // _ *coinbase coinbase_discriminant

                dup 0
                {&assert_discriminant}
                // _ *coinbase coinbase_discriminant

                push 1
                swap 1
                // _ *coinbase 1 coinbase_discriminant

                skiz call {has_coinbase_label}
                skiz call {no_coinbase_label}
                // _ [coinbase_amount]

                return

                {&has_coinbase}
                {&no_coinbase}
        )
    }
}
