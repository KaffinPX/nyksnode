use std::collections::HashMap;
use std::sync::OnceLock;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;

use super::TypeScript;
use super::TypeScriptWitness;
use super::amount::total_amount_main_loop::DigestSource;
use super::amount::total_amount_main_loop::TotalAmountMainLoop;
use super::native_currency_amount::NativeCurrencyAmount;
use crate::block::MINING_REWARD_TIME_LOCK_PERIOD;
use crate::proof_abstractions::SecretWitness;
use crate::proof_abstractions::mast_hash::MastHash;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::timestamp::Timestamp;
use crate::transaction::salted_utxos::SaltedUtxos;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::transaction_kernel::TransactionKernelField;
use crate::transaction::validity::tasm::coinbase_amount::CoinbaseAmount;
use crate::type_scripts::BFieldCodec;
use crate::type_scripts::TypeScriptAndWitness;

impl NativeCurrency {
    pub const BAD_COINBASE_SIZE_ERROR: i128 = 1_000_030;
    pub const BAD_SALTED_UTXOS_ERROR: i128 = 1_000_031;
    pub const NO_INFLATION_VIOLATION: i128 = 1_000_032;
    pub const COINBASE_TIMELOCK_INSUFFICIENT: i128 = 1_000_033;
    pub const FEE_EXCEEDS_MAX: i128 = 1_000_034;
    pub const FEE_EXCEEDS_MIN: i128 = 1_000_035;
    pub const SUM_OF_OUTPUTS_EXCEEDS_MAX: i128 = 1_000_036;
    pub const SUM_OF_OUTPUTS_IS_NEGATIVE: i128 = 1_000_037;
    pub const COINBASE_IS_SET_AND_FEE_IS_NEGATIVE: i128 = 1_000_038;
    pub const INVALID_COIN_AMOUNT: i128 = 1_000_039;
    pub const INVALID_COINBASE_DISCRIMINANT: i128 = 1_000_040;
}

/// `NativeCurrency` is the type script that governs Neptune's native currency,
/// Neptune coins.
///
/// The arithmetic for amounts is defined by the struct `NativeCurrencyAmount`.
/// This type script is responsible for checking that transactions that transfer
/// Neptune are balanced, *i.e.*,
///
///  sum inputs  +  (optional: coinbase)  ==  sum outputs  +  fee .
///
/// Transactions that are not balanced in this way are invalid. Furthermore, the
/// type script checks that no overflow occurs while computing the sums.
///
/// Lastly, if the coinbase is set then at least half of this amount must be
/// time-locked for a month.
///
/// This consensus program assumes that coinbase transactions can never be
/// merged with negative-fee paying transactions, as the timelock of the
/// coinbase reward could otherwise be circumvented.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct NativeCurrency;

impl TritonProgram for NativeCurrency {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let field_with_size_coinbase = field_with_size!(NativeCurrencyWitnessMemory::coinbase);
        let field_fee = field!(NativeCurrencyWitnessMemory::fee);
        let field_timestamp = field!(NativeCurrencyWitnessMemory::timestamp);
        let field_with_size_salted_input_utxos =
            field_with_size!(NativeCurrencyWitnessMemory::salted_input_utxos);
        let field_with_size_salted_output_utxos =
            field_with_size!(NativeCurrencyWitnessMemory::salted_output_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);

        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify =
            library.import(Box::new(tasm_lib::hashing::merkle_verify::MerkleVerify));
        let coin_size = NativeCurrencyAmount::static_length().unwrap();
        let hash_fee = library.import(Box::new(HashStaticSize { size: coin_size }));
        let compare_coin_amount = DataType::compare_elem_of_stack_size(coin_size);
        let timestamp_size = 1;
        let hash_timestamp = library.import(Box::new(HashStaticSize {
            size: timestamp_size,
        }));
        let u128_overflowing_add = library.import(Box::new(
            tasm_lib::arithmetic::u128::overflowing_add::OverflowingAdd,
        ));
        let i128_shr = library.import(Box::new(
            tasm_lib::arithmetic::i128::shift_right::ShiftRight,
        ));
        let u128_lt = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));
        let i128_lt = library.import(Box::new(tasm_lib::arithmetic::i128::lt::Lt));
        let shift_right_one_u128 = library.import(Box::new(
            tasm_lib::arithmetic::u128::shift_right_static::ShiftRightStatic::<1>,
        ));
        let coinbase_pointer_to_amount = library.import(Box::new(CoinbaseAmount));
        let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
            NativeCurrencyWitnessMemory,
        >::default()));

        let own_program_digest_alloc = library.kmalloc(Digest::LEN as u32);
        let coinbase_release_date_alloc = library.kmalloc(1);

        let loop_utxos_add_amounts_label = library.import(Box::new(TotalAmountMainLoop {
            digest_source: DigestSource::StaticMemory(own_program_digest_alloc),
            release_date: coinbase_release_date_alloc,
        }));

        let store_own_program_digest = triton_asm!(
            // _

            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ [own_program_digest]

            push {own_program_digest_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _
        );

        let store_coinbase_release_date = triton_asm!(
            // _ release_date
            push {coinbase_release_date_alloc.write_address()}
            write_mem 1
            pop 1
            // _
        );

        let assert_coinbase_size = triton_asm!(
            // _ coinbase_size

            dup 0
            push 1
            eq
            // _ coinbase_size (coinbase_size == 1)

            dup 1
            push 5
            eq
            // _ coinbase_size (coinbase_size == 1) (coinbase_size == 5)

            add
            assert error_id {Self::BAD_COINBASE_SIZE_ERROR}
            // _ coinbase_size
        );

        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();
        let push_min_amount = NativeCurrencyAmount::min().push_to_stack();

        let digest_eq = DataType::Digest.compare();

        let authenticate_salted_utxos = triton_asm! {
            // BEFORE:
            // _ *salted_utxos size

            dup 1 swap 1
            // _ *salted_utxos *salted_utxos size

            call {hash_varlen}
            // _ *salted_utxos [salted_utxos_hash]

            read_io 5
            // _ *salted_utxos [salted_utxos_hash] [sud]

            {&digest_eq}
            assert error_id {Self::BAD_SALTED_UTXOS_ERROR}
            // _ *salted_utxos
        };

        let assert_half_output_amount_timelocked_label =
            "neptune_core_native_currency_assert_half_output_amount_timelocked";
        let assert_half_output_amount_timelocked = triton_asm! {
            {assert_half_output_amount_timelocked_label}:
            // _ [total_output] [timelocked_amount]

            dup 7
            dup 7
            dup 7
            dup 7
            // _ [total_output] [timelocked_amount] [total_output]

            call {shift_right_one_u128}
            // _ [total_output] [timelocked_amount] [total_output / 2]

            dup 7
            dup 7
            dup 7
            dup 7
            // _ [total_output] [timelocked_amount] [total_output / 2] [timelocked_amount]

            call {u128_lt}
            // _ [total_output] [timelocked_amount] (total_output / 2 > timelocked_amount)

            push 0
            eq
            // _ [total_output] [timelocked_amount] (total_output / 2 <= timelocked_amount)

            assert error_id {Self::COINBASE_TIMELOCK_INSUFFICIENT}
            // _ [total_output] [timelocked_amount]

            return
        };

        let main_code = triton_asm! {
            // _

            {&store_own_program_digest}
            // _

            read_io {Digest::LEN}
            hint txkmh: Digest = stack[0..5]
            // _ [txkmh]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint native_currency_witness_ptr = stack[0]
            // _ [txkmh] *ncw

            dup 0
            call {audit_preloaded_data}
            // _ [txkmh] *ncw witness_size

            pop 1
            // _ [txkmh] *ncw

            /* Divine and authenticate coinbase field */
            dup 0
            {&field_with_size_coinbase}
            hint coinbase_ptr = stack[1]
            hint coinbase_size = stack[0]
            // _ [txkmh] *ncw *coinbase coinbase_size

            {&assert_coinbase_size}
            // _ [txkmh] *ncw *coinbase coinbase_size

            dup 7 dup 7 dup 7 dup 7 dup 7
            // _ [txkmh] *ncw *coinbase coinbase_size [txkmh]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Coinbase as u32}
            // _ [txkmh] *ncw *coinbase coinbase_size [txkmh] h i

            dup 8 dup 8
            // _ [txkmh] *ncw *coinbase coinbase_size [txkmh] h i *coinbase coinbase_size

            call {hash_varlen}
            hint coinbase_hash: Digest = stack[0..5]
            // _ [txkmh] *ncw *coinbase coinbase_size [txkmh] h i [coinbase_digest]

            call {merkle_verify}
            // _ [txkmh] *ncw *coinbase coinbase_size

            pop 1
            // _ [txkmh] *ncw *coinbase


            /* Divine and authenticate fee field */
            dup 1
            // _ [txkmh] *ncw *coinbase *ncw

            {&field_fee}
            hint fee_ptr = stack[0]
            // _ [txkmh] *ncw *coinbase *fee

            dup 7
            dup 7
            dup 7
            dup 7
            dup 7
            // _ [txkmh] *ncw *coinbase *fee [txkmh]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Fee as u32}
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i

            dup 7
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i *fee

            call {hash_fee} pop 1
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i [fee_digest]

            call {merkle_verify}
            // _ [txkmh] *ncw *coinbase *fee


            /* Verify that fee is non-negative when coinbase is set */
            dup 1
            read_mem 1 pop 1
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant

            dup 0 push 0 eq
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant (coinbase_discriminant == 0)

            dup 1 push 1 eq
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant (coinbase_discriminant == 0) (coinbase_discriminant == 1)

            add assert error_id {Self::INVALID_COINBASE_DISCRIMINANT}
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant

            dup 1 addi {coin_size-1} read_mem {coin_size} pop 1
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant [fee]

            push 127 call {i128_shr}
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant [fee >> 127]
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant signs signs signs signs

            /* Top bit of fee is 0 for positive fee, 1 for negative.
               Shifting the fee right by 127 (sign-preserving shift) means
               *all* bits are either 1 or 0. So all `signs` limbs are also the
               same. So we only need to inspect one of them.
            */

            pop 3
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant signs

            push 2 place 1 div_mod
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant quotient sign

            place 1 pop 1
            // _ [txkmh] *ncw *coinbase *fee coinbase_discriminant sign

            add
            // _ [txkmh] *ncw *coinbase *fee (coinbase_discriminant + sign)

            /* Possible values of top stack element: {0, 1, 2}.
               Allowed: {0, 1} */

            push 2 eq
            // _ [txkmh] *ncw *coinbase *fee (coinbase_discriminant && sign)

            push 0 eq
            // _ [txkmh] *ncw *coinbase *fee (!coinbase_discriminant || !sign)

            assert error_id {Self::COINBASE_IS_SET_AND_FEE_IS_NEGATIVE}
            // _ [txkmh] *ncw *coinbase *fee


            /* Divine and authenticate timestamp */
            dup 7 dup 7 dup 7 dup 7 dup 7
            // _ [txkmh] *ncw *coinbase *fee [txkmh]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Timestamp as u32}
            // _ [txkmh] *ncw *coinbase *fee [txkmh] height index
            hint index = stack[0]
            hint height = stack[1]

            dup 9 {&field_timestamp}
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i *timestamp
            hint timestamp_ptr = stack[0]

            dup 0
            read_mem 1 pop 1
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i *timestamp timestamp

            push {MINING_REWARD_TIME_LOCK_PERIOD}
            add
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i *timestamp coinbase_release_date

            {&store_coinbase_release_date}
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i *timestamp

            call {hash_timestamp}
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i [timestamp_hash] *next_field

            pop 1
            // _ [txkmh] *ncw *coinbase *fee [txkmh] h i [timestamp_hash]

            call {merkle_verify}
            // _ [txkmh] *ncw *coinbase *fee
            hint fee_ptr = stack[0]


            /* Divine and authenticate salted input and output UTXOs */
            dup 2 {&field_with_size_salted_input_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_input_utxos size

            {&authenticate_salted_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_input_utxos

            dup 3 {&field_with_size_salted_output_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_input_utxos *salted_output_utxos size

            {&authenticate_salted_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_input_utxos *salted_output_utxos


            /* Compute left-hand side: sum inputs + (optional coinbase) */
            swap 1 {&field_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos *input_utxos

            read_mem 1 push 2 add
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N *input_utxos[0]_si

            push 0 swap 1
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si

            push 0 push 0 push 0
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si 0 0 0

            dup 8
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si 0 0 0 *coinbase

            call {coinbase_pointer_to_amount}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si 0 0 0 [coinbase]

            hint coinbase = stack[0..4]
            hint enn = stack[9]
            hint i = stack[8]
            hint utxos_i = stack[7]

            push 0 push 0 push 0 push 0
            hint timelocked_amount = stack[0..4]
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si 0 0 0 [coinbase] [timelocked_amount]

            call {loop_utxos_add_amounts_label}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] [timelocked_amount]

            pop 4
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input]

            hint total_input : u128 = stack[0..4]


            /* Compute right-hand side: fee + sum outputs */
            dup 11 dup 11
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee *salted_output_utxos

            {&field_utxos}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee *output_utxos

            read_mem 1 push 2 add
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N *output_utxos[0]_si
            hint utxos_0_si = stack[0]

            push 0 swap 1
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si

            push 0 push 0 push 0
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si 0 0 0

            push 0
            push 0
            push 0
            push 0
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si 0 0 0 [total_output]

            hint total_output = stack[0..4]
            hint utxos_i_si = stack[7]
            hint i = stack[8]
            hint enn = stack[9]

            push 0 push 0 push 0 push 0
            hint timelocked_amount = stack[0..4]
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si 0 0 0 [total_output] [timelocked_amount]

            call {loop_utxos_add_amounts_label}
            hint timelocked_amount = stack[0..4]
            hint total_output = stack[4..8]
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount]

            // sanity check total output
            dup 7
            dup 7
            dup 7
            dup 7
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] [total_output]

            {&push_max_amount}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] [total_output] [max_nau]

            call {i128_lt}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] (max_nau < total_output)

            push 0 eq
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] (max_nau >= total_output)

            assert error_id {Self::SUM_OF_OUTPUTS_EXCEEDS_MAX}

            push 0
            push 0
            push 0
            push 0
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] [0]

            dup 11
            dup 11
            dup 11
            dup 11
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] [0] [total_output]

            call {i128_lt}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] (total_output < 0)

            push 0 eq
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount] (total_output >= 0)

            assert error_id {Self::SUM_OF_OUTPUTS_IS_NEGATIVE}
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output] [timelocked_amount]


            /* Verify that coinbase transactions timelock half their output amount */
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            pick 8 pop 1
            // _ [txkmh] *ncw *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] [total_output] [timelocked_amount]

            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            pick 12 pop 1
            // _ [txkmh] *ncw *coinbase *fee [total_input] [total_output] [timelocked_amount]

            pick 13
            call {coinbase_pointer_to_amount}
            hint coinbase = stack[0..4]
            // _ [txkmh] *ncw *fee [total_input] [total_output] [timelocked_amount] [coinbase]

            /* If coinbase is non-zero assert that at least half of total output is timelocked */
            push 0
            push 0
            push 0
            push 0
            call {u128_lt}
            // _ [txkmh] *ncw *fee [total_input] [total_output] [timelocked_amount] (coinbase > 0)

            skiz
                call {assert_half_output_amount_timelocked_label}
            // _ [txkmh] *ncw *fee [total_input] [total_output] [timelocked_amount]

            pop {coin_size}
            // _ [txkmh] *ncw *fee [total_input] [total_output]

            pick 8 addi {coin_size-1}
            read_mem {coin_size}
            pop 1
            hint fee = stack[0..4]
            // _ [txkmh] *ncw [total_input] [total_output] [fee]

            dup 3
            dup 3
            dup 3
            dup 3
            {&push_max_amount}
            hint max_amount = stack[0..4]
            // _ [txkmh] *ncw [total_input] [total_output] [fee] [fee] [max_amount]

            call {i128_lt}
            // _ [txkmh] *ncw [total_input] [total_output] [fee] (max_amount < fee)

            push 0 eq
            // _ [txkmh] *ncw [total_input] [total_output] [fee] (fee <= max_amount)

            assert error_id {Self::FEE_EXCEEDS_MAX}
            // _ [txkmh] *ncw [total_input] [total_output] [fee]

            {&push_min_amount}
            hint min_amount = stack[0..4]
            // _ [txkmh] *ncw [total_input] [total_output] [fee] [min_amount]

            dup 7
            dup 7
            dup 7
            dup 7
            // _ [txkmh] *ncw [total_input] [total_output] [fee] [min_amount] [fee]

            call {i128_lt}
            // _ [txkmh] *ncw [total_input] [total_output] [fee] (fee < min_amount)

            push 0 eq
            // _ [txkmh] *ncw [total_input] [total_output] [fee] (fee >= min_amount)

            assert error_id {Self::FEE_EXCEEDS_MIN}
            // _ [txkmh] *ncw [total_input] [total_output] [fee]

            call {u128_overflowing_add}
            pop 1
            // _ [txkmh] *ncw [total_input] [total_output']

            {&compare_coin_amount}
            // _ [txkmh] *ncw (total_input == total_output')

            assert error_id {Self::NO_INFLATION_VIOLATION}
            // _ [txkmh] *ncw

            pop 1
            pop 5
            // _

            halt
        };

        let imports = library.all_imports();

        let code = triton_asm!(
            {&main_code}
            {&assert_half_output_amount_timelocked}
            {&imports}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

impl TypeScript for NativeCurrency {
    type State = NativeCurrencyAmount;
}

#[derive(Debug, Clone, Deserialize, Serialize, BFieldCodec, GetSize, PartialEq, Eq, TasmObject)]
pub struct NativeCurrencyWitness {
    pub salted_input_utxos: SaltedUtxos,
    pub salted_output_utxos: SaltedUtxos,
    pub kernel: TransactionKernel,
}

/// The part of witness data that is read from memory
///
/// Factored out since this makes auditing the preloaded data much cheaper as
/// we avoid having to audit the [TransactionKernel].
#[derive(Debug, Clone, BFieldCodec, TasmObject)]
struct NativeCurrencyWitnessMemory {
    salted_input_utxos: SaltedUtxos,
    salted_output_utxos: SaltedUtxos,
    coinbase: Option<NativeCurrencyAmount>,
    fee: NativeCurrencyAmount,
    timestamp: Timestamp,
}

impl From<&NativeCurrencyWitness> for NativeCurrencyWitnessMemory {
    fn from(value: &NativeCurrencyWitness) -> Self {
        Self {
            salted_input_utxos: value.salted_input_utxos.clone(),
            salted_output_utxos: value.salted_output_utxos.clone(),
            coinbase: value.kernel.coinbase,
            fee: value.kernel.fee,
            timestamp: value.kernel.timestamp,
        }
    }
}

impl TypeScriptWitness for NativeCurrencyWitness {
    fn new(
        transaction_kernel: TransactionKernel,
        salted_input_utxos: SaltedUtxos,
        salted_output_utxos: SaltedUtxos,
    ) -> Self {
        Self {
            salted_input_utxos,
            salted_output_utxos,
            kernel: transaction_kernel,
        }
    }

    fn transaction_kernel(&self) -> TransactionKernel {
        self.kernel.clone()
    }

    fn salted_input_utxos(&self) -> SaltedUtxos {
        self.salted_input_utxos.clone()
    }

    fn salted_output_utxos(&self) -> SaltedUtxos {
        self.salted_output_utxos.clone()
    }

    fn type_script_and_witness(&self) -> TypeScriptAndWitness {
        TypeScriptAndWitness::new_with_nondeterminism(
            NativeCurrency.program(),
            self.nondeterminism(),
        )
    }
}

impl SecretWitness for NativeCurrencyWitness {
    fn program(&self) -> Program {
        NativeCurrency.program()
    }

    fn standard_input(&self) -> PublicInput {
        self.type_script_standard_input()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        let memory_part_of_witness: NativeCurrencyWitnessMemory = self.into();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &memory_part_of_witness,
        );

        // individual tokens
        let individual_tokens = vec![];

        // digests
        let mast_paths = [
            self.kernel.mast_path(TransactionKernelField::Coinbase),
            self.kernel.mast_path(TransactionKernelField::Fee),
            self.kernel.mast_path(TransactionKernelField::Timestamp),
        ]
        .concat();

        // put everything together
        NonDeterminism::new(individual_tokens)
            .with_digests(mast_paths)
            .with_ram(memory)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::proof_abstractions::tasm::program::tests::test_program_snapshot;

    test_program_snapshot!(
        NativeCurrency,
        "76e11a0def69ae7761379955f776dc096a0858edd67b98049115da7e882951e2c11127bd85b10c20"
    );
}
