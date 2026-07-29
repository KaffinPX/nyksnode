use std::collections::HashMap;
use std::sync::OnceLock;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::library::Library;
use tasm_lib::list::contains::Contains;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use triton_vm::prelude::NonDeterminism;
use triton_vm::prelude::PublicInput;

use crate::prelude::triton_vm;
use crate::proof_abstractions::SecretWitness;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::salted_utxos::SaltedUtxos;
use crate::transaction::utxo::Coin;
use crate::transaction::utxo::Utxo;
use crate::type_scripts::native_currency::NativeCurrency;

/// Maximum number of inputs/outputs allowed. Number of UTXOs must be strictly
/// less than this number.
const MAX_NUM_INPUTS_AND_OUTPUTS: usize = 100_000;

/// Maximum number of coins per UTXO allowed. Number of coins must be strictly
/// less than this number.
const MAX_NUM_COINS_PER_UTXOS: usize = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct CollectTypeScriptsWitness {
    pub salted_input_utxos: SaltedUtxos,
    pub salted_output_utxos: SaltedUtxos,
}

impl SecretWitness for CollectTypeScriptsWitness {
    fn standard_input(&self) -> PublicInput {
        [&self.salted_input_utxos, &self.salted_output_utxos]
            .map(|utxos| Tip5::hash(utxos).reversed().values().to_vec())
            .concat()
            .into()
    }

    fn output(&self) -> Vec<BFieldElement> {
        let type_script_hashes = Utxo::type_script_hashes(
            self.salted_input_utxos
                .utxos
                .iter()
                .chain(&self.salted_output_utxos.utxos),
        );
        type_script_hashes
            .into_iter()
            .flat_map(|d| d.values())
            .collect_vec()
    }

    fn program(&self) -> Program {
        CollectTypeScripts.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );

        NonDeterminism::default().with_ram(memory)
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct CollectTypeScripts;

impl CollectTypeScripts {
    // cannot be triggered
    const EMPTY_TYPE_SCRIPT_HASH_LIST: i128 = 1_000_510;

    // cannot be triggered
    const FIRST_TYPE_SCRIPT_HASH_NOT_NATIVE_CURRENCY: i128 = 1_000_511;

    // cannot be triggered
    const SALTED_UTXOS_TOO_SMALL: i128 = 1_000_512;

    const NON_INTEGRAL_SALTED_UTXOS: i128 = 1_000_513;

    const TOO_MANY_INPUTS_OR_OUTPUTS: i128 = 1_000_514;

    const TOO_MANY_COINS: i128 = 1_000_515;
}

impl TritonProgram for CollectTypeScripts {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let field_with_size_salted_input_utxos =
            field_with_size!(CollectTypeScriptsWitness::salted_input_utxos);
        let field_with_size_salted_output_utxos =
            field_with_size!(CollectTypeScriptsWitness::salted_output_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);
        let field_coins = field!(Utxo::coins);
        let field_type_script_hash = field!(Coin::type_script_hash);
        let contains = library.import(Box::new(Contains::new(DataType::Digest)));
        let new_list = library.import(Box::new(New));
        let push_digest = library.import(Box::new(Push::new(DataType::Digest)));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let eq_digest = DataType::Digest.compare();

        let collect_type_script_hashes_from_utxos =
            "neptune_consensus_transaction_collect_type_script_hashes_from_utxo".to_string();
        let collect_type_script_hashes_from_coins =
            "neptune_consensus_transaction_collect_type_script_hashes_from_coin".to_string();
        let push_digest_from_coin_to_list =
            "neptune_consensus_transaction_push_digest_to_list".to_string();
        let write_all_digests = "netpune_consensus_transaction_write_all_digests".to_string();
        let authenticate_salted_utxos_and_collect_hashes = triton_asm! {
            // BEFORE:
            // _ *ctsw *type_script_hashes *salted_utxos size

            dup 1 swap 1
            // _ *ctsw *type_script_hashes *salted_utxos *salted_utxos size


            /* Sanity check: Ensure salted utxos struct not too small */
            dup 0
            push 2
            lt
            assert error_id {Self::SALTED_UTXOS_TOO_SMALL}
            // _ *ctsw *type_script_hashes *salted_utxos *salted_utxos size


            call {hash_varlen}
            // _ *ctsw *type_script_hashes *salted_utxos [salted_utxos_hash]

            read_io 5
            // _ *ctsw *type_script_hashes *salted_utxos [salted_utxos_hash] [sud]

            {&eq_digest}
            assert error_id {Self::NON_INTEGRAL_SALTED_UTXOS}
            // _ *ctsw *type_script_hashes *salted_utxos

            /* Verify not too many UTXOs */
            {&field_utxos}
            // _ *ctsw *type_script_hashes *utxos_li

            read_mem 1 addi 2
            // _ *ctsw *type_script_hashes N *utxos[0]_si

            push {MAX_NUM_INPUTS_AND_OUTPUTS}
            dup 2
            lt
            // _ *ctsw *type_script_hashes N *utxos[0]_si (max_num_puts > N)

            assert error_id {Self::TOO_MANY_INPUTS_OR_OUTPUTS}
            // _ *ctsw *type_script_hashes N *utxos[0]_si

            push 0 swap 1
            // _ *ctsw *type_script_hashes N 0 *utxos[0]_si

            call {collect_type_script_hashes_from_utxos}
            // _ *ctsw *type_script_hashes N N *utxos[N]_si

            /* Ensure pointer is inside allowed ND-memory region */
            pop_count

            pop 3
            // _ *ctsw *type_script_hashes
        };

        let push_native_currency_hash_to_stack = NativeCurrency
            .hash()
            .values()
            .iter()
            .rev()
            .map(|elem| triton_instr!(push elem.value()))
            .collect_vec();

        let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
            CollectTypeScriptsWitness,
        >::default()));
        let payload = triton_asm! {

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ *ctsw

            dup 0
            call {audit_preloaded_data}
            // _ *ctsw witness_size

            pop 1
            // _ *ctsw

            call {new_list}
            // _ *ctsw *type_script_hashes

            /* Push native currency hash which must always be present */
            dup 0
            {&push_native_currency_hash_to_stack}
            call {push_digest}
            // _ *ctsw *type_script_hashes

            dup 1 {&field_with_size_salted_input_utxos}
            // _ *ctsw *type_script_hashes *salted_input_utxos size

            {&authenticate_salted_utxos_and_collect_hashes}
            // _ *ctsw *type_script_hashes

            dup 1 {&field_with_size_salted_output_utxos}
            // _ *ctsw *type_script_hashes *salted_output_utxos size

            {&authenticate_salted_utxos_and_collect_hashes}
            // _ *ctsw *type_script_hashes

            read_mem 1 addi 2 swap 1
            // _ *ctsw *type_script_hashes[0] len


            /* Sanity checks of generated list of type script hashes */
            dup 0
            push 0
            lt
            assert error_id {Self::EMPTY_TYPE_SCRIPT_HASH_LIST}
            // _ *ctsw *type_script_hashes[0] len

            dup 1
            addi {Digest::LEN-1}
            read_mem {Digest::LEN}
            pop 1
            // _ *ctsw *type_script_hashes[0] len [hashes[0]]

            {&push_native_currency_hash_to_stack}
            // _ *ctsw *type_script_hashes[0] len [hashes[0]] [native_currency_hash]

            {&DataType::Digest.compare()}
            assert error_id {Self::FIRST_TYPE_SCRIPT_HASH_NOT_NATIVE_CURRENCY}
            // _ *ctsw *type_script_hashes[0] len


            /* Write all hashes to std-out */
            push {Digest::LEN} mul
            // _ *ctsw *type_script_hashes[0] size

            dup 1 add
            // _ *ctsw *type_script_hashes[0] *type_script_hashes[N+1]

            call {write_all_digests}
            // _ *ctsw *type_script_hashes[N+1] *type_script_hashes[N+1]

            pop 3
            // _

            halt

            // INVARIANT: _ *type_script_hashes N i *utxos[i]_si
            {collect_type_script_hashes_from_utxos}:
                dup 2 dup 2 eq
                // _ *type_script_hashes N i *utxos[i]_si (N==i)

                skiz return
                // _ *type_script_hashes N i *utxos[i]_si

                dup 0 addi 1 {&field_coins}
                // _ *type_script_hashes N i *utxos[i]_si *coins

                read_mem 1 addi 2
                // _ *type_script_hashes N i *utxos[i]_si len *coins[0]_si

                /* Verify not too many coins */
                push {MAX_NUM_COINS_PER_UTXOS}
                dup 2
                lt
                // _ *type_script_hashes N i *utxos[i]_si len *coins[0]_si (max_num_coins > len)

                assert error_id {Self::TOO_MANY_COINS}
                // _ *type_script_hashes N i *utxos[i]_si len *coins[0]_si

                push 0 swap 1
                // _ *type_script_hashes N i *utxos[i]_si len 0 *coins[0]_si

                call {collect_type_script_hashes_from_coins}
                // _ *type_script_hashes N i *utxos[i]_si len len *coins[len]_si


                /* Ensure pointer is inside allowed ND-memory region */
                pop_count


                pop 3
                // _ *type_script_hashes N i *utxos[i]_si

                read_mem 1 addi 2
                // _ *type_script_hashes N i size *utxos[i]

                /* Ensure forward jump, by ensuring size is u32 */
                dup 1
                pop_count
                pop 1

                add
                // _ *type_script_hashes N i *utxos[i+1]_si

                swap 1 addi 1 swap 1
                // _ *type_script_hashes N (i+1) *utxos[i+1]_si

                recurse

            // INVARIANT: _ *type_script_hashes * * * len j *coin[j]_si
            {collect_type_script_hashes_from_coins}:
                dup 2 dup 2 eq
                // _ *type_script_hashes * * * len j *coin[j]_si (len==j)

                skiz return
                // _ *type_script_hashes * * * len j *coin[j]_si

                read_mem 1 addi 2
                // _ *type_script_hashes * * * len j size *coin[j]

                dup 7 dup 0 dup 2 {&field_type_script_hash}
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes *type_script_hashes *digest

                addi {Digest::LEN-1} read_mem {Digest::LEN} pop 1
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes *type_script_hashes [digest]

                call {contains}
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes ([digest] in type_script_hashes)

                push 0 eq
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes ([digest] not in type_script_hashes)

                skiz call {push_digest_from_coin_to_list}
                // _ *type_script_hashes * * * len j size *coin[j] garbage

                /* Ensure forward jump, by ensuring size is u32 */
                dup 2
                pop_count
                pop 2
                // _ *type_script_hashes * * * len j size *coin[j]

                add
                // _ *type_script_hashes * * * len j *coin[j+1]_si

                swap 1 addi 1 swap 1
                // _ *type_script_hashes * * * len (j+1) *coin[j+1]_si

                recurse

            // BEFORE: _ *coin[j] *type_script_hashes
            // AFTER:  _ *coin[j] *
            {push_digest_from_coin_to_list}:
                dup 1
                // _ *coin[j] *type_script_hashes *coin[j]

                {&field_type_script_hash}
                // _ *coin[j] *type_script_hashes *digest

                addi {Digest::LEN-1} read_mem {Digest::LEN} pop 1
                // _ *coin[j] *type_script_hashes [digest]

                call {push_digest}
                // _ *coin[j]

                push {0x2b00b5}

                return

            // INVARIANT: _ *type_script_hashes[i] *type_script_hashes[N+1]
            {write_all_digests}:

                dup 1 dup 1 eq
                // _ *type_script_hashes[i] *type_script_hashes[N+1] (i==N+1)

                skiz return
                // _ *type_script_hashes[i] *type_script_hashes[N+1]

                dup 1 addi {Digest::LEN-1} read_mem {Digest::LEN}
                // _ *type_script_hashes[i] *type_script_hashes[N+1] [type_script_hashes[i]] (*type_script_hashes[i]-1)

                addi {Digest::LEN+1} swap 7 pop 1
                // _ *type_script_hashes[i+1] *type_script_hashes[N+1] [type_script_hashes[i]]

                write_io 5
                // _ *type_script_hashes[i+1] *type_script_hashes[N+1]

                recurse

        };

        let code = triton_asm! {
            {&payload}
            {&library.all_imports()}
        };

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}
