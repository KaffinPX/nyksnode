use std::collections::HashMap;
use std::sync::OnceLock;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::library::Library;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use triton_vm::prelude::NonDeterminism;
use triton_vm::prelude::PublicInput;

use crate::consensus::transaction::salted_utxos::SaltedUtxos;
use crate::consensus::transaction::utxo::Utxo;
use crate::prelude::triton_vm;
use crate::proof_abstractions::SecretWitness;
use crate::proof_abstractions::tasm::program::TritonProgram;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct CollectLockScriptsWitness {
    pub salted_input_utxos: SaltedUtxos,
}

impl SecretWitness for CollectLockScriptsWitness {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(
            Tip5::hash(&self.salted_input_utxos)
                .reversed()
                .values()
                .to_vec(),
        )
    }

    fn output(&self) -> Vec<BFieldElement> {
        self.salted_input_utxos
            .utxos
            .iter()
            .flat_map(|utxo| utxo.lock_script_hash().values())
            .collect_vec()
    }

    fn program(&self) -> Program {
        CollectLockScripts.program()
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
pub struct CollectLockScripts;

impl CollectLockScripts {
    const JUMP_OUT_OF_BOUNDS: i128 = 1_000_260;
}

impl TritonProgram for CollectLockScripts {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        const MAX_JUMP_LENGTH: usize = 2_000_000;

        let mut library = Library::new();
        let field_with_size_salted_input_utxos =
            field_with_size!(CollectLockScriptsWitness::salted_input_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);
        let field_lock_script_hash = field!(Utxo::lock_script_hash);
        let hash_varlen = library.import(Box::new(HashVarlen));
        let eq_digest = DataType::Digest.compare();
        let write_all_lock_script_digests =
            "neptune_consensus_transaction_collect_lock_scripts_write_all_lock_script_digests"
                .to_string();

        let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
            CollectLockScriptsWitness,
        >::default()));

        let payload = triton_asm! {
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ *clsw

            dup 0
            call {audit_preloaded_data}
            // _ *clsw witness_size

            dup 1
            // _ *clsw witness_size *clsw

            {&field_with_size_salted_input_utxos}
            // _ *clsw witness_size *salted_input_utxos size

            dup 1 swap 1
            // _ *clsw witness_size *salted_input_utxos *salted_input_utxos size

            call {hash_varlen}
            // _ *clsw witness_size *salted_input_utxos [salted_input_utxos_hash]

            read_io 5
            // _ *clsw witness_size *salted_input_utxos [salted_input_utxos_hash] [siud]

            {&eq_digest} assert
            // _ *clsw witness_size *salted_input_utxos

            {&field_utxos}
            // _ *clsw witness_size *utxos_li

            read_mem 1 addi 2
            // _ *clsw witness_size N *utxos[0]_si

            push 0 swap 1
            // _ *clsw witness_size N 0 *utxos[0]_si

            call {write_all_lock_script_digests}
            // _ *clsw witness_size N N *ptr

            pop 5
            // _

            halt

            // INVARIANT: _ N i *utxos[i]_si
            {write_all_lock_script_digests}:
                dup 2 dup 2 eq
                // _ N i *utxos[i]_si (N==i)

                skiz return
                // _ N i *utxos[i]_si

                dup 0 addi 1 {&field_lock_script_hash}
                // _ N i *utxos[i]_si *lock_script_hash

                addi {Digest::LEN-1} read_mem {Digest::LEN} pop 1
                // _ N i *utxos[i]_si [lock_script_hash]

                write_io 5
                // _ N i *utxos[i]_si

                read_mem 1 addi 2
                // _ N i size *utxos[i]

                push {MAX_JUMP_LENGTH}
                dup 2
                lt
                assert error_id {Self::JUMP_OUT_OF_BOUNDS}
                // _ N i size *utxos[i]

                add
                // _ N i *utxos[i+1]_si

                swap 1 addi 1 swap 1
                // _ N (i+1) *utxos[i+1]_si

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
