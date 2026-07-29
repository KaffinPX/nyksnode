use std::collections::HashMap;
use std::sync::OnceLock;

use field_count::FieldCount;
use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::library::Library;
use tasm_lib::list;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::bfieldcodec_derive::BFieldCodec;

use crate::proof_abstractions::SecretWitness;
use crate::proof_abstractions::mast_hash::MastHash;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::salted_utxos::SaltedUtxos;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::transaction_kernel::TransactionKernelField;

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    GetSize,
    BFieldCodec,
    FieldCount,
    TasmObject,
)]
pub struct KernelToOutputsWitness {
    pub output_utxos: SaltedUtxos,
    pub sender_randomnesses: Vec<Digest>,
    pub receiver_digests: Vec<Digest>,
    pub kernel: TransactionKernel,
}

/// Contains the parts of the witness that the VM reads from memory
#[derive(Clone, Debug, PartialEq, Eq, BFieldCodec, TasmObject)]
struct KernelToOutputsWitnessMemory {
    pub output_utxos: SaltedUtxos,
    pub sender_randomnesses: Vec<Digest>,
    pub receiver_digests: Vec<Digest>,
}

impl From<&KernelToOutputsWitness> for KernelToOutputsWitnessMemory {
    fn from(value: &KernelToOutputsWitness) -> Self {
        Self {
            output_utxos: value.output_utxos.to_owned(),
            sender_randomnesses: value.sender_randomnesses.to_owned(),
            receiver_digests: value.receiver_digests.to_owned(),
        }
    }
}

impl SecretWitness for KernelToOutputsWitness {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(self.kernel.mast_hash().reversed().values().to_vec())
    }

    fn output(&self) -> Vec<BFieldElement> {
        Tip5::hash(&self.output_utxos).values().to_vec()
    }

    fn program(&self) -> Program {
        KernelToOutputs.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        let witness_for_memory: KernelToOutputsWitnessMemory = self.into();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &witness_for_memory,
        );

        // set authentication path digests
        let digests = self.kernel.mast_path(TransactionKernelField::Outputs);

        NonDeterminism::default()
            .with_ram(memory)
            .with_digests(digests)
    }
}

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, GetSize, FieldCount, BFieldCodec,
)]
pub struct KernelToOutputs;

impl KernelToOutputs {
    const JUMP_OUT_OF_BOUNDS_ERROR: i128 = 1_000_270;
    const INCONSISTENT_INDICATED_SALTED_OUTPUT_UTXOS_SIZE: i128 = 1_000_271;
    const INCONSISTENT_LENGTHS: i128 = 1_000_272;
}

impl TritonProgram for KernelToOutputs {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        const MAX_JUMP_LENGTH: usize = 2_000_000;

        const SIZE_OF_SALT: usize = 3;
        const SIZE_INDICATOR_SIZE: usize = 1;
        const LENGTH_INDICATOR_SIZE: usize = 1;

        let mut library = Library::new();

        let new_list = library.import(Box::new(list::new::New));
        let get_digest = library.import(Box::new(list::get::Get::new(DataType::Digest)));
        let compute_canonical_commitment =
            library.import(Box::new(tasm_lib::neptune::mutator_set::commit::Commit));
        let hash_varlen = library.import(Box::new(
            tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen,
        ));
        let merkle_verify =
            library.import(Box::new(tasm_lib::hashing::merkle_verify::MerkleVerify));
        let field_salted_output_utxos = field!(KernelToOutputsWitnessMemory::output_utxos);
        let field_sender_randomnesses = field!(KernelToOutputsWitnessMemory::sender_randomnesses);
        let field_receiver_digests = field!(KernelToOutputsWitnessMemory::receiver_digests);
        let field_utxos = field!(SaltedUtxos::utxos);

        let calculate_canonical_commitments =
            "kernel_to_outputs_calculate_canonical_commitments".to_string();

        let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
            KernelToOutputsWitnessMemory,
        >::default()));

        let tasm = triton_asm! {
            read_io 5       // _ [txkmh]
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
                            // _ [txkmh] *kernel_to_outputs_witness

            dup 0
            call {audit_preloaded_data}
            pop 1
                            // _ [txkmh] *kernel_to_outputs_witness

            dup 0
            {&field_salted_output_utxos}    // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos
            dup 0
            {&field_utxos}                  // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos
            addi 1                          // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len

            dup 2
            {&field_sender_randomnesses}    // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses

            dup 3
            {&field_receiver_digests}       // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests

            read_mem 1
            addi {1 + Digest::LEN}
            swap 1
            dup 0
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw N N

            dup 5
            {&field_utxos}
            read_mem 1
            pop 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw N N utxos_len

            dup 1
            eq
            assert error_id {Self::INCONSISTENT_LENGTHS}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw N N

            call {new_list}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw N N *canonical_commitments

            write_mem 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw N *canonical_commitments[0]

            swap 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw *canonical_commitments[0] N

            push 0
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw *canonical_commitments[0] N 0

            dup 5
            place 6
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len *utxos[0]_len *sender_randomnesses *receiver_digests[0]_lw *canonical_commitments[0] N 0


            call {calculate_canonical_commitments}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] *canonical_commitments[N] N N

            pop 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] *canonical_commitments[N] N

            push {-(Digest::LEN as isize)} mul addi -1 add
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] *canonical_commitments

            dup 0 read_mem 1 pop 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] *canonical_commitments N

            push {Digest::LEN} mul addi 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] *canonical_commitments (5*N+1)

            call {hash_varlen}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] [cc_digest]

            // r h i l
            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] [cc_digest] [txkmh]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Outputs as u32}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] [cc_digest] [txkmh] h i

            dup 11 dup 11 dup 11 dup 11 dup 11
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] [cc_digest] [txkmh] h i [cc_digest]

            call {merkle_verify}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len *sender_randomnesses *receiver_digests[N] [cc_digest]


            pop 5 pop 2
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos *utxos[0]_len  *utxos[N]_len

            swap 1
            push -1 mul
            add
            addi {SIZE_OF_SALT + SIZE_INDICATOR_SIZE + LENGTH_INDICATOR_SIZE}
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos (*utxos[N]_len - *utxos[0]_len + 5)
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos calculated_salted_utxos_len

            swap 1
            // _ [txkmh] *kernel_to_outputs_witness calculated_salted_utxos_len *salted_output_utxos

            addi -1
            // _ [txkmh] *kernel_to_outputs_witness calculated_salted_utxos_len *salted_output_utxos_size

            read_mem 1
            // _ [txkmh] *kernel_to_outputs_witness calculated_salted_utxos_len size (*salted_output_utxos_size-1)

            place 2
            // _ [txkmh] *kernel_to_outputs_witness  (*salted_output_utxos_size-1) calculated_salted_utxos_len size

            dup 1
            eq
            assert error_id {Self::INCONSISTENT_INDICATED_SALTED_OUTPUT_UTXOS_SIZE}
            // _ [txkmh] *kernel_to_outputs_witness  (*salted_output_utxos_size-1) size

            swap 1
             // _ [txkmh] *kernel_to_outputs_witness size (*salted_output_utxos_size-1)

            addi 2
            // _ [txkmh] *kernel_to_outputs_witness size *salted_output_utxos

            swap 1
            // _ [txkmh] *kernel_to_outputs_witness *salted_output_utxos size

            call {hash_varlen}
            // _ [txkmh] *kernel_to_outputs_witness [salted_outputs_hash]

            write_io {Digest::LEN}
            // _ [txkmh] *kernel_to_outputs_witness

            pop 5
            pop 1
            // _

            halt

            // INVARIANT: _ *utxos[i]_len *sender_randomnesses *receiver_digests[i]_lw *canonical_commitments[i] N i
            {calculate_canonical_commitments}:
                /* Loop's end-condition: N == i */
                dup 1 dup 1 eq
                skiz return
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i]_lw *canonical_commitments[i] N i

                dup 3
                read_mem {Digest::LEN}
                addi {2 * Digest::LEN}
                swap 9
                pop 1
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [receiver_digests[i]]

                dup 9 dup 6 call {get_digest}
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]]

                dup 15
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]] *utxos[i]_len

                read_mem 1 addi 2 swap 1
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]] *utxos[i] utxos[i]_len

                call {hash_varlen}
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [receiver_digests[i]] [sender_randomnesses[i]] [item]

                call {compute_canonical_commitment}
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i [canonical_commitment]

                dup 7 write_mem 5
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i] N i *canonical_commitments[i+1]

                swap 3 pop 1
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N i

                dup 5
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N i *utxos[i]_len

                read_mem 1
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N i utxos[i]_len (*utxos[i]_len-1)

                push {MAX_JUMP_LENGTH}
                dup 2
                lt
                assert error_id {Self::JUMP_OUT_OF_BOUNDS_ERROR}

                addi 2 add
                // _ *utxos[i]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N i utxos[i+1]_len

                swap 6 pop 1
                // _ *utxos[i+1]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N i

                addi 1
                // _ *utxos[i+1]_len *sender_randomnesses *receiver_digests[i+1]_lw *canonical_commitments[i+1] N (i+1)

                recurse
        };

        let dependencies = library.all_imports();

        let code = triton_asm!(
            {&tasm}
            {&dependencies}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}
