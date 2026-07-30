use std::sync::OnceLock;

use itertools::Itertools;
use tasm_lib::field;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::hash_from_stack::HashFromStack;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::isa::triton_instr;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::prelude::Tip5;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tracing::debug;

use super::block_proof_witness::BlockProofWitness;
use crate::block::BlockAppendix;
use crate::block::block_body::BlockBody;
use crate::block::block_body::BlockBodyField;
use crate::network::Network;
use crate::proof_abstractions::mast_hash::MastHash;
use crate::proof_abstractions::tasm::program::TritonProgram;
#[cfg(not(target_arch = "wasm32"))]
use crate::proof_abstractions::verifier::verify;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::transaction_kernel::TransactionKernelField;
use crate::transaction::validity::nyks_proof::NyksProof;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

/// Verifies that all claims listed in the appendix are true.
///
/// The witness for this program is `BlockProofWitness`.
#[derive(Debug, Clone, Copy)]
pub struct BlockProgram;

impl BlockProgram {
    const ILLEGAL_FEE: i128 = 1_000_210;
    const PROOF_SIZE_INDICATOR_TOO_BIG: i128 = 1_000_211;

    pub fn claim(block_body: &BlockBody, appendix: &BlockAppendix) -> Claim {
        Claim::new(Self.hash())
            .with_input(block_body.mast_hash().reversed().values().to_vec())
            .with_output(appendix.claims_as_output())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn verify(
        block_body: &BlockBody,
        appendix: &BlockAppendix,
        proof: &NyksProof,
        network: Network,
    ) -> bool {
        let claim = Self::claim(block_body, appendix);
        let proof_clone = proof.clone();

        debug!("** Calling triton_vm::verify to verify block proof ...");
        let verdict = verify(claim, proof_clone, network).await;
        debug!("** Call to triton_vm::verify to verify block proof completed; verdict: {verdict}.");

        verdict
    }
}

impl TritonProgram for BlockProgram {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        // restrict proof size to avoid jumping backwards or to arbitrary
        // place in memory.
        const MAX_PROOF_SIZE: u64 = 4_000_000;

        let mut library = Library::new();

        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        let block_body_field = field!(BlockProofWitness::block_body);
        let body_field_kernel = field!(BlockBody::transaction_kernel);
        let kernel_field_fee = field!(TransactionKernel::fee);
        let block_witness_field_claims = field!(BlockProofWitness::claims);
        let block_witness_field_proofs = field!(BlockProofWitness::proofs);

        let merkle_verify = library.import(Box::new(MerkleVerify));
        let coin_size = NativeCurrencyAmount::static_length().unwrap();
        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();
        let u128_lt = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));
        let hash_from_stack_digest = library.import(Box::new(HashFromStack::new(DataType::Digest)));
        let hash_from_stack_amount = library.import(Box::new(HashFromStack::new(DataType::I128)));
        let verify_fee_legality = triton_asm!(
            // _ *w [txkmh]

            dup 4
            dup 4
            dup 4
            dup 4
            dup 4
            push {TransactionKernel::MAST_HEIGHT}
            // _ *w [txkmh] [txkmh] txkm_height

            push {TransactionKernelField::Fee as u32}
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index

            dup 12 {&block_body_field} {&body_field_kernel} {&kernel_field_fee}
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index *fee

            addi {coin_size - 1} read_mem {coin_size} pop 1
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index [fee]

            /* Using u128-lt here, guarantees fee is both positive and less
               than max allowed amount.
            */
            dup 3
            dup 3
            dup 3
            dup 3
            {&push_max_amount}
            call {u128_lt}
            push 0 eq
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index [fee] (max >= fee)

            assert error_id {Self::ILLEGAL_FEE}
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index [fee]

            call {hash_from_stack_amount}
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index [fee_hash]

            call {merkle_verify}
            // _ *w [txkmh]
        );

        let hash_of_one = Tip5::hash(&1);
        let push_hash_of_one = hash_of_one
            .values()
            .into_iter()
            .rev()
            .map(|b| triton_instr!(push b))
            .collect_vec();
        let verify_set_merge_bit = triton_asm!(
            // _ [txkmh]

            dup 4
            dup 4
            dup 4
            dup 4
            dup 4
            push {TransactionKernel::MAST_HEIGHT}
            // _ [txkmh] [txkmh] txkm_height

            push {TransactionKernelField::MergeBit as u32}
            // _ [txkmh] [txkmh] txkm_height leaf_index

            {&push_hash_of_one}
            // _ [txkmh] [txkmh] txkm_height fee_leaf_index [merge_bit_hash (true)]

            call {merkle_verify}
            // _ [txkmh]
        );

        let authenticate_txkmh = triton_asm!(
            // _ [bbd] *w [txkmh]

            dup 4
            dup 4
            dup 4
            dup 4
            dup 4
            call {hash_from_stack_digest}
            // _ [bbd] *w [txkmh] [txkmh_hash]

            dup 15
            dup 15
            dup 15
            dup 15
            dup 15
            // _ [bbd] *w [txkmh] [txkmh_hash] [bbd]

            push {BlockBody::MAST_HEIGHT}
            push {BlockBodyField::TransactionKernel as u32}
            // _ [bbd] *w [txkmh] [txkmh_hash] [bbd] block_body_mast_height txk_leaf_index

            pick 11
            pick 11
            pick 11
            pick 11
            pick 11
            // _ [bbd] *w [txkmh] [bbd] block_body_mast_height txk_leaf_index [txkmh_hash]

            call {merkle_verify}
            // _ [bbd] *w [txkmh]
        );

        let hash_varlen = library.import(Box::new(HashVarlen));

        let verify_all_claims_loop = "verify_all_claims_loop".to_string();

        let verify_all_claims_function = triton_asm! {
            // INVARIANT: _ *claim[i]_si *proof[i]_si N i
            {verify_all_claims_loop}:

                // terminate if done
                dup 1 dup 1 eq skiz return

                pick 3
                // _ *proof[i]_si N i *claim[i]_si


                /* print claim hash */
                // _ *proof[i]_si N i *claim[i]_si

                read_mem 1
                addi 2
                // _ *proof[i]_si N i claim[i]_si *claim[i]

                dup 0
                dup 2
                call {hash_varlen}
                // _ *proof[i]_si N i claim[i]_si *claim[i] [hash(claim)]

                write_io {Digest::LEN}
                // _ *proof[i]_si N i claim[i]_si *claim[i]


                /* verify claim */
                dup 0
                dup 5
                addi 1
                // _ *proof[i]_si N i claim[i]_si *claim[i] *claim[i] *proof[i]

                call {stark_verify}
                // _ *proof[i]_si N i claim[i]_si *claim[i]


                /* Update pointers and counter */
                add
                // _ *proof[i]_si N i *claim[i+1]_si

                swap 3
                read_mem 1
                // _ *claim[i+1]_si N i proof[i]_si (*proof[i] - 2)

                push {MAX_PROOF_SIZE}
                dup 2
                lt
                assert error_id {Self::PROOF_SIZE_INDICATOR_TOO_BIG}

                addi 2
                add
                // _ *claim[i+1]_si N i *proof[i+1]_si

                place 2
                // _ *claim[i+1]_si *proof[i+1]_si N i

                addi 1
                // _ *claim[i+1]_si *proof[i+1]_si N (i + 1)

                recurse
        };

        let code = triton_asm! {
            // _

            read_io 5
            // _ [block_body_digest]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint block_witness_ptr = stack[0]
            // _ [bbd] *w

            divine {Digest::LEN}
            // _ [bbd] *w [txkmh]

            {&authenticate_txkmh}
            // _ [bbd] *w [txkmh]

            {&verify_fee_legality}
            // _ [bbd] *w [txkmh]

            {&verify_set_merge_bit}
            // _ [bbd] *w [txkmh]

            pop {Digest::LEN}
            // _ [bbd] *w

            /* verify appendix claims */
            dup 0 {&block_witness_field_claims}
            hint claims = stack[0]
            swap 1 {&block_witness_field_proofs}
            hint proofs = stack[1]
            // _ [bbd] *claims *proofs

            dup 1 read_mem 1 pop 1
            // _ [bbd] *claims *proofs N

            pick 2 addi 1
            pick 2 addi 1
            pick 2
            // _ [bbd] *claim[0] *proof[0] N

            push 0
            // _ [bbd] *claim[0] *proof[0] N 0

            call {verify_all_claims_loop}
            // _ [bbd] *claim[0] *proof[0] N N

            pop 4
            pop 5
            // _

            halt

            {&verify_all_claims_function}
            {&library.all_imports()}
        };

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::proof_abstractions::tasm::program::tests::test_program_snapshot;

    test_program_snapshot!(
        BlockProgram,
        "2d3fe8ddca93ac8be7f92a53c541f6dbb971ab2817cbc1743c8b5a3b3c99b6caf0102385258a828d"
    );
}
