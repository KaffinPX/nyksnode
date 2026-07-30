use itertools::Itertools;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::hash_from_stack::HashFromStack;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::list::multiset_equality_digests::MultisetEqualityDigests;
use tasm_lib::mmr::verify_mmr_successor::VerifyMmrSuccessor;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;
use tasm_lib::verifier::stark_verify::StarkVerify;

use crate::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::proof_abstractions::mast_hash::MastHash;
use crate::transaction::BFieldCodec;
use crate::transaction::TransactionKernel;
use crate::transaction::transaction_kernel::TransactionKernelField;
use crate::transaction::validity::nyks_proof::NyksProof;
use crate::transaction::validity::single_proof::DISCRIMINANT_FOR_UPDATE;
use crate::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField;
use crate::transaction::validity::tasm::claims::generate_single_proof_claim::GenerateSingleProofClaim;
use crate::transaction::validity::tasm::hash_removal_record_index_sets::HashRemovalRecordIndexSets;
use crate::transaction::validity::tasm::leaf_authentication::authenticate_msa_against_txk::AuthenticateMsaAgainstTxk;
use crate::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

// Dictated by the witness type of SingleProof
const UPDATE_WITNESS_ADDRESS: BFieldElement = BFieldElement::new(2);

#[derive(Debug, Clone, BFieldCodec, TasmObject)]
pub struct UpdateWitness {
    pub old_kernel: TransactionKernel,
    pub new_kernel: TransactionKernel,
    pub old_kernel_mast_hash: Digest,
    pub new_kernel_mast_hash: Digest,
    pub old_proof: NyksProof,
    pub new_swbfi_bagged: Digest,
    pub new_aocl: MmrAccumulator,
    pub new_swbfa_hash: Digest,
    pub old_swbfi_bagged: Digest,
    pub old_aocl: MmrAccumulator,
    pub old_swbfa_hash: Digest,
    pub aocl_successor_proof: MmrSuccessorProof,
    pub outputs_hash: Digest,
    pub announcements_hash: Digest,
}

impl UpdateWitness {
    pub fn from_old_transaction(
        old_kernel: TransactionKernel,
        old_proof: NyksProof,
        old_msa: MutatorSetAccumulator,
        new_kernel: TransactionKernel,
        new_msa: MutatorSetAccumulator,
        aocl_successor_proof: MmrSuccessorProof,
    ) -> Self {
        let msah_path = new_kernel.mast_path(TransactionKernelField::MutatorSetHash);
        assert!(
            MerkleTreeInclusionProof {
                tree_height: TransactionKernel::MAST_HEIGHT.try_into().unwrap(),
                indexed_leafs: vec![(
                    TransactionKernelField::MutatorSetHash as usize,
                    Tip5::hash(&new_msa.hash())
                )],
                authentication_structure: msah_path.clone(),
            }
            .verify(new_kernel.mast_hash()),
            "mutator set hash mast path should be valid"
        );

        assert_eq!(
            old_kernel.merge_bit, new_kernel.merge_bit,
            "merge bit cannot be changed by update"
        );

        Self {
            old_kernel_mast_hash: old_kernel.mast_hash(),
            new_kernel_mast_hash: new_kernel.mast_hash(),
            old_kernel,
            new_kernel: new_kernel.clone(),
            old_proof,
            new_swbfi_bagged: new_msa.swbf_inactive.bag_peaks(),
            new_aocl: new_msa.aocl,
            new_swbfa_hash: Tip5::hash(&new_msa.swbf_active),
            old_swbfi_bagged: old_msa.swbf_inactive.bag_peaks(),
            old_aocl: old_msa.aocl,
            old_swbfa_hash: Tip5::hash(&old_msa.swbf_active),
            aocl_successor_proof,
            outputs_hash: Tip5::hash(&new_kernel.outputs),
            announcements_hash: Tip5::hash(&new_kernel.announcements),
        }
    }

    pub fn populate_nd_streams(
        &self,
        nondeterminism: &mut NonDeterminism,
        single_proof_program_hash: Digest,
    ) {
        // update nondeterminism to account for verifying one STARK proof
        let claim = Claim::new(single_proof_program_hash)
            .with_input(self.old_kernel_mast_hash.reversed().values().to_vec());

        // this check is needed for regtest mode, to prevent a panic
        // because regtest mode uses mock (empty) proofs.
        if !triton_vm::verify(Stark::default(), &claim, &self.old_proof) {
            tracing::warn!("attempting to update invalid transaction ...");
            return;
        }
        StarkVerify::new_with_dynamic_layout(Stark::default()).update_nondeterminism(
            nondeterminism,
            &self.old_proof,
            &claim,
        );

        nondeterminism.digests.extend(
            [
                // mutator set hash
                self.new_kernel
                    .mast_path(TransactionKernelField::MutatorSetHash),
                self.old_kernel
                    .mast_path(TransactionKernelField::MutatorSetHash),
            ]
            .concat(),
        );

        VerifyMmrSuccessor::update_nondeterminism(nondeterminism, &self.aocl_successor_proof);

        nondeterminism.digests.extend(
            [
                // inputs
                self.old_kernel.mast_path(TransactionKernelField::Inputs),
                self.new_kernel.mast_path(TransactionKernelField::Inputs),
                // outputs
                self.old_kernel.mast_path(TransactionKernelField::Outputs),
                self.new_kernel.mast_path(TransactionKernelField::Outputs),
                // announcements
                self.old_kernel
                    .mast_path(TransactionKernelField::Announcements),
                self.new_kernel
                    .mast_path(TransactionKernelField::Announcements),
                // fee
                self.old_kernel.mast_path(TransactionKernelField::Fee),
                self.new_kernel.mast_path(TransactionKernelField::Fee),
                // coinbase
                self.old_kernel.mast_path(TransactionKernelField::Coinbase),
                self.new_kernel.mast_path(TransactionKernelField::Coinbase),
                // timestamp
                self.old_kernel.mast_path(TransactionKernelField::Timestamp),
                self.new_kernel.mast_path(TransactionKernelField::Timestamp),
                // merge bit
                self.old_kernel.mast_path(TransactionKernelField::MergeBit),
                self.new_kernel.mast_path(TransactionKernelField::MergeBit),
            ]
            .concat(),
        );

        nondeterminism
            .individual_tokens
            .extend_from_slice(&self.old_kernel.merge_bit.encode());
    }
}

#[derive(Debug, Copy, Clone)]
pub struct UpdateBranch;

impl UpdateBranch {
    pub const INPUT_SETS_NOT_EQUAL_ERROR: i128 = 1_000_100;
    pub const NEW_TIMESTAMP_NOT_GEQ_THAN_OLD_ERROR: i128 = 1_000_101;
    pub const WITNESS_SIZE_CHANGED_ERROR: i128 = 1_000_102;
    pub const MERGE_BIT_NOT_BIT: i128 = 1_000_103;
    pub const INPUT_SET_IS_EMPTY_ERROR: i128 = 1_000_104;
}

impl BasicSnippet for UpdateBranch {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "single_proof_program_digest".to_owned()),
            (DataType::Digest, "new_tx_kernel_digest".to_owned()),
            (DataType::VoidPointer, "single_proof_witness".to_owned()),
            (DataType::Bfe, "discriminant".to_owned()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "single_proof_program_digest".to_owned()),
            (DataType::Digest, "new_tx_kernel_digest".to_owned()),
            (DataType::VoidPointer, "single_proof_witness".to_owned()),
            (DataType::Bfe, "minus_1".to_owned()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_single_proof_update_branch".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let load_digest = triton_asm!(push {Digest::LEN - 1} add read_mem {Digest::LEN} pop 1);

        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let authenticate_msa = library.import(Box::new(AuthenticateMsaAgainstTxk));
        let authenticate_inputs = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Inputs,
        )));
        let authenticate_timestamp = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Timestamp,
        )));
        let verify_mmr_successor_proof = library.import(Box::new(VerifyMmrSuccessor));
        let hash_removal_record_index_set =
            library.import(Box::new(HashRemovalRecordIndexSets::<1>));
        let multiset_eq_digests = library.import(Box::new(MultisetEqualityDigests));
        let u64_lt = library.import(Box::new(tasm_lib::arithmetic::u64::lt::Lt));

        let old_txk_digest_alloc = library.kmalloc(Digest::LEN as u32);

        let old_kernel = field!(UpdateWitness::old_kernel);
        let load_old_kernel_digest = triton_asm!(
            push {old_txk_digest_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
        );

        let field_old_txk_mh = field!(UpdateWitness::old_kernel_mast_hash);
        let generate_single_proof_claim = library.import(Box::new(GenerateSingleProofClaim));

        let audit_preloaded_data =
            library.import(Box::new(VerifyNdSiIntegrity::<UpdateWitness>::default()));
        let merkle_verify = library.import(Box::new(MerkleVerify));
        let hash_bfe = library.import(Box::new(HashFromStack::new(DataType::Bfe)));

        let mut authenticate_field_twice_with_no_change =
            |field_with_size_getter: &[LabelledInstruction], field: TransactionKernelField| {
                let authenticate_generic_field =
                    library.import(Box::new(AuthenticateTxkField(field)));
                triton_asm! {
                    // _ [new_txk_mhash] *old_kernel *new_kernel

                    dup 1
                    // _ [new_txk_mhash] *old_kernel *new_kernel *old_kernel

                    {&field_with_size_getter}
                    // _ [new_txk_mhash] *old_kernel *new_kernel *field field_size

                    {&load_old_kernel_digest}
                    // _ [new_txk_mhash] *old_kernel *new_kernel *field field_size [old_txk_mhash]

                    dup 6 dup 6 call {authenticate_generic_field}
                    // _ [new_txk_mhash] *old_kernel *new_kernel *field field_size

                    dup 8
                    dup 8
                    dup 8
                    dup 8
                    dup 8
                    // _ [new_txk_mhash] *old_kernel *new_kernel *field field_size [new_txk_mhash]

                    dup 6 dup 6 call {authenticate_generic_field}
                    // _ [new_txk_mhash] *old_kernel *new_kernel *field field_size

                    pop 2
                    // _ [new_txk_mhash] *old_kernel *new_kernel
                }
            };

        let verify_coinbase_is_none = {
            let coinbase: Option<NativeCurrencyAmount> = None;
            let hash_of_none = Tip5::hash(&coinbase);
            let push_hash_none = hash_of_none
                .values()
                .into_iter()
                .rev()
                .map(|b| triton_instr!(push b))
                .collect_vec();
            triton_asm! {
                // _ [txk_mhash]

                push {TransactionKernel::MAST_HEIGHT}
                push {TransactionKernelField::Coinbase as u32}

                {&push_hash_none}

                call {merkle_verify}
                // _
            }
        };

        let update_witness_field_old_proof = field!(UpdateWitness::old_proof);

        let new_aocl_mmr_field = field!(UpdateWitness::new_aocl);
        let new_swbfi_bagged = field!(UpdateWitness::new_swbfi_bagged);
        let new_swbfa_hash = field!(UpdateWitness::new_swbfa_hash);
        let old_aocl_mmr_field = field!(UpdateWitness::old_aocl);
        let old_swbfi_bagged = field!(UpdateWitness::old_swbfi_bagged);
        let old_swbfa_hash = field!(UpdateWitness::old_swbfa_hash);

        let new_kernel = field!(UpdateWitness::new_kernel);

        let field_timestamp = field!(TransactionKernel::timestamp);
        let inputs_field_with_size = field_with_size!(TransactionKernel::inputs);
        let outputs_field_with_size = field_with_size!(TransactionKernel::outputs);
        let announcements_field_with_size = field_with_size!(TransactionKernel::announcements);
        let fee_field_with_size = field_with_size!(TransactionKernel::fee);

        let authenticate_merge_bit = triton_asm! {
                // _ [txk_mh] merge_bit

                push 1
                dup 1
                eq
                push 0
                dup 2
                eq
                add
                assert error_id {Self::MERGE_BIT_NOT_BIT}

                push {TransactionKernel::MAST_HEIGHT}

                push {TransactionKernelField::MergeBit as u32}

                pick 2
                // _ [txk_mh] height index merge_bit

                call {hash_bfe}
                // _ [txk_mh] height index [merge_bit_digest]

                call {merkle_verify}
                // _
        };

        let entrypoint = self.entrypoint();
        triton_asm! {
            {entrypoint}:
                // _ [program_digest] [new_txk_digest] *spw disc

                place 11
                // _ disc [program_digest] [new_txk_digest] *spw
                place 10
                // _ disc *spw [program_digest] [new_txk_digest]

                push {UPDATE_WITNESS_ADDRESS}
                // _ [program_digest] [new_txk_digest] *update_witness

                dup 0
                call {audit_preloaded_data}
                // _ [program_digest] [new_txk_digest] *update_witness witness_size

                place 11
                // _ witness_size [program_digest] [new_txk_digest] *update_witness

                dup 0
                {&field_old_txk_mh}
                // _ witness_size [program_digest] [new_txk_digest] *update_witness *old_txk_mhash

                {&load_digest}
                // _ witness_size [program_digest] [new_txk_digest] *update_witness [old_tx_mast_hash; 5]

                push {old_txk_digest_alloc.write_address()}
                write_mem {Digest::LEN}
                pop 1
                // _ witness_size [program_digest] [new_txk_digest] *update_witness

                place 10
                // _ witness_size *update_witness [program_digest] [new_txk_digest]

                push {old_txk_digest_alloc.read_address()}
                read_mem 5
                pop 1
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] [old_txk_mhash; 5]

                dup 14
                dup 14
                dup 14
                dup 14
                dup 14
               // _ witness_size *update_witness [program_digest] [new_txk_mhash] [old_txk_mhash; 5] [program_digest]

                call {generate_single_proof_claim}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *claim

                dup 11 {&update_witness_field_old_proof}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *claim *proof

                call {stark_verify}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash]


                /* Verify AOCL-related witness data */
                /* 1: Verify new AOCL-related witness data */
                dup 10
                {&new_aocl_mmr_field}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_aocl

                dup 11
                {&new_swbfi_bagged}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_aocl *new_swbfi_bagged

                dup 12
                {&new_swbfa_hash}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_aocl *new_swbfi_bagged *new_swbfa_digest

                dup 2
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_aocl *new_swbfi_bagged *new_swbfa_digest *new_aocl

                dup 2
                dup 2
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_aocl *new_swbfi_bagged *new_swbfa_digest *new_aocl *new_swbfi_bagged *new_swbfa_digest

                dup 10
                dup 10
                dup 10
                dup 10
                dup 10
                call {authenticate_msa}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_aocl *new_swbfi_bagged *new_swbfa_digest
                /* Now, all new mutator set-related values on stack are authenticated */


                /* Verify old AOCL-related witness data */
                dup 13
                {&old_aocl_mmr_field}
                // _ witness_size *update_witness [...; 13] *old_aocl

                dup 14
                {&old_swbfi_bagged}
                // _ witness_size *update_witness [...; 13] *old_aocl *old_swbfi_bagged

                dup 15
                {&old_swbfa_hash}
                // _ witness_size *update_witness [...; 13] *old_aocl *old_swbfi_bagged *old_swbfa_digest

                dup 2
                // _ witness_size *update_witness [...; 13] *old_aocl *old_swbfi_bagged *old_swbfa_digest *old_aocl

                dup 2
                dup 2
                // _ witness_size *update_witness [...; 13] *old_aocl *old_swbfi_bagged *old_swbfa_digest *old_aocl *old_swbfi_bagged *old_swbfa_digest

                push {old_txk_digest_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ witness_size *update_witness [...; 13] *old_aocl *old_swbfi_bagged *old_swbfa_digest *old_aocl *old_swbfi_bagged *old_swbfa_digest [old_txk_mast_hash]

                call {authenticate_msa}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_aocl *new_swbfi_bagged *new_swbfa_digest *old_aocl *old_swbfi_bagged *old_swbfa_digest
                /* Now, all old mutator set-related values on stack are authenticated */

                pop 2
                swap 2
                pop 2
                swap 1
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_aocl *new_aocl


                /* Verify that new AOCL is a successor of old AOCL */
                call {verify_mmr_successor_proof}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash]


                /* Authenticate inputs, preserve pointers */
                dup 10
                {&old_kernel}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel

                dup 0
                {&inputs_field_with_size}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *old_inputs old_inputs_size

                push {old_txk_digest_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *old_inputs old_inputs_size [old_txk_mhash]

                dup 6
                dup 6
                call {authenticate_inputs}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *old_inputs old_inputs_size

                pop 1
                dup 12
                {&new_kernel}
                hint new_kernel_ptr = stack[0]
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *old_inputs *new_kernel

                swap 1
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel *old_inputs

                dup 1 {&inputs_field_with_size}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs new_inputs_size

                dup 9
                dup 9
                dup 9
                dup 9
                dup 9
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs new_inputs_size [new_txk_mhash]

                dup 6
                dup 6
                call {authenticate_inputs}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs new_inputs_size

                pop 1
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs


                /* Verify that tx has a non-zero number of inputs */
                dup 0
                read_mem 1
                pop 1
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs new_inputs_len

                push 0
                eq
                push 0
                eq
                assert error_id {Self::INPUT_SET_IS_EMPTY_ERROR}


                /* verify index set equality */
                call {hash_removal_record_index_set}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs_digests

                swap 1
                call {hash_removal_record_index_set}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel *new_inputs_digests *old_inputs_digests

                call {multiset_eq_digests}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel set_equality(*new_inputs_digests, *old_inputs_digests)

                assert error_id {Self::INPUT_SETS_NOT_EQUAL_ERROR}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel


                /* Authenticate outputs and verify no-change */
                {&authenticate_field_twice_with_no_change(&outputs_field_with_size, TransactionKernelField::Outputs)}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel

                /* Authenticate announcements and verify no-change */
                {&authenticate_field_twice_with_no_change(&announcements_field_with_size, TransactionKernelField::Announcements)}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel

                /* Authenticate fee and verify no-change */
                {&authenticate_field_twice_with_no_change(&fee_field_with_size, TransactionKernelField::Fee)}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel


                /* Authenticate coinbase and verify None in old and new tx */
                push {old_txk_digest_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                {&verify_coinbase_is_none}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel

                dup 6
                dup 6
                dup 6
                dup 6
                dup 6
                {&verify_coinbase_is_none}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *old_kernel *new_kernel


                /* Authenticate timestamps and verify gte */
                {&field_timestamp}
                swap 1
                {&field_timestamp}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_timestamp *old_timestamp

                {&load_old_kernel_digest}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_timestamp *old_timestamp [old_kernel_txk_mh]

                dup 5 push 1
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_timestamp *old_timestamp [old_kernel_txk_mh] *old_timestamp 1

                call {authenticate_timestamp}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_timestamp *old_timestamp

                dup 6
                dup 6
                dup 6
                dup 6
                dup 6
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_timestamp *old_timestamp [new_txk_mhash]

                dup 6 push 1
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_timestamp *old_timestamp [new_txk_mhash] *new_timestamp 1

                call {authenticate_timestamp}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_timestamp *old_timestamp

                read_mem 1 pop 1
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_timestamp old_timestamp

                split
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] *new_timestamp old_hi old_lo

                swap 1
                swap 2
                read_mem 1
                pop 1
                split
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] old_hi old_lo new_hi new_lo

                call {u64_lt}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] (new_timestamp < old_timestamp)

                push 0 eq
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] (new_timestamp >= old_timestamp)

                assert error_id {Self::NEW_TIMESTAMP_NOT_GEQ_THAN_OLD_ERROR}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash]


                /* verify that merge bit has not changed */
                divine 1
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] merge_bit

                {&load_old_kernel_digest}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] merge_bit [old_txk_mh]

                dup 5
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] merge_bit [old_txk_mh] merge_bit

                {&authenticate_merge_bit}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] merge_bit

                dup 5
                dup 5
                dup 5
                dup 5
                dup 5
                pick 5
                // _ witness_size *update_witness [program_digest] [new_txk_mhash] [new_txk_mhash] merge_bit

                {&authenticate_merge_bit}
                // _ witness_size *update_witness [program_digest] [new_txk_mhash]


                // _ disc *spw witness_size *update_witness [program_digest] [new_txk_mhash]

                pick 11
                pick 11
                // _ disc *spw [program_digest] [new_txk_mhash] witness_size *update_witness

                call {audit_preloaded_data}
                // _ disc *spw [program_digest] [new_txk_mhash] witness_size witness_size_again

                eq
                assert error_id {Self::WITNESS_SIZE_CHANGED_ERROR}
                // _ disc *spw [program_digest] [new_txk_mhash]

                pick 10
                pick 11
                // _ [program_digest] [new_txk_mhash] *spw disc

                addi {-(DISCRIMINANT_FOR_UPDATE as isize) - 1}
                // _ [program_digest] [new_txk_mhash] *spw -1

                return
        }
    }
}
