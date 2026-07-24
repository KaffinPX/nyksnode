use std::collections::HashMap;
use std::sync::OnceLock;

use crate::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::consensus::transaction::validity::neptune_proof::Proof;
use crate::triton_vm::prelude::*;
use itertools::Itertools;
use tasm_lib::field;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::verifier::stark_verify::StarkVerify;

use crate::BFieldElement;
use crate::consensus::transaction::Claim;
use crate::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::consensus::transaction::validity::proof_collection::ProofCollection;
use crate::consensus::transaction::validity::tasm::claims::generate_collect_lock_scripts_claim::GenerateCollectLockScriptsClaim;
use crate::consensus::transaction::validity::tasm::claims::generate_collect_type_scripts_claim::GenerateCollectTypeScriptsClaim;
use crate::consensus::transaction::validity::tasm::claims::generate_k2o_claim::GenerateK2oClaim;
use crate::consensus::transaction::validity::tasm::claims::generate_lock_script_claim_template::GenerateLockScriptClaimTemplate;
use crate::consensus::transaction::validity::tasm::claims::generate_rri_claim::GenerateRriClaim;
use crate::consensus::transaction::validity::tasm::claims::generate_type_script_claim_template::GenerateTypeScriptClaimTemplate;
use crate::consensus::transaction::validity::tasm::single_proof::merge_branch::MergeBranch;
use crate::consensus::transaction::validity::tasm::single_proof::update_branch::UpdateBranch;
use crate::proof_abstractions::SecretWitness;
use crate::proof_abstractions::mast_hash::MastHash;
use crate::proof_abstractions::tasm::program::TritonProgram;

use super::tasm::single_proof::merge_branch::MergeWitness;
use super::tasm::single_proof::update_branch::UpdateWitness;

pub const DISCRIMINANT_FOR_PROOF_COLLECTION: u64 = 0;
pub const DISCRIMINANT_FOR_UPDATE: u64 = 1;
pub const DISCRIMINANT_FOR_MERGE: u64 = 2;

const INVALID_WITNESS_DISCRIMINANT_ERROR: i128 = 1_000_050;
const NO_BRANCH_TAKEN_ERROR: i128 = 1_000_051;
const MANIPULATED_PROOF_COLLECTION_WITNESS_ERROR: i128 = 1_000_052;

#[derive(Debug, Clone, BFieldCodec)]
pub enum SingleProofWitness {
    Collection(Box<ProofCollection>),
    Update(UpdateWitness),
    Merger(MergeWitness),
    // Wait for Hard Fork One:
    // IntegralMempool(IntegralMempoolMembershipWitness)
}

impl SingleProofWitness {
    pub fn from_collection(proof_collection: ProofCollection) -> Self {
        Self::Collection(Box::new(proof_collection))
    }

    pub fn from_update(witness: UpdateWitness) -> Self {
        Self::Update(witness)
    }

    pub fn from_merge(merge_witness: MergeWitness) -> Self {
        Self::Merger(merge_witness)
    }
}

// This implementation of `TasmObject` is required for `decode_iter` and the
// method `decode_from_memory` that relies on it.
impl TasmObject for SingleProofWitness {
    fn label_friendly_name() -> String {
        "SingleProofWitness".to_string()
    }

    fn compute_size_and_assert_valid_size_indicator(
        _library: &mut Library,
    ) -> Vec<LabelledInstruction> {
        unimplemented!()
    }

    fn decode_iter<Itr: Iterator<Item = BFieldElement>>(
        iterator: &mut Itr,
    ) -> Result<Box<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let discriminant = iterator
            .next()
            .ok_or(Box::new(BFieldCodecError::EmptySequence))?;
        let field_size = iterator
            .next()
            .ok_or(Box::new(BFieldCodecError::SequenceTooShort))?
            .value()
            .try_into()
            .map_err(|_| Box::new(BFieldCodecError::ElementOutOfRange))?;
        let field_data = iterator.take(field_size).collect_vec();

        match discriminant.value() {
            DISCRIMINANT_FOR_PROOF_COLLECTION => Ok(Box::new(Self::Collection(Box::new(
                *BFieldCodec::decode(&field_data)?,
            )))),
            DISCRIMINANT_FOR_UPDATE => {
                Ok(Box::new(Self::Update(*BFieldCodec::decode(&field_data)?)))
            }
            DISCRIMINANT_FOR_MERGE => {
                Ok(Box::new(Self::Merger(*BFieldCodec::decode(&field_data)?)))
            }
            _ => Err(Box::new(BFieldCodecError::ElementOutOfRange)),
        }
    }
}

impl SecretWitness for SingleProofWitness {
    fn standard_input(&self) -> PublicInput {
        let kernel_mast_hash = match self {
            Self::Collection(pc) => pc.kernel_mast_hash,
            Self::Update(witness) => witness.new_kernel_mast_hash,
            Self::Merger(witness) => witness.new_kernel.mast_hash(),
        };
        kernel_mast_hash.reversed().values().into()
    }

    fn output(&self) -> Vec<BFieldElement> {
        std::vec![]
    }

    fn program(&self) -> Program {
        SingleProof.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // populate nondeterministic memory with witness
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );

        let mut nondeterminism = NonDeterminism::default().with_ram(memory);
        let stark_verify_snippet = StarkVerify::new_with_dynamic_layout(Stark::default());
        let single_proof_program_hash = SingleProof.hash();

        match self {
            SingleProofWitness::Collection(proof_collection) => {
                nondeterminism
                    .digests
                    .extend_from_slice(&proof_collection.merge_bit_mast_path);

                // removal records integrity
                let rri_claim = proof_collection.removal_records_integrity_claim();
                let rri_proof = &proof_collection.removal_records_integrity;
                stark_verify_snippet.update_nondeterminism(
                    &mut nondeterminism,
                    rri_proof,
                    &rri_claim,
                );

                // kernel to outputs
                let k2o_claim = proof_collection.kernel_to_outputs_claim();
                let k2o_proof = &proof_collection.kernel_to_outputs;
                stark_verify_snippet.update_nondeterminism(
                    &mut nondeterminism,
                    k2o_proof,
                    &k2o_claim,
                );

                // collect lock scripts
                let cls_claim = proof_collection.collect_lock_scripts_claim();
                let cls_proof = &proof_collection.collect_lock_scripts;
                stark_verify_snippet.update_nondeterminism(
                    &mut nondeterminism,
                    cls_proof,
                    &cls_claim,
                );

                // collect type scripts
                let cts_claim = proof_collection.collect_type_scripts_claim();
                let cts_proof = &proof_collection.collect_type_scripts;
                stark_verify_snippet.update_nondeterminism(
                    &mut nondeterminism,
                    cts_proof,
                    &cts_claim,
                );

                // lock scripts
                for (claim, proof) in proof_collection
                    .lock_script_claims()
                    .into_iter()
                    .zip(&proof_collection.lock_scripts_halt)
                {
                    stark_verify_snippet.update_nondeterminism(&mut nondeterminism, proof, &claim);
                }

                // type scripts
                for (claim, proof) in proof_collection
                    .type_script_claims()
                    .into_iter()
                    .zip(&proof_collection.type_scripts_halt)
                {
                    stark_verify_snippet.update_nondeterminism(&mut nondeterminism, proof, &claim);
                }
            }
            SingleProofWitness::Update(witness) => {
                witness.populate_nd_streams(&mut nondeterminism, single_proof_program_hash);
            }
            SingleProofWitness::Merger(witness_of_merge) => {
                witness_of_merge
                    .populate_nd_streams(&mut nondeterminism, single_proof_program_hash);
            }
        }

        nondeterminism
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SingleProof;

impl SingleProof {
    /// Not to be confused with SingleProofWitness::claim
    fn claim(tx_kernel_mast_hash: Digest) -> Claim {
        Claim::about_program(&SingleProof.program())
            .with_input(tx_kernel_mast_hash.reversed().values())
    }
}

/// Not to be confused with SingleProofWitness::claim
///
/// Consensus rule set refers to the rule set for which the claim must be valid.
pub fn single_proof_claim(tx_kernel_mast_hash: Digest, _: ConsensusRuleSet) -> Claim {
    SingleProof::claim(tx_kernel_mast_hash)
}

pub fn produce_single_proof_mock(valid_mock: bool) -> Proof {
    let claim = Claim::new(Digest::default());
    if valid_mock {
        Proof::valid_mock(claim)
    } else {
        Proof::invalid_mock(claim)
    }
}

impl TritonProgram for SingleProof {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();

        // imports
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let assemble_rri_claim = library.import(Box::new(GenerateRriClaim));
        let assemble_k2o_claim = library.import(Box::new(GenerateK2oClaim));
        let assemble_cls_claim = library.import(Box::new(GenerateCollectLockScriptsClaim));
        let assemble_cts_claim = library.import(Box::new(GenerateCollectTypeScriptsClaim));
        let assemble_lock_script_claim_template =
            library.import(Box::new(GenerateLockScriptClaimTemplate));
        let assemble_type_script_claim_template =
            library.import(Box::new(GenerateTypeScriptClaimTemplate));

        let proof_collection_field_kernel_mast_hash = field!(ProofCollection::kernel_mast_hash);
        let proof_collection_field_removal_records_integrity =
            field!(ProofCollection::removal_records_integrity);
        let proof_collection_field_collect_lock_scripts =
            field!(ProofCollection::collect_lock_scripts);
        let proof_collection_field_kernel_to_outputs = field!(ProofCollection::kernel_to_outputs);
        let proof_collection_field_collect_type_scripts =
            field!(ProofCollection::collect_type_scripts);
        let proof_collection_field_lock_scripts_halt = field!(ProofCollection::lock_scripts_halt);
        let proof_collection_field_type_scripts_halt = field!(ProofCollection::type_scripts_halt);

        let update_branch = library.import(Box::new(UpdateBranch));
        let merge_branch = library.import(Box::new(MergeBranch));

        let audit_witness_of_proof_collection =
            library.import(Box::new(VerifyNdSiIntegrity::<ProofCollection>::default()));

        let claim_field_with_size_output = triton_asm!(read_mem 1 addi 1 place 1 addi -1);
        let merkle_verify =
            library.import(Box::new(tasm_lib::hashing::merkle_verify::MerkleVerify));

        let verify_scripts_loop_label = "neptune_transaction_verify_lock_scripts_loop";
        let verify_scripts_loop_body = triton_asm! {
            // INVARIANT: _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size
            {verify_scripts_loop_label}:
                hint current_proof_size = stack[0]
                hint current_proof_ptr = stack[1]
                hint eof = stack[2]
                hint current_program_digest = stack[3]
                hint claim_program_digest = stack[4]
                hint claim_template = stack[5]

                dup 3 dup 3 eq skiz return
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size

                dup 3
                addi {Digest::LEN - 1}
                read_mem {Digest::LEN}
                pop 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size [current_program_digest]

                dup 9
                write_mem {Digest::LEN}
                pop 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size

                dup 5
                dup 2
                call {stark_verify}
                // _ *claim_template *claim_program_digest *current_program_digest *eof *current_proof current_proof_size

                add
                // _ *claim_template *claim_program_digest *current_program_digest *eof *next_proof_si

                read_mem 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof next_proof_size (*next_proof_si-1)
                addi 2
                // _ *claim_template *claim_program_digest *current_program_digest *eof next_proof_size *next_proof
                swap 1
                // _ *claim_template *claim_program_digest *current_program_digest *eof *next_proof next_proof_size

                swap 3
                addi {Digest::LEN}
                swap 3
                // _ *claim_template *claim_program_digest *next_program_digest *eof *next_proof next_proof_size

                recurse
        };

        let verify_merge_bit_false = triton_asm! {
            // _ [txk_digest] garb garb

                dup 6
                dup 6
                dup 6
                dup 6
                dup 6
                // _ [txk_digest] garb garb [txk_digest]

                push {TransactionKernel::MAST_HEIGHT as u32}
                push {TransactionKernelField::MergeBit as u32}
                // _ [txk_digest] garb garb [txk_digest] height index

                push 0
                push 0
                push 0
                push 0
                push 0
                push 0
                push 0
                push 0
                push 1
                push {u32::from(false)}
                // _ [txk_digest] garb garb [txk_digest] height index [padded-false-encoded]

                sponge_init
                sponge_absorb
                sponge_squeeze

                pick 5 pop 1
                pick 5 pop 1
                pick 5 pop 1
                pick 5 pop 1
                pick 5 pop 1
                // _ [txk_digest] garb garb [txk_digest] height index [false-digest]

                call {merkle_verify}
                // _ [txk_digest] garb garb
        };

        let proof_collection_case_label =
            "neptune_transaction_single_proof_case_collection".to_string();
        let proof_collection_case_body = triton_asm! {
            // BEFORE: [txk_digest] *single_proof_witness discriminant
            // AFTER: [txk_digest] *single_proof_witness discriminant
            {proof_collection_case_label}:
                hint discriminant = stack[0]
                hint single_proof_witness = stack[1]
                hint txk_digest = stack[2..7]
                // _ [txk_digest] *single_proof_witness discriminant

                {&verify_merge_bit_false}
                // _ [txk_digest] *single_proof_witness discriminant

                dup 1 addi 2
                hint proof_collection_ptr = stack[0]
                // _ [txk_digest] *spw disc *proof_collection

                dup 0
                call {audit_witness_of_proof_collection}
                // _ [txk_digest] *spw disc *proof_collection proof_collection_size

                place 8
                // _ pc_size [txk_digest] *spw disc *proof_collection
                // _ [txk_digest] *spw disc *proof_collection <-- rename


                /* check kernel MAST hash */

                dup 0 {&proof_collection_field_kernel_mast_hash}
                // [txk_digest] *spw disc *proof_collection *kernel_mast_hash

                push {Digest::LEN - 1} add
                read_mem {Digest::LEN}
                pop 1
                hint kernel_mast_hash: Digest = stack[0..5]
                // [txk_digest] *spw disc *proof_collection [kernel_mast_hash]

                dup 12
                dup 12
                dup 12
                dup 12
                dup 12
                // [txk_digest] *spw disc *proof_collection [kernel_mast_hash] [txk_digest]

                assert_vector
                pop {Digest::LEN}
                // [txk_digest] *spw disc *proof_collection


                /* create and verify removal records integrity claim */
                call {assemble_rri_claim}
                hint rri_claim = stack[0]
                // [txk_digest] *spw disc *proof_collection *rri_claim

                dup 1 {&proof_collection_field_removal_records_integrity}
                // [txk_digest] *spw disc *proof_collection *rri_claim *rri_proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection


                /* create and verify kernel to outputs claim */
                call {assemble_k2o_claim}
                // [txk_digest] *spw disc *proof_collection *k2o_claim

                dup 1 {&proof_collection_field_kernel_to_outputs}
                // [txk_digest] *spw disc *proof_collection *k2o_claim *proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection


                /* assemble and verify collect lock scripts claim */
                dup 0
                // [txk_digest] *spw disc *proof_collection

                call {assemble_cls_claim}
                hint cls_claim = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim

                dup 1 dup 1 swap 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cls_claim *proof_collection

                {&proof_collection_field_collect_lock_scripts}
                // [txk_digest] *spw disc *proof_collection *cls_claim *cls_claim *cls_proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection *cls_claim


                /* assemble and verify collect type scripts claim */

                dup 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *proof_collection

                call {assemble_cts_claim}
                hint cts_claim = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim

                dup 0 dup 3
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *cts_claim *proof_collection

                {&proof_collection_field_collect_type_scripts}
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *cts_claim *cts_proof

                call {stark_verify}
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim


                /* for all lock scripts, assemble claim and verify */
                dup 2
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *proof_collection

                call {assemble_lock_script_claim_template}
                hint program_digest_ptr = stack[0]
                hint lock_script_claim_ptr = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr

                dup 3 {&claim_field_with_size_output}
                hint output_size = stack[0]
                hint lock_script_hashes = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes size

                dup 1 add addi 2
                hint eof = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes *eof

                swap 1 addi 2
                hint lock_script_hashes_i = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *eof *lock_script_hashes[0]

                swap 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes[0] *eof


                dup 6
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes[0] *eof *proof_collection

                {&proof_collection_field_lock_scripts_halt} addi 1
                hint lock_script_proofs_i_si = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes *eof *lock_script_proofs[0]_si

                read_mem 1
                hint proof_size = stack[1]
                addi 2
                swap 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ls_claim_template *program_digest_ptr *lock_script_hashes *eof *lock_script_proofs[0] proof_size

                call {verify_scripts_loop_label}

                pop 5 pop 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim


                /* for all type scripts, assemble claim and verify */
                dup 2
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *proof_collection

                call {assemble_type_script_claim_template}
                hint program_digest_ptr = stack[0]
                hint type_script_claim_ptr = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr

                dup 2 {&claim_field_with_size_output}
                hint output_size = stack[0]
                hint type_script_hashes = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes size

                dup 1 add addi 2
                hint eof = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof

                pick 1 addi 2
                hint type_script_hashes_i = stack[0]
                place 1
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes[0] *eof


                dup 6
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes[0] *eof *proof_collection

                {&proof_collection_field_type_scripts_halt}
                addi 1
                hint type_script_proofs_i_si = stack[0]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof *type_script_proofs[0]_si

                read_mem 1
                hint proof_size = stack[1]
                addi 2
                place 1
                hint type_script_proofs_i = stack[1]
                // [txk_digest] *spw disc *proof_collection *cls_claim *cts_claim *ts_claim_template *program_digest_ptr *type_script_hashes *eof *type_script_proofs[0] proof_size

                call {verify_scripts_loop_label}

                pop 5 pop 4
                addi {-(DISCRIMINANT_FOR_PROOF_COLLECTION as isize) - 1}
                // [txk_digest] *spw -1

                dup 1 addi 2
                // _ [txk_digest] *spw -1 *proof_collection
                // _ pc_size_init [txk_digest] *spw -1 *proof_collection <-- rename

                call {audit_witness_of_proof_collection}
                // _ pc_size_init [txk_digest] *spw -1 pc_size_end

                pick 8
                eq
                assert error_id {MANIPULATED_PROOF_COLLECTION_WITNESS_ERROR}
                // _ [txk_digest] *spw -1

                return
        };

        let verify_discriminant_has_legal_value = triton_asm!(
            // _ discr

            dup 0
            push {DISCRIMINANT_FOR_PROOF_COLLECTION}
            eq

            dup 1
            push {DISCRIMINANT_FOR_UPDATE}
            eq

            dup 2
            push {DISCRIMINANT_FOR_MERGE}
            eq
            // _ discr (discr == proof_coll) (discr == update) (discr == merge)

            add
            add
            // _ discr (discr == proof_coll || discr == update || discr == merge)

            assert error_id {INVALID_WITNESS_DISCRIMINANT_ERROR}
            // _ discr
        );

        let main = triton_asm! {
            // _

            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ [own_digest]

            read_io 5
            // _ [own_digest] [txk_digest]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ [own_digest] [txk_digest] *single_proof_witness

            read_mem 1 addi 1 swap 1
            // _ [own_digest] [txk_digest] *single_proof_witness discriminant

            {&verify_discriminant_has_legal_value}
            // _ [own_digest] [txk_digest] *single_proof_witness discriminant

            /* match discriminant */
            dup 0 push {DISCRIMINANT_FOR_PROOF_COLLECTION} eq
            skiz call {proof_collection_case_label}

            dup 0 push {DISCRIMINANT_FOR_UPDATE} eq
            skiz call {update_branch}

            dup 0 push {DISCRIMINANT_FOR_MERGE} eq
            skiz call {merge_branch}

            // _ [own_digest] [txk_digest] *single_proof_witness discriminant

            // a discriminant of -1 indicates that some branch was executed
            push -1
            eq
            assert error_id {NO_BRANCH_TAKEN_ERROR}

            pop 1 pop 5 pop 5
            // _

            halt
        };

        let code = triton_asm! {
            {&main}
            {&proof_collection_case_body}
            {&verify_scripts_loop_body}
            {&library.all_imports()}
        };

        (library, code)
    }

    fn hash(&self) -> Digest {
        static PROGRAM_DIGEST: OnceLock<Digest> = OnceLock::new();

        let digest = PROGRAM_DIGEST.get_or_init(|| self.program().hash());

        *digest
    }

    fn program(&self) -> Program {
        // Overwrite trait-implementation since this leads to much faster code.
        // Throughout the lifetime of a client, the `SingleProof` program for a
        // given version never changes, so this is OK.
        static PROGRAM: OnceLock<Program> = OnceLock::new();

        let program = PROGRAM.get_or_init(|| {
            let (_, code) = self.library_and_code();
            Program::new(&code)
        });

        program.clone()
    }
}
