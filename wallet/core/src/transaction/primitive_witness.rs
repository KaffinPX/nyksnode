use std::collections::HashMap;
use std::fmt::Display;

use itertools::Itertools;
use nyks_consensus::prelude::tasm_lib::prelude::Tip5;
use nyks_consensus::proof_abstractions::SecretWitness;
use nyks_consensus::proof_abstractions::tasm::program::TritonProgram;
use nyks_consensus::tasm_lib::prelude::Digest;
use nyks_consensus::transaction::lock_script::LockScriptAndWitness;
use nyks_consensus::transaction::salted_utxos::SaltedUtxos;
use nyks_consensus::transaction::transaction_kernel::TransactionKernelField;
use nyks_consensus::transaction::transaction_kernel::TransactionKernelModifier;
use nyks_consensus::transaction::utxo::Utxo;
use nyks_consensus::transaction::validity::collect_lock_scripts::CollectLockScripts;
use nyks_consensus::transaction::validity::collect_lock_scripts::CollectLockScriptsWitness;
use nyks_consensus::transaction::validity::collect_type_scripts::CollectTypeScripts;
use nyks_consensus::transaction::validity::collect_type_scripts::CollectTypeScriptsWitness;
use nyks_consensus::transaction::validity::kernel_to_outputs::KernelToOutputs;
use nyks_consensus::transaction::validity::kernel_to_outputs::KernelToOutputsWitness;
use nyks_consensus::transaction::validity::proof_collection::ProofCollection;
use nyks_consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrity;
use nyks_consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrityWitness;
use nyks_consensus::triton_vm::error::ProvingError;
use nyks_consensus::triton_vm::prelude::BFieldCodec;
use nyks_consensus::triton_vm::vm::PublicInput;
use nyks_consensus::triton_vm::vm::VM;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tracing::info;

use crate::transaction::BuilderTransaction;
use crate::transaction::BuilderTransactionProof;
use crate::transaction::builder::input::TxInputList;
use nyks_consensus::block::mutator_set_update::MutatorSetUpdate;
use nyks_consensus::mutator_set::authenticated_item::AuthenticatedItem;
use nyks_consensus::mutator_set::ms_membership_proof::MsMembershipProof;
use nyks_consensus::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use nyks_consensus::mutator_set::removal_record::RemovalRecord;
use nyks_consensus::proof_abstractions::mast_hash::MastHash;
use nyks_consensus::transaction::transaction_kernel::TransactionKernel;
use nyks_consensus::type_scripts::TypeScriptAndWitness;
use nyks_consensus::type_scripts::known_type_scripts;
use nyks_consensus::type_scripts::known_type_scripts::match_type_script_and_generate_witness;
use tracing::warn;

/// enumerates possible witness validation errors
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WitnessValidationError {
    #[error("invalid lock script. error: {0}")]
    InvalidLockScript(Digest),

    #[error("invalid membership proof")]
    InvalidMembershipProof {
        witness_mutator_set_accumulator_hash: Digest,
        kernel_mutator_set_hash: Digest,
    },

    #[error(
        "missing typescript witness for: {type_script_name},\n with hash:\n {type_script_hash}"
    )]
    MissingTypeScriptWitness {
        type_script_hash: Digest,
        type_script_name: String,
    },

    #[error("Too many typescript witnesses. Expected {expected}, got {got}")]
    TooManyTypeScriptWitnesses { expected: usize, got: usize },

    #[error("invalid type script: {type_script_hash}; ({type_script_name}). Error:\n{vm_error}")]
    InvalidTypeScript {
        type_script_hash: Digest,
        type_script_name: String,
        vm_error: String,
    },

    #[error("removal records generated from witness do not match transaction kernel inputs")]
    RemovalRecordsMismatch {
        witnessed_removal_records: Vec<RemovalRecord>,
        kernel_removal_records: Vec<RemovalRecord>,
    },

    #[error("transaction mutator set does not match witness mutator set")]
    MutatorSetMismatch {
        witness_mutator_set_hash: Digest,
        transaction_mutator_set_hash: Digest,
    },

    #[error("Primitive-witness backed transaction cannot have a set merge bit")]
    MergeBitSet,

    // catch-all error, eg for anyhow errors
    #[error("transaction could not be created.  reason: {0}")]
    Failed(String),
}

/// Identifies which sub-proof is being generated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvingStage {
    RemovalRecordsIntegrity,
    CollectLockScripts,
    KernelToOutputs,
    CollectTypeScripts,
    LockScript {
        index: usize,
        total: usize,
        program_hash: Digest,
    },
    TypeScript {
        index: usize,
        total: usize,
        program_hash: Digest,
        name: String,
    },
}

impl Display for ProvingStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvingStage::RemovalRecordsIntegrity => write!(f, "RemovalRecordsIntegrity"),
            ProvingStage::CollectLockScripts => write!(f, "CollectLockScripts"),
            ProvingStage::KernelToOutputs => write!(f, "KernelToOutputs"),
            ProvingStage::CollectTypeScripts => write!(f, "CollectTypeScripts"),
            ProvingStage::LockScript { index, total, .. } => {
                write!(f, "Lock script {}/{}", index + 1, total)
            }
            ProvingStage::TypeScript {
                index, total, name, ..
            } => {
                write!(f, "Type script {}/{} ({name})", index + 1, total)
            }
        }
    }
}

/// The raw witness is the most primitive type of transaction witness.
/// It exposes secret data and is therefore not for broadcasting.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec)]
pub struct PrimitiveWitness {
    pub input_utxos: SaltedUtxos,
    pub input_membership_proofs: Vec<MsMembershipProof>,
    pub lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
    pub type_scripts_and_witnesses: Vec<TypeScriptAndWitness>,
    pub output_utxos: SaltedUtxos,
    pub output_sender_randomnesses: Vec<Digest>,
    pub output_receiver_digests: Vec<Digest>,
    pub mutator_set_accumulator: MutatorSetAccumulator,
    pub kernel: TransactionKernel,
}

impl Display for PrimitiveWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let coinbase_str = match self.kernel.coinbase {
            Some(cb) => format!("Yes: {cb}"),
            None => "No".to_owned(),
        };
        let utxo_digests = self.input_utxos.utxos.iter().map(Tip5::hash);
        let kernel_merkle_tree = self.kernel.merkle_tree();
        let mut kernel_mt_leafs = kernel_merkle_tree.leafs();
        write!(
            f,
            "inputs: [{}]\noutputs: [{}]\ncoinbase: {}\nfee: {}\n\
            txk mast hash: {}\n\ninput canonical commitments:\n{}\n\
            kernel mast hash leafs:\n{}\n\n\n",
            self.input_utxos,
            self.output_utxos,
            coinbase_str,
            self.kernel.fee,
            self.kernel.mast_hash(),
            self.input_membership_proofs
                .iter()
                .zip_eq(utxo_digests)
                .map(|(msmp, utxo_digest)| msmp.addition_record(utxo_digest).canonical_commitment)
                .join("\n"),
            kernel_mt_leafs.join("\n"),
        )
    }
}

impl PrimitiveWitness {
    /// Generate a primitive witness for a transaction from various disparate witness data.
    ///
    /// # Panics
    /// Panics if transaction validity cannot be satisfied.
    pub fn generate_primitive_witness(
        unlocked_utxos: &TxInputList,
        output_utxos: Vec<Utxo>,
        sender_randomnesses: Vec<Digest>,
        receiver_digests: Vec<Digest>,
        transaction_kernel: TransactionKernel,
        mutator_set_accumulator: MutatorSetAccumulator,
    ) -> PrimitiveWitness {
        /// Generate a salt to use for [SaltedUtxos], deterministically.
        fn generate_secure_pseudorandom_seed(
            input_utxos: &Vec<Utxo>,
            output_utxos: &Vec<Utxo>,
            sender_randomnesses: &Vec<Digest>,
        ) -> [u8; 32] {
            let preimage = [
                input_utxos.encode(),
                output_utxos.encode(),
                sender_randomnesses.encode(),
            ]
            .concat();
            let seed = Tip5::hash_varlen(&preimage);
            let seed: [u8; Digest::BYTES] = seed.into();

            seed[0..32].try_into().unwrap()
        }

        let input_utxos = unlocked_utxos
            .iter()
            .map(|unlocker| unlocker.utxo.to_owned())
            .collect_vec();
        let salt_seed =
            generate_secure_pseudorandom_seed(&input_utxos, &output_utxos, &sender_randomnesses);

        let mut rng = StdRng::from_seed(salt_seed);
        let salted_output_utxos = SaltedUtxos::new_with_rng(output_utxos.to_vec(), &mut rng);
        let salted_input_utxos = SaltedUtxos::new_with_rng(input_utxos.clone(), &mut rng);

        let type_script_hashes =
            Utxo::type_script_hashes(input_utxos.iter().chain(output_utxos.iter()));
        let type_scripts_and_witnesses = type_script_hashes
            .into_iter()
            .map(|type_script_hash| {
                match_type_script_and_generate_witness(
                    type_script_hash,
                    transaction_kernel.clone(),
                    salted_input_utxos.clone(),
                    salted_output_utxos.clone(),
                )
                .expect("type script hash should be known.")
            })
            .collect_vec();
        let input_lock_scripts_and_witnesses = unlocked_utxos
            .iter()
            .map(|unlocker| unlocker.lock_script_and_witness())
            .cloned()
            .collect_vec();
        let input_membership_proofs = unlocked_utxos
            .iter()
            .map(|unlocker| unlocker.membership_proof().to_owned())
            .collect_vec();

        PrimitiveWitness {
            input_utxos: salted_input_utxos,
            lock_scripts_and_witnesses: input_lock_scripts_and_witnesses,
            type_scripts_and_witnesses,
            input_membership_proofs,
            output_utxos: salted_output_utxos,
            output_sender_randomnesses: sender_randomnesses.to_vec(),
            output_receiver_digests: receiver_digests.to_vec(),
            mutator_set_accumulator,
            kernel: transaction_kernel,
        }
    }

    /// Verify the transaction directly from primitive witness
    ///
    /// (without proofs or decomposing into subclaims).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn validate(&self) -> Result<(), WitnessValidationError> {
        for lock_script_and_witness in &self.lock_scripts_and_witnesses {
            let lock_script = lock_script_and_witness.program.clone();
            let secret_input = lock_script_and_witness.nondeterminism();
            let public_input = Tip5::hash(self).reversed().encode().into();

            // This could be a lengthy, CPU intensive call.
            // Also, the lock script is satisfied if it halts gracefully (i.e., without crashing).
            // The output is irrelevant.
            let result = tokio::task::spawn_blocking(move || {
                VM::run(lock_script.clone(), public_input, secret_input)
            })
            .await;

            let Ok(run_res) = result else {
                let reason = "Failed to spawn task for verifying lock script.";
                let error = WitnessValidationError::Failed(reason.into());
                warn!("{}", error);
                return Err(error);
            };

            if let Err(_e) = run_res {
                // tbd: should we include the VMerror in InvalidLockScript error?
                let error = WitnessValidationError::InvalidLockScript(
                    lock_script_and_witness.program.hash(),
                );
                warn!("{}", error);
                return Err(error);
            }
        }

        // Verify correct computation of removal records. Also, collect the removal
        // records' hashes in order to validate them against those provided in the
        // transaction kernel later.
        let mut witnessed_removal_records = vec![];
        for (input_utxo, membership_proof) in self
            .input_utxos
            .utxos
            .iter()
            .zip_eq(&self.input_membership_proofs)
        {
            let item = Tip5::hash(input_utxo);
            // TODO: write these functions in tasm
            if !self.mutator_set_accumulator.verify(item, membership_proof) {
                let error = WitnessValidationError::InvalidMembershipProof {
                    witness_mutator_set_accumulator_hash: self.mutator_set_accumulator.hash(),
                    kernel_mutator_set_hash: self.kernel.mutator_set_hash,
                };
                warn!("{} - {:#?}", error, error);
                return Err(error);
            }
            let removal_record = self.mutator_set_accumulator.drop(item, membership_proof);
            witnessed_removal_records.push(removal_record);
        }

        // verify that all type required scripts are present.
        let required_type_script_hashes = Utxo::type_script_hashes(
            self.output_utxos
                .utxos
                .iter()
                .chain(&self.input_utxos.utxos),
        );
        let type_script_dictionary = self
            .type_scripts_and_witnesses
            .iter()
            .map(|tsaw| (tsaw.program.hash(), tsaw.program.to_owned()))
            .collect::<HashMap<_, _>>();

        // Verify we don't have too many type script witnesses.
        if type_script_dictionary.len() > required_type_script_hashes.len() {
            let error = WitnessValidationError::TooManyTypeScriptWitnesses {
                expected: required_type_script_hashes.len(),
                got: type_script_dictionary.len(),
            };
            warn!("{}", error);
            return Err(error);
        }

        // all must be in dictionary.  so if we find first that is not then it
        // is already an error.  note that the error only informs caller of the
        // first unknown, not all.
        if let Some(first_missing_type_script_hash) = required_type_script_hashes
            .iter()
            .find(|tsh| !type_script_dictionary.contains_key(tsh))
        {
            let typescript_name =
                known_type_scripts::typescript_name(*first_missing_type_script_hash);
            let error = WitnessValidationError::MissingTypeScriptWitness {
                type_script_hash: *first_missing_type_script_hash,
                type_script_name: typescript_name.to_owned(),
            };
            warn!("{}", error);
            return Err(error);
        }

        // verify type scripts
        for (j, type_script_hash) in required_type_script_hashes.iter().enumerate() {
            let type_script = type_script_dictionary[type_script_hash].clone();
            let nondeterminism = self.type_scripts_and_witnesses[j].nondeterminism();
            let public_input = [
                self.kernel.mast_hash(),
                Tip5::hash(&self.input_utxos),
                Tip5::hash(&self.output_utxos),
            ]
            .into_iter()
            .flat_map(|d| d.reversed().values())
            .collect_vec();
            let public_input: PublicInput = public_input.into();

            // Like above: potentially lengthy, CPU intensive call, only thing that matters
            // is error-free completion.
            let result = tokio::task::spawn_blocking(move || {
                VM::run(type_script, public_input, nondeterminism)
            })
            .await;

            let Ok(run_res) = result else {
                let reason = "Failed to spawn task for verifying type script.";
                let error = WitnessValidationError::Failed(reason.into());
                warn!("{}", error);
                return Err(error);
            };

            if let Err(vm_error) = run_res {
                // tbd: should we include the VMError in InvalidTypeScript error?
                let typescript_name = known_type_scripts::typescript_name(*type_script_hash);
                let error = WitnessValidationError::InvalidTypeScript {
                    type_script_hash: *type_script_hash,
                    type_script_name: typescript_name.to_owned(),
                    vm_error: vm_error.to_string(),
                };
                warn!("{}", error);
                return Err(error);
            }
        }

        if witnessed_removal_records != self.kernel.inputs {
            let error = WitnessValidationError::RemovalRecordsMismatch {
                witnessed_removal_records,
                kernel_removal_records: self.kernel.inputs.clone(),
            };
            warn!("{} - {:#?}", error, error);
            return Err(error);
        }

        if self.mutator_set_accumulator.hash() != self.kernel.mutator_set_hash {
            let error = WitnessValidationError::MutatorSetMismatch {
                witness_mutator_set_hash: self.mutator_set_accumulator.hash(),
                transaction_mutator_set_hash: self.kernel.mutator_set_hash,
            };
            warn!("{} - {:#?}", error, error);
            return Err(error);
        }

        if self.kernel.merge_bit {
            let error = WitnessValidationError::MergeBitSet;
            warn!("{} - {:#?}", error, error);
            return Err(error);
        }

        // announcements: there isn't anything to verify

        Ok(())
    }

    /// Update a primitive witness to be valid under a new mutator set.
    ///
    /// Assumes initial primitive witness is valid, and that inputs were not
    /// spent in the supplied mutator set update. Otherwise panics. Also
    /// assumes that the lock script witnesses are still valid under the new
    /// mutator set.
    pub fn update_with_new_ms_data(self, mutator_set_update: MutatorSetUpdate) -> Self {
        let mut msa_state: MutatorSetAccumulator = self.mutator_set_accumulator.clone();
        let mut transaction_removal_records: Vec<RemovalRecord> = self.kernel.inputs.clone();
        let mut transaction_removal_records: Vec<&mut RemovalRecord> =
            transaction_removal_records.iter_mut().collect();

        let mut primitive_witness = self;

        let old_membership_proofs = primitive_witness.input_membership_proofs.clone();
        let own_items = primitive_witness
            .input_utxos
            .utxos
            .iter()
            .map(Tip5::hash)
            .collect_vec();
        let mut authenticated_items = own_items
            .into_iter()
            .zip(old_membership_proofs)
            .map(|(item, msmp)| AuthenticatedItem {
                item,
                ms_membership_proof: msmp,
            })
            .collect_vec();

        // Don't need to check return value because we assume inputs are not
        // spent in supplied mutator set update.
        let _ = mutator_set_update.apply_to_accumulator_and_records(
            &mut msa_state,
            &mut transaction_removal_records,
            &mut authenticated_items.iter_mut().collect_vec(),
        );
        let new_membership_proofs = authenticated_items
            .into_iter()
            .map(|x| x.ms_membership_proof)
            .collect_vec();
        primitive_witness.input_membership_proofs = new_membership_proofs;

        let kernel = TransactionKernelModifier::default()
            .inputs(
                transaction_removal_records
                    .into_iter()
                    .map(|x| x.to_owned())
                    .collect_vec(),
            )
            .mutator_set_hash(msa_state.hash())
            .clone_modify(&primitive_witness.kernel);

        primitive_witness.kernel = kernel.clone();
        primitive_witness.mutator_set_accumulator = msa_state.clone();

        // Set type_scripts_and_witnesses field from other fields in primitive witness.
        let type_scripts_and_witnesses = primitive_witness
            .type_scripts_and_witnesses
            .iter()
            .map(|ts_and_w| {
                match_type_script_and_generate_witness(
                    ts_and_w.program.hash(),
                    kernel.clone(),
                    primitive_witness.input_utxos.clone(),
                    primitive_witness.output_utxos.clone(),
                )
                .expect("type script hash should be known.")
            })
            .collect_vec();
        primitive_witness.type_scripts_and_witnesses = type_scripts_and_witnesses;

        primitive_witness
    }

    pub fn prove(&self) -> Result<ProofCollection, ProvingError> {
        self.prove_with_progress(|_| {})
    }

    pub fn prove_with_progress(
        &self,
        mut on_progress: impl FnMut(ProvingStage),
    ) -> Result<ProofCollection, ProvingError> {
        // TODO: potentially add a way to show progress of proving...
        let (
            removal_records_integrity_witness,
            collect_lock_scripts_witness,
            kernel_to_outputs_witness,
            collect_type_scripts_witness,
        ) = self.extract_specific_witnesses();

        let txk_mast_hash = self.kernel.mast_hash();
        let txk_mast_hash_as_input = PublicInput::new(txk_mast_hash.reversed().values().to_vec());
        let salted_inputs_hash = Tip5::hash(&self.input_utxos);
        let salted_outputs_hash = Tip5::hash(&self.output_utxos);

        info!("Starting proving of {:x}...", txk_mast_hash);

        on_progress(ProvingStage::RemovalRecordsIntegrity);
        let removal_records_integrity = RemovalRecordsIntegrity.prove(
            removal_records_integrity_witness.claim(),
            removal_records_integrity_witness.nondeterminism(),
        )?;

        on_progress(ProvingStage::CollectLockScripts);
        let collect_lock_scripts = CollectLockScripts.prove(
            collect_lock_scripts_witness.claim(),
            collect_lock_scripts_witness.nondeterminism(),
        )?;

        on_progress(ProvingStage::KernelToOutputs);
        let kernel_to_outputs = KernelToOutputs.prove(
            kernel_to_outputs_witness.claim(),
            kernel_to_outputs_witness.nondeterminism(),
        )?;

        on_progress(ProvingStage::CollectTypeScripts);
        let collect_type_scripts = CollectTypeScripts.prove(
            collect_type_scripts_witness.claim(),
            collect_type_scripts_witness.nondeterminism(),
        )?;

        let lock_scripts_len = self.lock_scripts_and_witnesses.len();
        let mut lock_scripts_halt = vec![];

        for (i, lock_script_and_witness) in self.lock_scripts_and_witnesses.iter().enumerate() {
            on_progress(ProvingStage::LockScript {
                index: i,
                total: lock_scripts_len,
                program_hash: lock_script_and_witness.program.hash(),
            });
            lock_scripts_halt.push(lock_script_and_witness.prove(txk_mast_hash_as_input.clone())?);
        }

        let type_scripts_len = self.type_scripts_and_witnesses.len();
        let mut type_scripts_halt = vec![];

        for (i, tsaw) in self.type_scripts_and_witnesses.iter().enumerate() {
            let hash = tsaw.program.hash();
            on_progress(ProvingStage::TypeScript {
                index: i,
                total: type_scripts_len,
                program_hash: tsaw.program.hash(),
                name: known_type_scripts::typescript_name(hash).to_owned(),
            });
            type_scripts_halt.push(tsaw.prove(
                txk_mast_hash,
                salted_inputs_hash,
                salted_outputs_hash,
            )?);
        }

        let lock_script_hashes = self
            .lock_scripts_and_witnesses
            .iter()
            .map(|lsaw| lsaw.program.hash())
            .collect_vec();
        let type_script_hashes = self
            .type_scripts_and_witnesses
            .iter()
            .map(|tsaw| tsaw.program.hash())
            .collect_vec();
        let merge_bit_mast_path = self.kernel.mast_path(TransactionKernelField::MergeBit);

        Ok(ProofCollection {
            removal_records_integrity,
            collect_lock_scripts,
            lock_scripts_halt,
            kernel_to_outputs,
            collect_type_scripts,
            type_scripts_halt,
            lock_script_hashes,
            type_script_hashes,
            kernel_mast_hash: txk_mast_hash,
            salted_inputs_hash,
            salted_outputs_hash,
            merge_bit_mast_path,
        })
    }

    fn extract_specific_witnesses(
        &self,
    ) -> (
        RemovalRecordsIntegrityWitness,
        CollectLockScriptsWitness,
        KernelToOutputsWitness,
        CollectTypeScriptsWitness,
    ) {
        // collect witnesses
        let removal_records_integrity_witness = RemovalRecordsIntegrityWitness::from(self);
        let collect_lock_scripts_witness = CollectLockScriptsWitness::from(self);
        let kernel_to_outputs_witness = KernelToOutputsWitness::from(self);
        let collect_type_scripts_witness = CollectTypeScriptsWitness::from(self);

        (
            removal_records_integrity_witness,
            collect_lock_scripts_witness,
            kernel_to_outputs_witness,
            collect_type_scripts_witness,
        )
    }
}

impl From<&PrimitiveWitness> for RemovalRecordsIntegrityWitness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            input_utxos: primitive_witness.input_utxos.clone(),
            membership_proofs: primitive_witness.input_membership_proofs.clone(),
            aocl_auth_paths: primitive_witness
                .input_membership_proofs
                .iter()
                .map(|x| x.auth_path_aocl.to_owned())
                .collect(),
            coinbase: primitive_witness.kernel.coinbase,
            removal_records: primitive_witness.kernel.inputs.clone(),
            aocl: primitive_witness.mutator_set_accumulator.aocl.clone(),
            swbfi: primitive_witness
                .mutator_set_accumulator
                .swbf_inactive
                .clone(),
            swbfa_hash: Tip5::hash(&primitive_witness.mutator_set_accumulator.swbf_active),
            mast_path_mutator_set: primitive_witness
                .kernel
                .mast_path(TransactionKernelField::MutatorSetHash),
            mast_path_inputs: primitive_witness
                .kernel
                .mast_path(TransactionKernelField::Inputs),
            mast_path_coinbase: primitive_witness
                .kernel
                .mast_path(TransactionKernelField::Coinbase),
            mast_root: primitive_witness.kernel.mast_hash(),
        }
    }
}

impl From<&PrimitiveWitness> for CollectLockScriptsWitness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            salted_input_utxos: primitive_witness.input_utxos.clone(),
        }
    }
}

impl From<&PrimitiveWitness> for KernelToOutputsWitness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            output_utxos: primitive_witness.output_utxos.clone(),
            sender_randomnesses: primitive_witness.output_sender_randomnesses.clone(),
            receiver_digests: primitive_witness.output_receiver_digests.clone(),
            kernel: primitive_witness.kernel.clone(),
        }
    }
}

impl From<&PrimitiveWitness> for CollectTypeScriptsWitness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            salted_input_utxos: primitive_witness.input_utxos.clone(),
            salted_output_utxos: primitive_witness.output_utxos.clone(),
        }
    }
}

impl From<PrimitiveWitness> for BuilderTransaction {
    fn from(pw: PrimitiveWitness) -> Self {
        BuilderTransaction {
            kernel: pw.kernel.clone(),
            proof: BuilderTransactionProof::Witness(pw),
        }
    }
}
