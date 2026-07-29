use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::*;
use tracing::debug;
use tracing::trace;

use super::removal_records_integrity::RemovalRecordsIntegrity;
use crate::network::Network;
use crate::proof_abstractions::tasm::program::TritonProgram;
#[cfg(not(target_arch = "wasm32"))]
use crate::proof_abstractions::verifier::verify;
use crate::transaction::BFieldCodec;
use crate::transaction::validity::collect_lock_scripts::CollectLockScripts;
use crate::transaction::validity::collect_type_scripts::CollectTypeScripts;
use crate::transaction::validity::kernel_to_outputs::KernelToOutputs;
use crate::transaction::validity::neptune_proof::Proof;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct ProofCollection {
    pub removal_records_integrity: Proof,
    pub collect_lock_scripts: Proof,
    pub lock_scripts_halt: Vec<Proof>,
    pub kernel_to_outputs: Proof,
    pub collect_type_scripts: Proof,
    pub type_scripts_halt: Vec<Proof>,
    pub lock_script_hashes: Vec<Digest>,
    pub type_script_hashes: Vec<Digest>,
    pub kernel_mast_hash: Digest,
    pub salted_inputs_hash: Digest,
    pub salted_outputs_hash: Digest,
    pub merge_bit_mast_path: Vec<Digest>,
}

impl ProofCollection {
    /// Get the total number of proofs in this collection
    pub fn num_proofs(&self) -> usize {
        1 + // removal_records_integrity
        1 + // collect_lock_scripts
        self.lock_scripts_halt.len() + // lock_scripts_halt
        1 + // kernel_to_outputs
        1 + // collect_type_scripts
        self.type_scripts_halt.len() // type_scripts_halt
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn verify(&self, txk_mast_hash: Digest, network: Network) -> bool {
        debug!("verifying, txk hash: {}", txk_mast_hash);
        debug!("verifying, salted inputs hash: {}", self.salted_inputs_hash);
        debug!(
            "verifying, salted outputs hash: {}",
            self.salted_outputs_hash
        );
        // make sure we are talking about the same tx
        if self.kernel_mast_hash != txk_mast_hash {
            return false;
        }

        // There must be exactly one halting proof per collected script hash.
        // The verification loops below use `zip`, which silently truncates to the
        // shorter operand; without this guard a prover could submit fewer (e.g.
        // zero) `*_scripts_halt` proofs than `*_script_hashes` and have the
        // surplus lock-/type-script checks skipped while `verify` still returns
        // `true`. Reject the (attacker-controlled) length mismatch as invalid
        // here rather than via `zip_eq`, which would panic on untrusted input.
        if self.lock_scripts_halt.len() != self.lock_script_hashes.len()
            || self.type_scripts_halt.len() != self.type_script_hashes.len()
        {
            return false;
        }

        // compile claims
        let removal_records_integrity_claim =
            Claim::about_program(&RemovalRecordsIntegrity.program())
                .with_input(self.kernel_mast_hash.reversed().values())
                .with_output(self.salted_inputs_hash.values().to_vec());
        trace!(
            "removal records integrity claim: {:?}",
            removal_records_integrity_claim
        );
        let kernel_to_outputs_claim = Claim::about_program(&KernelToOutputs.program())
            .with_input(self.kernel_mast_hash.reversed().values())
            .with_output(self.salted_outputs_hash.values().to_vec());
        let collect_lock_scripts_claim = Claim::about_program(&CollectLockScripts.program())
            .with_input(self.salted_inputs_hash.reversed().values())
            .with_output(
                self.lock_script_hashes
                    .iter()
                    .flat_map(|d| d.values())
                    .collect(),
            );
        let collect_type_scripts_claim = Claim::about_program(&CollectTypeScripts.program())
            .with_input(
                [self.salted_inputs_hash, self.salted_outputs_hash]
                    .into_iter()
                    .flat_map(|d| d.reversed().values())
                    .collect_vec(),
            )
            .with_output(
                self.type_script_hashes
                    .iter()
                    .flat_map(|d| d.values())
                    .collect_vec(),
            );
        trace!("collect_type_scripts_claim:\n{collect_type_scripts_claim:?}\n\n");
        let lock_script_claims = self
            .lock_script_hashes
            .iter()
            .map(|&lsh| Claim::new(lsh).with_input(self.kernel_mast_hash.reversed().values()))
            .collect_vec();
        let type_script_claims = self
            .type_script_hashes
            .iter()
            .map(|tsh| {
                Claim::new(*tsh).with_input(
                    [
                        self.kernel_mast_hash,
                        self.salted_inputs_hash,
                        self.salted_outputs_hash,
                    ]
                    .into_iter()
                    .flat_map(|d| d.reversed().values())
                    .collect_vec(),
                )
            })
            .collect_vec();

        // verify
        debug!("verifying removal records integrity ...");
        let rri = verify(
            removal_records_integrity_claim.clone(),
            self.removal_records_integrity.clone(),
            network,
        )
        .await;
        debug!("{rri}");
        debug!("verifying kernel to outputs ...");
        let k2o = verify(
            kernel_to_outputs_claim.clone(),
            self.kernel_to_outputs.clone(),
            network,
        )
        .await;
        debug!("{k2o}");
        debug!("verifying collect lock scripts ...");
        let cls = verify(
            collect_lock_scripts_claim.clone(),
            self.collect_lock_scripts.clone(),
            network,
        )
        .await;
        debug!("{cls}");
        debug!("verifying collect type scripts ...");
        let cts = verify(
            collect_type_scripts_claim.clone(),
            self.collect_type_scripts.clone(),
            network,
        )
        .await;
        debug!("{cts}");
        debug!("verifying that all lock scripts halt ...");
        let mut lsh = true;
        for (cl, pr) in lock_script_claims.iter().zip(self.lock_scripts_halt.iter()) {
            lsh &= verify(cl.clone(), pr.clone(), network).await;
        }
        debug!("{lsh}");
        debug!("verifying that all type scripts halt ...");
        let mut tsh = true;
        for (cl, pr) in type_script_claims.iter().zip(self.type_scripts_halt.iter()) {
            tsh &= verify(cl.clone(), pr.clone(), network).await;
        }
        debug!("{tsh}");

        // and all bits together and return
        rri && k2o && cls && cts && lsh && tsh
    }

    pub fn removal_records_integrity_claim(&self) -> Claim {
        Claim::about_program(&RemovalRecordsIntegrity.program())
            .with_input(self.kernel_mast_hash.reversed().values())
            .with_output(self.salted_inputs_hash.values().to_vec())
    }

    pub fn kernel_to_outputs_claim(&self) -> Claim {
        Claim::about_program(&KernelToOutputs.program())
            .with_input(self.kernel_mast_hash.reversed().values())
            .with_output(self.salted_outputs_hash.values().to_vec())
    }

    pub fn collect_lock_scripts_claim(&self) -> Claim {
        let mut lock_script_hashes_as_output = vec![];
        let mut i: usize = 0;
        while i < self.lock_script_hashes.len() {
            let lock_script_hash: Digest = self.lock_script_hashes[i];
            let mut j: usize = 0;
            while j < Digest::LEN {
                lock_script_hashes_as_output.push(lock_script_hash.values()[j]);
                j += 1;
            }
            i += 1;
        }
        Claim::about_program(&CollectLockScripts.program())
            .with_input(self.salted_inputs_hash.reversed().values())
            .with_output(lock_script_hashes_as_output)
    }

    pub fn collect_type_scripts_claim(&self) -> Claim {
        let mut type_script_hashes_as_output = vec![];
        let mut i = 0;
        while i < self.type_script_hashes.len() {
            let type_script_hash: Digest = self.type_script_hashes[i];
            let mut j: usize = 0;
            while j < Digest::LEN {
                type_script_hashes_as_output.push(type_script_hash.values()[j]);
                j += 1;
            }
            i += 1;
        }
        Claim::about_program(&CollectTypeScripts.program())
            .with_input(
                [self.salted_inputs_hash, self.salted_outputs_hash]
                    .map(|digest| digest.reversed().values())
                    .concat(),
            )
            .with_output(type_script_hashes_as_output)
    }

    pub fn lock_script_claims(&self) -> Vec<Claim> {
        let mut claims = vec![];
        let mut i = 0;
        while i < self.lock_script_hashes.len() {
            let claim = Claim::new(self.lock_script_hashes[i])
                .with_input(self.kernel_mast_hash.reversed().values());
            claims.push(claim);

            i += 1;
        }

        claims
    }

    pub fn type_script_claims(&self) -> Vec<Claim> {
        let type_script_input = [
            self.kernel_mast_hash.reversed().values(),
            self.salted_inputs_hash.reversed().values(),
            self.salted_outputs_hash.reversed().values(),
        ]
        .concat();
        let mut claims = vec![];
        let mut i = 0;
        while i < self.type_script_hashes.len() {
            let type_script_hash = self.type_script_hashes[i];
            let claim = Claim::new(type_script_hash).with_input(type_script_input.clone());
            claims.push(claim);
            i += 1;
        }
        claims
    }
}
