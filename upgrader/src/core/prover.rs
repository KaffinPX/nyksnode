use nyks_consensus::proof_abstractions::SecretWitness;
use nyks_consensus::proof_abstractions::tasm::program::TritonProgram;
use nyks_consensus::transaction::validity::nyks_proof::NyksProof;
use nyks_consensus::transaction::validity::single_proof::SingleProof;
use nyks_consensus::transaction::validity::single_proof::SingleProofWitness;
use nyks_prover::JobCancelReceiver;
use nyks_prover::ProverJob;
use nyks_prover::ProverJobSettings;
use nyks_prover::ProverProcessCompletion;
use std::sync::OnceLock;

static PROVER_SETTINGS: OnceLock<ProverJobSettings> = OnceLock::new();

pub fn init_prover_settings(settings: ProverJobSettings) {
    PROVER_SETTINGS
        .set(settings)
        .expect("prover settings already initialised");
}

/// Prove a single‑proof witness using the global settings.
/// Returns `None` if the proof was cancelled or the actual prover returned an error.
pub async fn prove_sp_program(
    witness: SingleProofWitness,
    cancel_rx: JobCancelReceiver,
) -> Option<NyksProof> {
    let settings = PROVER_SETTINGS
        .get()
        .expect("prover settings not initialised - call init_prover_settings() first");

    let job = ProverJob::new(
        SingleProof.program(),
        witness.claim(),
        witness.nondeterminism(),
        settings.clone(),
    );

    match job.prove(cancel_rx).await.ok()? {
        ProverProcessCompletion::Finished(proof) => Some(proof),
        ProverProcessCompletion::Cancelled => None,
    }
}
