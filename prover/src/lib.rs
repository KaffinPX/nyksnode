//! Implements a triton-vm job for proving
//! consensus programs.
//!
//! These proofs take a lot of time, cpu, and memory to
//! create. As such, only one should execute at a time
//! or even the beefiest of today's hardware might run out
//! of resources.
use std::path::PathBuf;
use std::process::Stdio;

use nyks_consensus::transaction::validity::neptune_proof::Proof;
use nyks_consensus::triton_vm::error::InstructionError;
use nyks_consensus::triton_vm::prelude::Program;
use nyks_consensus::triton_vm::proof::Claim;
use nyks_consensus::triton_vm::vm::NonDeterminism;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

use crate::env::TritonVmEnvVars;

pub mod env;

/// Error code from the spawned prover process in the range 200-232 are reserved
/// for communicating that the proof is too big. The error code returned is
/// 200 + the encountered log2 padded height. So guaranteed to be in the range
/// [200-232] where no common error codes live, from what I know.
pub const PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE: i32 = 200;

/// represents an error running a [ProverJob]
#[derive(Debug, thiserror::Error)]
pub enum ProverJobError {
    /// Error code indicating that the processor table is too big. Does not
    /// refer to the actual AET which may still exceed the user-defined limit.
    #[error("triton-vm program complexity limit exceeded. result: {result}, limit: {limit}")]
    ProofComplexityLimitExceeded { limit: u32, result: u32 },

    #[error("external proving process failed: {0}")]
    TritonVmProverFailed(#[from] VmProcessError),
}

/// represents an error invoking external prover process
///
/// provides additional details for [ProverJobError::TritonVmProverFailed]
#[derive(Debug, thiserror::Error)]
pub enum VmProcessError {
    #[error("parameter serialization failed")]
    ParameterSerializationFailed(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("stdin unavailable")]
    StdinUnavailable,

    #[error("result deserialization failed")]
    ResultDeserializationFailed(#[from] Box<bincode::ErrorKind>),

    #[error("proving process returned non-zero exit code: {0}")]
    NonZeroExitCode(i32),

    /// Error code indicating that AET was generated and its padded height too
    /// big.
    #[error("triton-vm program complexity limit exceeded. result: {result}, limit: {limit}")]
    ProofComplexityLimitExceeded { limit: u32, result: u32 },

    // note: on unix an exit with no code indicates the process
    // ended because of a signal, but this is not the case in
    // windows, so cannot be relied upon. There doesn't appear to
    // be any good cross-platform heuristic to determine if a process
    // ended normally or was killed.
    //
    // *if* we could determine the process was externally killed then
    // it would be reasonable to retry the job.
    #[error(
        "out-of-process triton-vm proving job terminated without exit code. \
        Possibly killed by OS. You might not have enough RAM to construct this \
        proof."
    )]
    NoExitCode,

    #[error("Triton VM failed: {0}")]
    TritonVmFailed(InstructionError),
}

#[derive(Debug)]
pub enum ProverProcessCompletion {
    Finished(Proof),
    Cancelled,
}

#[derive(Debug, Clone, Default)]
pub struct ProverJobSettings {
    // TODO: Kept for checking if machine is capable for producing that proof.
    pub max_log2_padded_height_for_proofs: Option<u8>,
    pub triton_vm_env_vars: TritonVmEnvVars,
}

pub type JobCancelReceiver = watch::Receiver<()>; // used in pub trait
pub type JobCancelSender = watch::Sender<()>;

#[derive(Debug, Clone)]
pub struct ProverJob {
    program: Program,
    claim: Claim,
    nondeterminism: NonDeterminism,
    job_settings: ProverJobSettings,
}

impl ProverJob {
    /// instantiate a ProverJob
    pub fn new(
        program: Program,
        claim: Claim,
        nondeterminism: NonDeterminism,
        job_settings: ProverJobSettings,
    ) -> Self {
        Self {
            program,
            claim,
            nondeterminism,
            job_settings,
        }
    }

    /// Run the program and generate a proof for it, assuming the Triton VM run
    /// halts gracefully.
    ///
    /// If a message is received on the [JobCancelReceiver] channel while
    /// proving, the job will be cancelled.
    ///
    /// panics if job cannot be successfully cancelled.
    ///
    /// If we are in a test environment, try reading it from disk. If it is not
    /// there, generate it and store it to disk.
    pub async fn prove(
        &self,
        rx: JobCancelReceiver,
    ) -> Result<ProverProcessCompletion, VmProcessError> {
        // this fn is kept in-case i wanna support mock proofs...
        self.prove_out_of_process(rx).await
    }

    /// runs triton-vm prover out of process.
    ///
    /// This method spawns child process and waits for either:
    ///   1. the child to finish
    ///   2. a job-cancellation message.
    ///
    /// It returns a Result<ProverProcessCompletion, _> indicating:
    ///   1. Ok(Completion) - prover finished successfully (with a Proof)
    ///   2. Ok(Cancelled) - job was cancelled
    ///   3. Err(e) - an error occurred.
    ///
    /// If the job is cancelled while the child process is running then
    /// an attempt is made to kill the child process.  If this attempt
    /// fails, the fn will panic.
    ///
    /// input is sent via stdin, output is received via stdout.
    /// stderr is ignored.
    ///
    /// The prover executable is triton-vm-prover. It must reside
    /// in same directory as xnt-core.
    /// see Self::path_to_triton_vm_prover()
    ///
    /// parameters claim, program, nondeterminism are passed as
    /// json strings.
    ///
    /// the result is a [Proof], which is bincode serialized.
    ///
    /// The process result is only read if exit code is 0.
    /// A non-zero exit code or no code results in an error.
    async fn prove_out_of_process(
        &self,
        mut rx: JobCancelReceiver,
    ) -> Result<ProverProcessCompletion, VmProcessError> {
        use tokio::io::AsyncBufReadExt;
        use tokio::io::BufReader;

        // start child process
        let mut child = {
            let inputs = [
                serde_json::to_string(&self.claim)?,
                serde_json::to_string(&self.program)?,
                serde_json::to_string(&self.nondeterminism)?,
                serde_json::to_string(&self.job_settings.max_log2_padded_height_for_proofs)?,
                serde_json::to_string(&self.job_settings.triton_vm_env_vars)?,
            ];

            let mut child = tokio::process::Command::new(Self::path_to_prover())
                .kill_on_drop(true) // extra insurance.
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;

            let mut child_stdin = child.stdin.take().ok_or(VmProcessError::StdinUnavailable)?;
            child_stdin.write_all(inputs.join("\n").as_bytes()).await?;

            child
        };

        let child_process_id = match child.id() {
            Some(id) => id.to_string(),
            None => "??".to_string(),
        };

        tracing::debug!("prover job started child process. id: {}", child_process_id);

        // Use std err of spawned process for debugging purposes.
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    tracing::debug!("[triton-vm prover]: {line}");
                }
            });
        }

        // see <https://github.com/tokio-rs/tokio/discussions/7132>
        tokio::select! {
            result = process_util::wait_with_output(&mut child) => {
                let output = result?;
                match output.status.code() {
                    Some(0) => {
                        let proof: Proof = bincode::deserialize(&output.stdout)?;
                        tracing::debug!(
                            "Generated proof, with padded height: {}",
                            proof.padded_height()
                                .map(|x| x.to_string())
                                .unwrap_or_else(|e| format!("could not get padded height from proof.\nGot: {e}"))
                        );
                        Ok(ProverProcessCompletion::Finished(proof))
                    }
                    Some(code) => {
                        const LOG2_PADDED_HEIGHT_RANGE: i32 = 32;
                        if (PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE
                            ..=PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE
                                + LOG2_PADDED_HEIGHT_RANGE)
                            .contains(&code)
                        {
                            let limit = self
                                .job_settings
                                .max_log2_padded_height_for_proofs
                                .expect(
                                    "Must have max log2 padded height set if this error reported",
                                )
                                .into();
                            let observed_log_padded_height = (code
                                - PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE)
                                .try_into()
                                .unwrap();
                            Err(VmProcessError::ProofComplexityLimitExceeded {
                                limit,
                                result: observed_log_padded_height,
                            })
                        } else {
                            Err(VmProcessError::NonZeroExitCode(code))
                        }

                    }

                    None => Err(VmProcessError::NoExitCode),
                }
            },

            _ = rx.changed() => {
                tracing::debug!("prover job got cancel message. killing child process. id: {}", child_process_id);
                child.kill().await.expect("external proving process should be killed");
                tracing::debug!("prover job: kill succeeded for child process. id: {},  cancelling job", child_process_id);
                Ok(ProverProcessCompletion::Cancelled)
            }
        }
    }

    /// obtains path to nyks-prover executable
    ///
    /// nyks-prover must reside in the same directory as applications that will use it.
    /// This enables debug builds of nyks to invoke debug build of nyks-prover.
    /// Also works for release build, and for a package/distribution.
    ///
    /// note: we do not verify that the path exists. That will occur anyway
    /// when nyks-prover is executed.
    fn path_to_prover() -> PathBuf {
        let mut exe_path = std::env::current_exe().unwrap();
        exe_path.set_file_name("nyks-prover");
        exe_path
    }
}

// future cleanup: remove this module, when possible.
mod process_util {

    use std::process::Output;

    use tokio::io::AsyncRead;
    use tokio::io::AsyncReadExt;
    use tokio::process::Child;

    // This fn is a slightly modified copy of
    // tokio::process::Child::wait_with_output().
    //
    // As of tokio 1.43.0, Child::wait_with_output() takes `self` argument,
    // which prevents use within a select along with Child::kill().  The docs
    // for Child::kill() demonstrate using a select!() to Child::wait() for a
    // process and optionally kill() it if a message is received.  However,
    // Child::wait_with_output() used in this manner results in a compile error
    // due to the `self` parameter, which differs from `&mut self` that
    // Child::wait() takes.
    //
    // The modified fn below takes `&mut Child` and has some minor mods so it
    // does not rely on internal tokio functions.
    //
    // Links:
    //   A playground demonstrating the compile error:
    //   <https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&gist=a1aaeb3204f62f9369b85d73d7e25c2e>
    //
    //   A playground demonstrating this solution:
    //   <https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&gist=a956940628dd8b0d8bf5d1a546d4a6eb>
    //
    //   A writeup / discussion of the issue:
    //   <https://github.com/tokio-rs/tokio/discussions/7132>
    pub async fn wait_with_output(child: &mut Child) -> tokio::io::Result<Output> {
        async fn read_to_end<A: AsyncRead + Unpin>(
            io: &mut Option<A>,
        ) -> tokio::io::Result<Vec<u8>> {
            let mut vec = Vec::new();
            if let Some(io) = io.as_mut() {
                io.read_to_end(&mut vec).await?;
            }
            Ok(vec)
        }

        let mut stdout_pipe = child.stdout.take();
        let mut stderr_pipe = child.stderr.take();

        let stdout_fut = read_to_end(&mut stdout_pipe);
        let stderr_fut = read_to_end(&mut stderr_pipe);

        let (status, stdout, stderr) = tokio::try_join!(child.wait(), stdout_fut, stderr_fut)?;

        // Drop happens after `try_join` due to <https://github.com/tokio-rs/tokio/issues/4309>
        drop(stdout_pipe);
        drop(stderr_pipe);

        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}
