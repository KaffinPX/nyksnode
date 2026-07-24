use std::panic::RefUnwindSafe;
use tasm_lib::prelude::triton_vm;

use tasm_lib::library::Library;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::error::InstructionError;
use tasm_lib::triton_vm::error::ProvingError;
use tasm_lib::triton_vm::prelude::*;

use crate::consensus::transaction::validity::neptune_proof::Proof;

#[derive(Debug, Clone)]
pub enum TritonError {
    RustShadowPanic(String),
    TritonVMPanic(String, InstructionError),
}

/// A [`TritonProgram`] represents the logic subprogram for transaction or
/// block validity.
pub trait TritonProgram
where
    Self: RefUnwindSafe + std::fmt::Debug,
{
    /// Helps identify all imported Triton assembly snippets.
    /// You probably want to use [`Self::program`].
    // Implemented this way to ensure synchronicity between the library in use
    // and the actual code.
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>);

    /// The Triton VM [`Program`].
    fn program(&self) -> Program {
        let (_, code) = self.library_and_code();
        Program::new(&code)
    }

    /// The [program](Self::program)'s hash [digest](Digest).
    //
    // note: we do not provide a default impl because implementors should cache
    // their Digest with OnceLock.
    fn hash(&self) -> Digest;

    /// Run the program and generate a proof for it, assuming running halts
    /// gracefully.
    ///
    /// If we are in the test environment, try reading it from disk. And if it
    /// not there, generate it and store it to disk.
    ///
    /// This method is a thin wrapper around `prove_consensus_program`, which
    /// does the same but for arbitrary programs.
    //
    // The entire trait is only `pub` to facilitate benchmarks; it is not part of
    // the public API. The suppressed lints below are not nice, but I don't know
    // how else to make it work.
    fn prove(&self, claim: Claim, nondeterminism: NonDeterminism) -> Result<Proof, ProvingError> {
        triton_vm::prove(Stark::default(), &claim, self.program(), nondeterminism)
            .map(|proof| proof.into())
    }
}
