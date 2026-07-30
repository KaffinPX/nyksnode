use std::panic::RefUnwindSafe;
use tasm_lib::prelude::triton_vm;

use tasm_lib::library::Library;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::error::InstructionError;
use tasm_lib::triton_vm::error::ProvingError;
use tasm_lib::triton_vm::prelude::*;

use crate::transaction::validity::nyks_proof::NyksProof;

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
    fn prove(
        &self,
        claim: Claim,
        nondeterminism: NonDeterminism,
    ) -> Result<NyksProof, ProvingError> {
        triton_vm::prove(Stark::default(), &claim, self.program(), nondeterminism)
            .map(|proof| proof.into())
    }
}

#[cfg(test)]
pub mod tests {
    /// Test for regressions in a Triton program.
    ///
    /// As Triton programs are refactored to improve readability, it is
    /// important to ensure that the program does not actually change. If such a
    /// change affects a *consensus program* then BOOM! hard fork.
    ///
    /// This test checks the program's hash against a hardcoded value. If the
    /// program changes and that hardcoded value is not updated in lockstep, the
    /// test will fail.
    ///
    /// Example usage:
    ///
    /// ```
    /// use crate::models::proof_abstractions::tasm::program::test_program_snapshot;
    ///
    /// struct MyProgram;
    ///
    /// impl TritonProgram for MyProgram {
    ///     fn library_and_code() ->  (Library, Vec<LabelledInstruction>) {
    ///         /// ...
    ///         (Library::new(), vec![])
    ///     }
    /// }
    ///
    /// #[cfg(test)]
    /// mod test {
    ///     use super::*;
    ///
    ///     test_program_snapshot!(
    ///         MyProgram,
    ///         // snapshot taken from master on 2025-02-11 at 12:00 [commit id]
    ///         "c0f8cbc73a844ab6c3586d8891e29b677a3aa08f25f9aec0f854a72bf2e2f84c2a48c9dd1bbe0a66"
    ///     );
    /// }
    /// ```
    macro_rules! test_program_snapshot {
        ($consensus_program:expr, $hash_hex:literal $(,)?) => {
            #[test]
            fn program_hash_has_not_changed() {
                let old_hash = $hash_hex.to_string();
                let new_hash = $consensus_program.program().hash().to_hex();
                println!("old hash: {old_hash}");
                println!("new hash: {new_hash}");
                assert_eq!(old_hash, new_hash);
            }
        };
    }

    pub(crate) use test_program_snapshot;
}
