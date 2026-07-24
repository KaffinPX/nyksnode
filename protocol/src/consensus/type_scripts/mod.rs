pub mod amount;
pub mod known_type_scripts;
pub mod native_currency;
pub mod native_currency_amount;
pub mod time_lock;

use std::collections::HashMap;
use std::hash::Hasher as StdHasher;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::error::ProvingError;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::transaction::transaction_kernel::TransactionKernel;
use super::transaction::utxo::Coin;
use crate::consensus::transaction::salted_utxos::SaltedUtxos;
use crate::consensus::transaction::validity::neptune_proof::Proof;
use crate::proof_abstractions::mast_hash::MastHash;
use crate::proof_abstractions::tasm::program::TritonProgram;

pub trait TypeScript: TritonProgram {
    type State: BFieldCodec;

    fn try_decode_state(
        &self,
        state: &[BFieldElement],
    ) -> Result<Box<Self::State>, <Self::State as BFieldCodec>::Error> {
        Self::State::decode(state)
    }

    fn matches_coin(&self, coin: &Coin) -> bool {
        self.try_decode_state(&coin.state).is_ok() && coin.type_script_hash == self.hash()
    }
}

pub trait TypeScriptWitness {
    fn new(
        transaction_kernel: TransactionKernel,
        salted_input_utxos: SaltedUtxos,
        salted_output_utxos: SaltedUtxos,
    ) -> Self;
    fn transaction_kernel(&self) -> TransactionKernel;
    fn salted_input_utxos(&self) -> SaltedUtxos;
    fn salted_output_utxos(&self) -> SaltedUtxos;
    fn type_script_and_witness(&self) -> TypeScriptAndWitness;
    fn type_script_standard_input(&self) -> PublicInput {
        PublicInput::new(
            [
                self.transaction_kernel().mast_hash().reversed().values(),
                Tip5::hash(&self.salted_input_utxos()).reversed().values(),
                Tip5::hash(&self.salted_output_utxos()).reversed().values(),
            ]
            .concat()
            .to_vec(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TypeScriptAndWitness {
    pub program: Program,
    nd_tokens: Vec<BFieldElement>,
    nd_memory: Vec<(BFieldElement, BFieldElement)>,
    nd_digests: Vec<Digest>,
}

impl TypeScriptAndWitness {
    pub fn new_with_nondeterminism(program: Program, witness: NonDeterminism) -> Self {
        Self {
            program,
            nd_memory: witness.ram.into_iter().collect(),
            nd_tokens: witness.individual_tokens,
            nd_digests: witness.digests,
        }
    }

    #[cfg(any(test, feature = "arbitrary-impls"))]
    pub fn new_with_tokens(program: Program, tokens: Vec<BFieldElement>) -> Self {
        Self {
            program,
            nd_memory: vec![],
            nd_tokens: tokens,
            nd_digests: vec![],
        }
    }

    pub fn nondeterminism(&self) -> NonDeterminism {
        NonDeterminism::new(self.nd_tokens.clone())
            .with_digests(self.nd_digests.clone())
            .with_ram(self.nd_memory.iter().copied().collect::<HashMap<_, _>>())
    }

    /// Assuming the type script halts gracefully, prove it.
    pub fn prove(
        &self,
        txk_mast_hash: Digest,
        salted_inputs_hash: Digest,
        salted_outputs_hash: Digest,
    ) -> Result<Proof, ProvingError> {
        let input: Vec<_> = [txk_mast_hash, salted_inputs_hash, salted_outputs_hash]
            .into_iter()
            .flat_map(|d| d.reversed().values())
            .collect();
        let claim = Claim::new(self.program.hash()).with_input(input);

        triton_vm::prove(
            Stark::default(),
            &claim,
            self.program.clone(),
            self.nondeterminism(),
        )
        .map(|proof| proof.into())
    }
}

impl std::hash::Hash for TypeScriptAndWitness {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        self.program.instructions.hash(state);
        self.nd_tokens.hash(state);
        self.nd_memory.hash(state);
        self.nd_digests.hash(state);
    }
}
