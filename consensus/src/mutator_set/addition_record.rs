use std::fmt::Display;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::tip5::digest::Digest;

#[derive(
    Clone,
    Copy,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    GetSize,
    BFieldCodec,
    TasmObject,
)]
pub struct AdditionRecord {
    pub canonical_commitment: Digest,
}

impl AdditionRecord {
    pub fn new(canonical_commitment: Digest) -> Self {
        Self {
            canonical_commitment,
        }
    }
}

impl Display for AdditionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.canonical_commitment)
    }
}
