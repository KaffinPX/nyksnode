//! Re-exports the most commonly-needed APIs of nyksnode.
//!
//! This module is intended to be wildcard-imported, _i.e._, `use nyks_protocol::prelude::twenty_first;`.
//! You might also want to consider wildcard-importing these prelude,
//! `use nyks_protocol::prelude::tasm_lib::prelude::*;`.
//! `use nyks_protocol::prelude::triton_vm::prelude::*;`.

pub use tasm_lib;
pub use tasm_lib::prelude::triton_vm;
pub use tasm_lib::prelude::twenty_first;
