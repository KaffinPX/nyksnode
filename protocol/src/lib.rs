// recursion limit for macros (e.g. triton_asm!)
#![recursion_limit = "2048"]
#![deny(clippy::shadow_unrelated)]

pub mod consensus;
pub mod prelude;
pub mod proof_abstractions;

pub use prelude::tasm_lib;
pub use prelude::triton_vm;
pub use prelude::twenty_first;
pub use triton_vm::prelude::BFieldElement;
