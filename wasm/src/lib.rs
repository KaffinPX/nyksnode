use nyks_protocol::consensus::block::Block;
use nyks_protocol::consensus::network::Network;
use nyks_protocol::consensus::transaction::lock_script::LockScriptAndWitness;
use nyks_protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_protocol::proof_abstractions::timestamp::Timestamp;
use nyks_protocol::triton_vm::vm::PublicInput;
use nyks_protocol::twenty_first::tip5::Digest;
use nyks_wallet_core::transaction::builder::TransactionBuilder;
use nyks_wallet_core::transaction::builder::input::TxInputList;
use nyks_wallet_core::transaction::builder::output::TxOutput;

use wasm_bindgen::prelude::*;

pub use wasm_bindgen_rayon::init_thread_pool;
pub mod wallet_entropy;

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    tracing_wasm::set_as_global_default();
}

#[wasm_bindgen]
pub fn benchmark_nop_generation() {
    let genesis_block = Block::genesis(Network::Main);
    let mutator_set_accumulator = genesis_block.mutator_set_accumulator_after().unwrap();
    let transaction = TransactionBuilder::new()
        .inputs(TxInputList::empty())
        .outputs(Vec::<TxOutput>::new().into())
        .fee(NativeCurrencyAmount::from_nau(0))
        .timestamp(genesis_block.header().timestamp + Timestamp::seconds(1))
        .mutator_set_accumulator(mutator_set_accumulator)
        .build()
        .unwrap();
    let _ = transaction.upgrade();
}

#[wasm_bindgen]
pub fn benchmark_lock_script_proving() {
    let key = Digest::default();
    let lock_script_and_witness = LockScriptAndWitness::standard_hash_lock_from_preimage(key);
    let binding_hash_input = PublicInput::new(key.reversed().values().to_vec());
    let _ = lock_script_and_witness.prove(binding_hash_input).unwrap();
}
