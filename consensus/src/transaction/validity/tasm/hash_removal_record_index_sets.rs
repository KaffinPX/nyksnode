use tasm_lib::data_type::DataType;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::list::higher_order::inner_function::InnerFunction;
use tasm_lib::list::higher_order::inner_function::RawCode;
use tasm_lib::list::higher_order::map::ChainMap;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::mutator_set::removal_record::RemovalRecord;

/// Hash the absolute index sets of `NUM_INPUT_LISTS` lists of [`RemovalRecord`]s,
/// putting all resulting digests in one list, which is returned.
#[derive(Clone, Copy, Debug)]
pub struct HashRemovalRecordIndexSets<const NUM_INPUT_LISTS: usize>;

impl<const NUM_INPUT_LISTS: usize> HashRemovalRecordIndexSets<NUM_INPUT_LISTS> {
    pub const OUT_OF_ELEMENT_POINTER_ERROR_ID: i128 = 1_000_250;
}

impl<const NUM_INPUT_LISTS: usize> BasicSnippet for HashRemovalRecordIndexSets<NUM_INPUT_LISTS> {
    fn parameters(&self) -> Vec<(DataType, String)> {
        // Type of all "inputs" argument is Vec<RemovalRecord>
        vec![(DataType::VoidPointer, "rr_list".to_owned()); NUM_INPUT_LISTS]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        let list_of_digests = DataType::List(Box::new(DataType::Digest));
        vec![(list_of_digests, "list_of_digests".to_string())]
    }

    fn entrypoint(&self) -> String {
        format!("neptune_transaction_hash_removal_record_index_sets_{NUM_INPUT_LISTS}")
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let hash_varlen = library.import(Box::new(HashVarlen));

        let hash_one_index_set = triton_asm! {
            // BEFORE: _ *removal_record rr_len
            // AFTER:  _ [index_set_digest: Digest]
            hash_one_index_set:
                dup 1
                {&field_with_size!(RemovalRecord::absolute_indices)}
                            // _ *removal_record rr_len *ai ai_len

                /* check that *ai points into this removal record */
                pick 2      // _ *removal_record *ai ai_len rr_len
                dup 2       // _ *removal_record *ai ai_len rr_len *ai
                pick 4      // _ *ai ai_len rr_len *ai *removal_record
                push -1
                mul
                add         // _ *ai ai_len rr_len (*ai-*removal_record)
                lt          // _ *ai ai_len (*ai-*removal_record < rr_len)
                assert error_id {Self::OUT_OF_ELEMENT_POINTER_ERROR_ID}
                            // _ *ai ai_len

                call {hash_varlen}
                return
        };
        let map = library.import(Box::new(ChainMap::<NUM_INPUT_LISTS>::new(
            InnerFunction::RawCode(RawCode::new(
                hash_one_index_set,
                DataType::Tuple(vec![DataType::VoidPointer, DataType::Bfe]),
                DataType::Digest,
            )),
        )));

        triton_asm! {
            // BEFORE: _ [*rrs; N]
            // AFTER:  _ *digests
            {self.entrypoint()}: call {map} return
        }
    }
}
