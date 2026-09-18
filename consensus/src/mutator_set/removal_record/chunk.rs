use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use thiserror::Error;

use super::super::shared::CHUNK_SIZE;

/// *Hard* max on the number of `u32` elements in a packed [`Chunk`].
///
/// 256 batches can touch a chunk. Each batch has 8 UTXOs. And the removal of
/// each UTXO sets 45 indices. So a maximum of 92,160 elements can
/// (with a Tip5 preimage attack) be set in a chunk.
///
/// (256 * 8 * 45 + 2) * 12 / 32 = 34561 (rounded up)
///  |     |   |    |    |    '---- u32 width
///  |     |   |    |    '--------- width of packed element and length indicator
///  |     |   |    '-------------- two u12 values for the length indicator
///  |     |   '------------------- num set indices per removed element
///  |     '----------------------- UTXOs per batch
///  '----------------------------- num batches that can touch one specific chunk
const MAX_PACKED_LENGTH: usize = 34561;
const MAX_UNPACKED_LENGTH: usize = 92160;

/// The 12th bit of the first `u12` of a packed [`Chunk`]. It is set iff the
/// next `u12` is also part of the length indicator. See [`Chunk::pack`].
const LONG_LENGTH_FLAG: u32 = 1 << 11;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum ChunkUnpackError {
    #[error(
        "payload is too large -- packed chunk can never be more than {MAX_PACKED_LENGTH} u32s"
    )]
    PayloadTooBig,

    #[error("actual length is inconsistent relative to length indicator")]
    InconsistentLength,

    #[error("remainder bits were not zero")]
    NonzeroTrailingPadding,

    #[error("the empty chunk packs to the empty list, not to a zero length indicator")]
    NonCanonicalEmptyChunk,

    #[error(
        "length indicator uses the long form for a length below {LONG_LENGTH_FLAG}, which fits \
         the short form"
    )]
    NonMinimalLengthIndicator,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject)]
pub struct Chunk {
    pub relative_indices: Vec<u32>,
}

impl Chunk {
    pub fn empty_chunk() -> Self {
        Chunk {
            relative_indices: vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.relative_indices.is_empty()
    }

    pub fn insert(&mut self, index: u32) {
        assert!(
            index < CHUNK_SIZE,
            "index cannot exceed chunk size in `insert`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );
        self.relative_indices.push(index);
        self.relative_indices.sort();
    }

    /// Insert a batch of indices. Equivalent to calling [`Self::insert`] for
    /// each of them, but sorts only once.
    pub fn insert_many(&mut self, indices: &[u32]) {
        for index in indices {
            assert!(
                *index < CHUNK_SIZE,
                "index cannot exceed chunk size in `insert`. CHUNK_SIZE = {}, got index = {}",
                CHUNK_SIZE,
                index
            );
        }
        self.relative_indices.extend_from_slice(indices);
        self.relative_indices.sort();
    }

    pub fn remove_once(&mut self, index: u32) {
        assert!(
            index < CHUNK_SIZE,
            "index cannot exceed chunk size in `remove`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );
        let mut drop = None;
        for i in 0..self.relative_indices.len() {
            if self.relative_indices[i] == index {
                drop = Some(i);
            }
        }

        if let Some(d) = drop {
            self.relative_indices.remove(d);
        }
    }

    pub fn contains(&self, index: u32) -> bool {
        assert!(
            index < CHUNK_SIZE,
            "index cannot exceed chunk size in `contains`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );

        self.relative_indices.contains(&index)
    }

    /// Return a chunk with indices which are the concatenation and sorting of indices in two input chunks
    pub fn combine(self, other: Self) -> Self {
        let mut ret = Self::empty_chunk();
        for idx in self.relative_indices {
            ret.relative_indices.push(idx);
        }
        for idx in other.relative_indices {
            ret.relative_indices.push(idx);
        }
        ret.relative_indices.sort();
        ret
    }

    /// Remove the indices in a chunk from a chunk.
    ///
    /// /// # Panics
    ///
    /// - If one of the subtracted indices are not present in the chunk.
    pub fn subtract(&mut self, other: Self) {
        for remove_index in other.relative_indices {
            // Find the 1st match and remove that
            match self
                .relative_indices
                .iter()
                .find_position(|x| **x == remove_index)
            {
                Some((i, _)) => self.relative_indices.remove(i),
                None => panic!("Attempted to remove index that was not present in chunk."),
            };
        }
    }

    pub fn to_indices(&self) -> Vec<u32> {
        self.relative_indices.clone()
    }

    pub fn from_indices(relative_indices: &[u32]) -> Self {
        Chunk {
            relative_indices: relative_indices.to_vec(),
        }
    }

    pub fn from_slice(sl: &[u32]) -> Chunk {
        Chunk {
            relative_indices: sl.to_vec(),
        }
    }

    /// Compresses a [`Chunk`] by encoding:
    ///  - the length of the vector of relative indices as a length indicator of
    ///    either one or two u12 elements, see below,
    ///  - every element as a u12,
    ///  - the resulting bitvec as `Vec<u32>`.
    ///
    /// The length indicator spends one u12 for lengths below 2^11, storing the
    /// length verbatim. Chunks with more indices than this, set the 12th bit of
    /// the first u12 as a flag, and the next u12 is then also part of the
    /// length indicator:
    ///
    /// Lengths 2^11 and above are encoded as:
    ///
    /// ```notest
    ///  <--- u12 ---> <--- u12 --->
    /// ┌─┬───────────┬─────────────┐
    /// │1│ length hi │  length lo  │
    /// └─┴───────────┴─────────────┘
    ///  '--- flag
    /// ```
    ///
    /// That leaves 11 + 12 = 23 bits for the length, which is much more than
    /// [`MAX_UNPACKED_LENGTH`].
    pub(crate) fn pack(&self) -> Chunk {
        if self.relative_indices.is_empty() {
            return Self {
                relative_indices: vec![],
            };
        }

        // assert that we haven't already packed. I.e. that high bits are zero.
        assert!(self.relative_indices.iter().all(|x| *x < CHUNK_SIZE));

        assert!(
            self.relative_indices.len() <= MAX_UNPACKED_LENGTH,
            "Unpacked length of a chunk may not exceed {MAX_UNPACKED_LENGTH}"
        );

        let num_elements = self.relative_indices.len() as u32;
        let length_encoding = if num_elements < LONG_LENGTH_FLAG {
            vec![num_elements]
        } else {
            let length_hi = (num_elements >> 12) | LONG_LENGTH_FLAG;
            let length_lo = num_elements & ((1 << 12) - 1);
            vec![length_hi, length_lo]
        };

        self.pack_with_length_encoding(&length_encoding)
    }

    /// The bit-packing half of [`Self::pack`], with the length indicator
    /// supplied by the caller.
    fn pack_with_length_encoding(&self, length_encoding: &[u32]) -> Chunk {
        let mut packed = vec![];
        let mut width = 0_usize;
        let mut current = 0_u64;

        for &element in length_encoding.iter().chain(&self.relative_indices) {
            width += 12;
            current = (current << 12) | u64::from(element);

            if width >= 32 {
                let remainder = width % 32;
                packed.push(
                    u32::try_from(current >> remainder)
                        .expect("width of `current` should always be less than 44"),
                );
                width -= 32;
                current &= (1 << remainder) - 1;
            }
        }

        if width != 0 {
            packed.push(
                u32::try_from(current << (32 - width))
                    .expect("width of `current` should be less than 32 here"),
            );
        }

        Self {
            relative_indices: packed,
        }
    }

    /// Inverse of [`Self::pack`].
    pub(crate) fn try_unpack(&self) -> Result<Self, ChunkUnpackError> {
        if self.relative_indices.is_empty() {
            return Ok(Self {
                relative_indices: vec![],
            });
        }

        if self.relative_indices.len() > MAX_PACKED_LENGTH {
            return Err(ChunkUnpackError::PayloadTooBig);
        }

        let mut unpacked = vec![];

        let mut current = 0_u64;
        let mut width = 0_usize;

        // The first u12 is the length, unless its 12th bit is set, in which
        // case the length spans the first two u12s. See [`Self::pack`].
        let first_length_element = (self.relative_indices[0] >> 20) & ((1 << 12) - 1);
        let (indicated_length, num_length_elements) = if first_length_element < LONG_LENGTH_FLAG {
            (first_length_element, 1)
        } else {
            let length_hi = first_length_element & (LONG_LENGTH_FLAG - 1);
            let length_lo = (self.relative_indices[0] >> 8) & ((1 << 12) - 1);
            ((length_hi << 12) | length_lo, 2)
        };

        // The length indicator must be the one `pack` would have produced.
        if indicated_length == 0 {
            return Err(ChunkUnpackError::NonCanonicalEmptyChunk);
        }
        if num_length_elements == 2 && indicated_length < LONG_LENGTH_FLAG {
            return Err(ChunkUnpackError::NonMinimalLengthIndicator);
        }

        #[expect(clippy::manual_div_ceil, reason = "approach tasm implementation")]
        let indicated_packed_length = ((indicated_length + num_length_elements) * 12 + 31) / 32;
        if indicated_packed_length != u32::try_from(self.relative_indices.len()).unwrap() {
            return Err(ChunkUnpackError::InconsistentLength);
        }

        let mut remaining_elements = indicated_length + num_length_elements;
        // Invariant: number of elements left to iterate over is
        // N == (remaining_elements * 12 - width + 31) / 32.
        //
        // Loop invariant before:
        // N == self.relative_indices.len()
        //   == indicated_packed_length
        //               (as per above if-statement)
        //   == ((indicated_length + num_length_elements) * 12 + 31) / 32
        //               (by assignment above that)
        //   == (remaining_elements * 12 + 31) / 32
        //               (by assignment to remaining_elements)
        //   == (remaining_elements * 12 - width + 31) / 32
        //               (since width == 0).
        for &element in &self.relative_indices {
            current = (current << 32) | u64::from(element);
            width += 32;

            // At this point, width is guaranteed to be in [32;44). In every
            // iteration of the next loop, 12 is subtracted. Therefore, the next
            // loop can run for either 2 or 3 iterations -- tertium non datur.
            while width >= 12 && remaining_elements != 0 {
                let denominator = width / 12;
                let remainder = width % 12;
                let mask = (1 << 12) - 1;
                unpacked.push(
                    u32::try_from((current >> (remainder + (denominator - 1) * 12)) & mask)
                        .expect("complicated invariant not satisfied"),
                );
                remaining_elements -= 1;
                let mask = mask << (remainder + (denominator - 1) * 12);
                let mask = !mask;
                current &= mask;
                width -= 12;
            }

            // Loop invariant at end of iteration: new number of elements left
            // to iterate over N* = N - 1. Distinguish two cases.
            //
            //  1. Inner while-loop ran for 2 iterations.
            //     width in [0;4) and width* = width + 8 (mod 12)
            //                               = width + 8
            //     remaining_elements* == remaining_elements - 2
            //     N   == (remaining_elements * 12 + width + 31) / 32.
            //     N* + 1 == ((remaining_elements* + 2) * 12 - (width* - 8) + 31) / 32
            //     N* = (remaining_elements* * 12 + 24 - width* + 8 + 31 - 32) / 32
            //        = (remaining_elements* * 12 - width + 31) / 32.
            //
            //  2. Inner while-loop ran for 3 iterations.
            //     Then width is in [4;12) and width* = width + 8 (mod 12)
            //                                        = width - 4
            //     remaining_elements* == remaining_elements - 3
            //     N   == (remaining_elements * 12 + width + 31) / 32.
            //     N* + 1 == ((remaining_elements* + 3) * 12 - (width* + 4) + 31) / 32
            //     N* = (remaining_elements* * 12 + 36 - width* -4 + 31 - 32) / 32
            //        = (remaining_elements* * 12 - width + 31) / 32.
            //
            // So the invariant is restored.
        }

        // Loop invariant afterwards:
        // N == 0
        //   == (remaining_elements * 12 - width + 31) / 32, so
        //   remaining_elements * 12 - width + 31 < 32
        //   remaining_elements * 12 - width < 1
        // From width in [0;12) it follows that remaining_elements == 0.
        // So it is not necessary check that remaining_elements == 0.

        let total_bit_length = (indicated_length + num_length_elements) * 12;
        let num_non_padding_bits_in_last_element = total_bit_length % 32;
        let tail_length = if num_non_padding_bits_in_last_element != 0 {
            32 - num_non_padding_bits_in_last_element
        } else {
            0
        };
        let mask = (1 << tail_length) - 1;

        if *self.relative_indices.last().unwrap() & mask != 0 {
            return Err(ChunkUnpackError::NonzeroTrailingPadding);
        }

        Ok(Self {
            relative_indices: unpacked[num_length_elements as usize..].to_vec(),
        })
    }
}
