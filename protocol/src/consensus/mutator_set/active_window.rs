use std::ops::Range;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::removal_record::chunk::Chunk;
use super::shared::CHUNK_SIZE;
use super::shared::WINDOW_SIZE;

#[derive(Clone, Debug, Eq, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject)]
pub struct ActiveWindow {
    // It's OK to store this in memory, since it's on the size of kilobytes, not gigabytes.
    pub sbf: Vec<u32>,
}

impl PartialEq for ActiveWindow {
    fn eq(&self, other: &Self) -> bool {
        self.sbf == other.sbf
    }
}

impl Default for ActiveWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveWindow {
    pub fn new() -> Self {
        Self { sbf: Vec::new() }
    }

    /// Grab a slice from the sparse Bloom filter by supplying an
    /// interval. Given how the
    /// sparse Bloom filter is represented (i.e., as a list of
    /// indices), this operation boils down to copying all indices
    /// that live in the range and subtracting the lower bound from
    /// them.
    /// The word "slice" is used in the denotation of submatrices not
    /// rust's contiguous memory structures.
    fn slice(&self, interval: Range<u32>) -> Vec<u32> {
        self.sbf
            .iter()
            .filter(|l| interval.contains(*l))
            .map(|l| *l - interval.start)
            .collect_vec()
    }

    /// Get the chunk of the active window that, upon sliding, becomes
    /// inactive.
    pub fn slid_chunk(&self) -> Chunk {
        Chunk::from_indices(&self.slice(0..CHUNK_SIZE))
    }

    /// Set range to zero.
    fn zerofy(&mut self, lower: u32, upper: u32) {
        // locate
        let mut drops = Vec::new();
        for (location_index, location) in self.sbf.iter().enumerate() {
            if lower <= *location && *location < upper {
                drops.push(location_index);
            }
        }

        // drop
        for d in drops.iter().rev() {
            self.sbf.remove(*d);
        }
    }

    /// Slide the window: drop all integers indexing into the first
    /// chunk, and subtract CHUNK_SIZE from all others.
    pub fn slide_window(&mut self) {
        self.zerofy(0, CHUNK_SIZE);
        for location in &mut self.sbf {
            *location -= CHUNK_SIZE;
        }
    }

    /// Return true iff there is a set integer in the given range.
    fn hasset(&self, lower: u32, upper: u32) -> bool {
        for location in &self.sbf {
            if lower <= *location && *location < upper {
                return true;
            }
        }
        false
    }

    /// Undo a window slide.
    pub fn slide_window_back(&mut self, chunk: &Chunk) {
        assert!(!self.hasset(WINDOW_SIZE - CHUNK_SIZE, WINDOW_SIZE));
        for location in &mut self.sbf {
            *location += CHUNK_SIZE;
        }
        let indices = chunk.to_indices();
        for index in indices {
            self.sbf.push(index);
        }
        self.sbf.sort();
    }

    /// # Panics
    ///
    /// - if the index is not less than window size
    pub fn insert(&mut self, index: u32) {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `insert`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );
        self.sbf.push(index);
        self.sbf.sort();
    }

    pub fn remove(&mut self, index: u32) {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `remove`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );

        // locate last match
        let mut found = false;
        let mut drop_index_index = 0;
        for (index_index, index_value) in self.sbf.iter().enumerate() {
            if *index_value == index {
                found = true;
                drop_index_index = index_index;
            }
        }

        // if found, drop last match
        if found {
            self.sbf.remove(drop_index_index);
        }

        // if not found, the indicated integer is zero
        assert!(found, "Decremented integer is already zero.");
    }

    pub fn contains(&self, index: u32) -> bool {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `contains`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );

        for loc in &self.sbf {
            if *loc == index {
                return true;
            }
        }
        false
    }

    pub fn to_vec_u32(&self) -> Vec<u32> {
        self.sbf.clone()
    }

    pub fn from_vec_u32(vector: Vec<u32>) -> Self {
        Self { sbf: vector }
    }
}
