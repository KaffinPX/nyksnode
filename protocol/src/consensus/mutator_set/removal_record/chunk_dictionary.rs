use std::slice::Iter;
use std::slice::IterMut;
use std::vec::IntoIter;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use triton_vm::prelude::Digest;

use super::chunk::Chunk;
use crate::prelude::triton_vm;

type AuthenticatedChunk = (MmrMembershipProof, Chunk);
type ChunkIndex = u64;

#[derive(
    Clone, Debug, Serialize, Deserialize, GetSize, PartialEq, Eq, Default, BFieldCodec, TasmObject,
)]

pub struct ChunkDictionary {
    /// {chunk index => (MMR membership proof for the whole chunk to which index belongs, chunk value)}
    /// This list is always sorted. It has max. NUM_TRIALS=45 elements, so we
    /// don't care about the cost of reallocation when `insert`ing or
    /// `remove`ing.
    pub dictionary: Vec<(u64, (MmrMembershipProof, Chunk))>,
}

impl ChunkDictionary {
    pub fn empty() -> Self {
        Self {
            dictionary: Vec::new(),
        }
    }

    pub fn new(mut dictionary: Vec<(ChunkIndex, AuthenticatedChunk)>) -> Self {
        dictionary.sort_by_key(|(k, _v)| *k);
        Self { dictionary }
    }

    pub fn indices_and_leafs(&self) -> Vec<(ChunkIndex, Digest)> {
        self.dictionary
            .iter()
            .map(|(k, (_mp, ch))| (*k, Tip5::hash(ch)))
            .collect_vec()
    }

    pub fn indices_and_chunks(&self) -> Vec<(ChunkIndex, Chunk)> {
        self.dictionary
            .iter()
            .map(|(k, (_mp, ch))| (*k, ch.clone()))
            .collect_vec()
    }

    pub fn chunk_indices_and_membership_proofs_and_leafs(
        &self,
    ) -> Vec<(u64, MmrMembershipProof, Digest)> {
        self.dictionary
            .iter()
            .map(|(k, (mp, ch))| (*k, mp.clone(), Tip5::hash(ch)))
            .collect_vec()
    }

    pub fn chunk_indices_and_membership_proofs_and_leafs_iter_mut(
        &mut self,
    ) -> std::slice::IterMut<'_, (u64, (MmrMembershipProof, Chunk))> {
        self.dictionary.iter_mut()
    }

    pub fn authentication_paths(&self) -> Vec<MmrMembershipProof> {
        self.dictionary
            .iter()
            .map(|(_, (mp, _))| mp.to_owned())
            .collect()
    }

    pub fn all_chunk_indices(&self) -> Vec<ChunkIndex> {
        self.dictionary.iter().map(|(ci, _)| *ci).collect_vec()
    }

    pub fn contains_key(&self, key: &ChunkIndex) -> bool {
        self.dictionary
            .iter()
            .any(|(chunk_index, _)| *chunk_index == *key)
    }

    pub fn get(&self, key: &ChunkIndex) -> Option<&AuthenticatedChunk> {
        self.dictionary
            .iter()
            .find(|(chunk_index, _)| *chunk_index == *key)
            .map(|(_, value)| value)
    }

    pub fn all<F: FnMut(&(ChunkIndex, AuthenticatedChunk)) -> bool>(&self, f: F) -> bool {
        self.dictionary.iter().all(f)
    }

    pub fn is_empty(&self) -> bool {
        self.dictionary.is_empty()
    }

    pub fn iter(&self) -> Iter<'_, (ChunkIndex, AuthenticatedChunk)> {
        self.dictionary.iter()
    }

    pub fn len(&self) -> usize {
        self.dictionary.len()
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, (ChunkIndex, AuthenticatedChunk)> {
        self.dictionary.iter_mut()
    }

    pub fn insert(
        &mut self,
        index: ChunkIndex,
        value: AuthenticatedChunk,
    ) -> Option<AuthenticatedChunk> {
        if let Some((_found_chunk_index, found_authenticated_chunk)) =
            self.dictionary.iter_mut().find(|(k, _v)| *k == index)
        {
            let old_chunk = found_authenticated_chunk.clone();
            *found_authenticated_chunk = value;
            Some(old_chunk)
        } else {
            let insertion_index = self.dictionary.iter().filter(|(k, _v)| *k < index).count();
            self.dictionary.insert(insertion_index, (index, value));
            None
        }
    }

    pub fn get_mut(&mut self, index: &ChunkIndex) -> Option<&mut AuthenticatedChunk> {
        self.dictionary
            .iter_mut()
            .find(|(k, _v)| *k == *index)
            .map(|(_k, v)| v)
    }

    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&(ChunkIndex, AuthenticatedChunk)) -> bool,
    {
        self.dictionary.retain(f)
    }

    pub fn remove(&mut self, index: &ChunkIndex) -> Option<AuthenticatedChunk> {
        let maybe_position = self
            .dictionary
            .iter()
            .enumerate()
            .find(|(_i, (k, _v))| *k == *index)
            .map(|(i, _)| i);
        if let Some(definite_position) = maybe_position {
            let (_chunk_index, authenticated_chunk) = self.dictionary.remove(definite_position);
            Some(authenticated_chunk)
        } else {
            None
        }
    }
}

impl IntoIterator for ChunkDictionary {
    type Item = (ChunkIndex, AuthenticatedChunk);

    type IntoIter = IntoIter<(ChunkIndex, AuthenticatedChunk)>;

    fn into_iter(self) -> Self::IntoIter {
        self.dictionary.into_iter()
    }
}
