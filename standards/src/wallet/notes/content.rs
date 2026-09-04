use std::fmt::Debug;

use nyks_consensus::BFieldElement;
use nyks_consensus::transaction::utxo::Utxo;
use nyks_consensus::twenty_first::math::bfield_codec::BFieldCodec;
use nyks_consensus::twenty_first::tip5::Digest;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

/// Errors that can occur when working with [`NoteContent`].
#[derive(Debug, Error)]
pub enum NoteContentError {
    #[error("empty sequence: expected at least a discriminant element")]
    EmptySequence,

    #[error("unknown content discriminant: {0}")]
    UnknownDiscriminant(u64),

    // Boxed because each content type has its own BFieldCodec::Error type.
    // One Decode variant can then handle all of them.
    #[error("failed to decode content: {0}")]
    Decode(Box<dyn std::error::Error + Send + Sync>),
}

/// UTXO notification payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BFieldCodec)]
pub struct UtxoContent {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
}

impl UtxoContent {
    pub const DISCRIMINANT: u64 = 0;

    pub fn new(utxo: Utxo, sender_randomness: Digest) -> Self {
        Self {
            utxo,
            sender_randomness,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteContent {
    Utxo(UtxoContent),
}

impl NoteContent {
    /// Returns the discriminant of the contained content.
    pub fn discriminant(&self) -> u64 {
        match self {
            Self::Utxo(_) => UtxoContent::DISCRIMINANT,
        }
    }
}

impl From<UtxoContent> for NoteContent {
    fn from(u: UtxoContent) -> Self {
        Self::Utxo(u)
    }
}

impl BFieldCodec for NoteContent {
    type Error = NoteContentError;

    fn encode(&self) -> Vec<BFieldElement> {
        let (discriminant, mut payload) = match self {
            Self::Utxo(u) => (UtxoContent::DISCRIMINANT, u.encode()),
        };

        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(BFieldElement::new(discriminant));
        out.append(&mut payload);
        out
    }

    fn decode(sequence: &[BFieldElement]) -> Result<Box<Self>, Self::Error> {
        let (disc_elem, rest) = sequence
            .split_first()
            .ok_or(NoteContentError::EmptySequence)?;
        let discriminant = disc_elem.value();

        match discriminant {
            d if d == UtxoContent::DISCRIMINANT => {
                let content = UtxoContent::decode(rest)
                    .map_err(|e| NoteContentError::Decode(e.into()))?;
                Ok(Box::new(Self::Utxo(*content)))
            }
            _ => Err(NoteContentError::UnknownDiscriminant(discriminant)),
        }
    }

    fn static_length() -> Option<usize> {
        // Variable-length: total size depends on which variant is encoded.
        None
    }
}
