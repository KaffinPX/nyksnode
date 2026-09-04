use std::fmt::Debug;

use nyks_consensus::BFieldElement;
use nyks_consensus::transaction::utxo::Utxo;
use nyks_consensus::twenty_first::math::bfield_codec::BFieldCodec;
use nyks_consensus::twenty_first::tip5::Digest;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

pub trait Content:
    Clone + Debug + PartialEq + Eq + Send + Sync + BFieldCodec + for<'de> Deserialize<'de> + Serialize
{
    /// Unique discriminant used in the note header.
    const DISCRIMINANT: u64;
}

/// Errors that can occur when working with [`NoteContent`].
#[derive(Debug, Error)]
pub enum NoteContentError {
    #[error("unknown content discriminant: {0}")]
    UnknownDiscriminant(u64),

    // Boxed because each Content impl has its own BFieldCodec::Error type.
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
    pub fn new(utxo: Utxo, sender_randomness: Digest) -> Self {
        Self {
            utxo,
            sender_randomness,
        }
    }
}

impl Content for UtxoContent {
    const DISCRIMINANT: u64 = 0;
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

    /// Encodes the content into a vector of BFieldElements.
    pub fn encode(&self) -> Vec<BFieldElement> {
        match self {
            Self::Utxo(u) => u.encode(),
        }
    }

    /// Decodes content from a discriminant and a data slice.
    pub fn decode(disc: u64, data: &[BFieldElement]) -> Result<Self, NoteContentError> {
        match disc {
            d if d == UtxoContent::DISCRIMINANT => {
                let content =
                    UtxoContent::decode(data).map_err(|e| NoteContentError::Decode(e.into()))?;
                Ok(Self::Utxo(*content))
            }
            _ => Err(NoteContentError::UnknownDiscriminant(disc)),
        }
    }
}

impl From<UtxoContent> for NoteContent {
    fn from(u: UtxoContent) -> Self {
        Self::Utxo(u)
    }
}
