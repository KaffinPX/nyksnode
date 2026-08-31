use std::fmt::Debug;

use anyhow::Result;
use anyhow::bail;
use nyks_consensus::BFieldElement;
use nyks_consensus::transaction::utxo::Utxo;
use nyks_consensus::twenty_first::math::bfield_codec::BFieldCodec;
use nyks_consensus::twenty_first::tip5::Digest;
use serde::Deserialize;
use serde::Serialize;

pub trait Content:
    Clone + Debug + PartialEq + Eq + Send + Sync + BFieldCodec + for<'de> Deserialize<'de> + Serialize
{
    /// Unique discriminant used in the note header.
    const DISCRIMINANT: u64;
}

/// Plain message content: an arbitrary list of BFieldElements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BFieldCodec)]
pub struct MessageContent(pub Vec<BFieldElement>);

impl Content for MessageContent {
    const DISCRIMINANT: u64 = 0;
}

/// UTXO notification payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BFieldCodec)]
pub struct UtxoContent {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
}

impl Content for UtxoContent {
    const DISCRIMINANT: u64 = 1;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteContent {
    Message(MessageContent),
    Utxo(UtxoContent),
}

impl NoteContent {
    /// Returns the discriminant of the contained content.
    pub fn discriminant(&self) -> u64 {
        match self {
            Self::Message(_) => MessageContent::DISCRIMINANT,
            Self::Utxo(_) => UtxoContent::DISCRIMINANT,
        }
    }

    /// Encodes the content into a vector of BFieldElements.
    pub fn encode(&self) -> Vec<BFieldElement> {
        match self {
            Self::Message(m) => m.encode(),
            Self::Utxo(u) => u.encode(),
        }
    }

    /// Decodes content from a discriminant and a data slice.
    pub fn decode(disc: u64, data: &[BFieldElement]) -> Result<Self> {
        match disc {
            d if d == MessageContent::DISCRIMINANT => {
                Ok(Self::Message(*MessageContent::decode(data)?))
            }
            d if d == UtxoContent::DISCRIMINANT => Ok(Self::Utxo(*UtxoContent::decode(data)?)),
            _ => bail!("Unknown content discriminant: {disc}"),
        }
    }
}

impl From<MessageContent> for NoteContent {
    fn from(m: MessageContent) -> Self {
        Self::Message(m)
    }
}

impl From<UtxoContent> for NoteContent {
    fn from(u: UtxoContent) -> Self {
        Self::Utxo(u)
    }
}
