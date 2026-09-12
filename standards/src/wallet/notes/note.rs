use anyhow::Result;
use anyhow::ensure;
use bech32::FromBase32;
use bech32::ToBase32;
use nyks_consensus::BFieldElement;
use nyks_consensus::network::Network;
use nyks_consensus::transaction::announcement::Announcement;
use nyks_consensus::twenty_first::math::bfield_codec::BFieldCodec;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::wallet::keys::network_hrp_char;
use crate::wallet::notes::bfes_to_bytes_raw;
use crate::wallet::notes::bytes_to_bfes_raw;
use crate::wallet::notes::content::NoteContent;
use crate::wallet::notes::content::NoteContentError;

pub(crate) const TAG_PUBLIC: u64 = 0;
pub(crate) const TAG_PRIVATE: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicNote {
    pub receiver_id: BFieldElement,
    pub content: NoteContent,
}

impl PublicNote {
    pub fn new(receiver_id: BFieldElement, content: NoteContent) -> Self {
        Self {
            receiver_id,
            content,
        }
    }
}

#[derive(Debug, Error)]
pub enum PublicNoteError {
    #[error("public note too short")]
    TooShort,

    #[error("expected public tag, got {0}")]
    WrongTag(u64),

    #[error("failed to decode note content: {0}")]
    Content(#[from] NoteContentError),
}

impl BFieldCodec for PublicNote {
    type Error = PublicNoteError;

    fn encode(&self) -> Vec<BFieldElement> {
        let mut msg = vec![BFieldElement::new(TAG_PUBLIC), self.receiver_id];
        msg.extend(self.content.encode());
        msg
    }

    fn decode(data: &[BFieldElement]) -> Result<Box<Self>, Self::Error> {
        if data.len() < 2 {
            return Err(PublicNoteError::TooShort);
        }

        if data[0].value() != TAG_PUBLIC {
            return Err(PublicNoteError::WrongTag(data[0].value()));
        }

        let content = *NoteContent::decode(&data[2..])?;
        Ok(Box::new(Self { receiver_id: data[1], content }))
    }

    fn static_length() -> Option<usize> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateNote {
    pub receiver_id: BFieldElement,
    pub ciphertext: Vec<BFieldElement>,
}

impl PrivateNote {
    pub fn new(receiver_id: BFieldElement, ciphertext: Vec<BFieldElement>) -> Self {
        Self {
            receiver_id,
            ciphertext,
        }
    }
}

#[derive(Debug, Error)]
pub enum PrivateNoteError {
    #[error("private note too short")]
    TooShort,

    #[error("expected private tag, got {0}")]
    WrongTag(u64),
}

impl BFieldCodec for PrivateNote {
    type Error = PrivateNoteError;

    fn encode(&self) -> Vec<BFieldElement> {
        let mut msg = vec![BFieldElement::new(TAG_PRIVATE), self.receiver_id];
        msg.extend(self.ciphertext.clone());
        msg
    }

    fn decode(data: &[BFieldElement]) -> Result<Box<Self>, Self::Error> {
        if data.len() < 2 {
            return Err(PrivateNoteError::TooShort);
        }

        if data[0].value() != TAG_PRIVATE {
            return Err(PrivateNoteError::WrongTag(data[0].value()));
        }

        Ok(Box::new(Self { receiver_id: data[1], ciphertext: data[2..].to_vec() }))
    }

    fn static_length() -> Option<usize> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Note {
    Public(PublicNote),
    Private(PrivateNote),
}

#[derive(Debug, Error)]
pub enum NoteError {
    #[error("empty note")]
    Empty,

    #[error("unknown note tag: {0}")]
    UnknownTag(u64),

    #[error(transparent)]
    Public(#[from] PublicNoteError),

    #[error(transparent)]
    Private(#[from] PrivateNoteError),
}

impl Note {
    pub fn receiver_id(&self) -> BFieldElement {
        match self {
            Self::Public(p) => p.receiver_id,
            Self::Private(p) => p.receiver_id,
        }
    }

    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public(_))
    }

    pub fn is_private(&self) -> bool {
        matches!(self, Self::Private(_))
    }

    pub fn into_bech32m(self, network: Network) -> String {
        let hrp = Self::hrp(network);
        let bytes = bfes_to_bytes_raw(&self.encode());
        bech32::encode(&hrp, bytes.to_base32(), bech32::Variant::Bech32m)
            .expect("bech32m encoding never fails")
    }

    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(encoded)?;
        ensure!(variant == bech32::Variant::Bech32m, "Only bech32m is supported");
        ensure!(hrp == Self::hrp(network), "Invalid HRP for network");
        let bytes = Vec::<u8>::from_base32(&data)?;
        let msg = bytes_to_bfes_raw(&bytes)?;
        Ok(*Note::decode(&msg)?)
    }

    fn hrp(network: Network) -> String {
        format!("note{}", network_hrp_char(network))
    }
}

impl BFieldCodec for Note {
    type Error = NoteError;

    fn encode(&self) -> Vec<BFieldElement> {
        match self {
            Self::Public(p) => p.encode(),
            Self::Private(p) => p.encode(),
        }
    }

    fn decode(data: &[BFieldElement]) -> Result<Box<Self>, Self::Error> {
        match data.first().ok_or(NoteError::Empty)?.value() {
            TAG_PUBLIC => Ok(Box::new(Self::Public(*PublicNote::decode(data)?))),
            TAG_PRIVATE => Ok(Box::new(Self::Private(*PrivateNote::decode(data)?))),
            other => Err(NoteError::UnknownTag(other)),
        }
    }

    fn static_length() -> Option<usize> {
        None
    }
}

impl From<&Note> for Announcement {
    fn from(note: &Note) -> Self {
        Announcement::new(note.encode())
    }
}

impl TryFrom<&Announcement> for Note {
    type Error = NoteError;
    fn try_from(a: &Announcement) -> Result<Self, Self::Error> {
        Note::decode(&a.message).map(|b| *b)
    }
}

impl From<PublicNote> for Note {
    fn from(n: PublicNote) -> Self {
        Self::Public(n)
    }
}

impl From<PrivateNote> for Note {
    fn from(n: PrivateNote) -> Self {
        Self::Private(n)
    }
}
