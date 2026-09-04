use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use bech32::FromBase32;
use bech32::ToBase32;
use nyks_consensus::BFieldElement;
use nyks_consensus::network::Network;
use nyks_consensus::transaction::announcement::Announcement;
use serde::Deserialize;
use serde::Serialize;

use crate::wallet::keys::network_hrp_char;
use crate::wallet::notes::content::NoteContent;

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

    pub fn into_message(self) -> Vec<BFieldElement> {
        let mut msg = vec![
            BFieldElement::new(TAG_PUBLIC),
            self.receiver_id,
            BFieldElement::new(self.content.discriminant()),
        ];
        msg.extend(self.content.encode());
        msg
    }

    pub fn from_message(data: &[BFieldElement]) -> Result<Self> {
        if data.len() < 3 {
            bail!("Public note too short");
        }
        if data[0].value() != TAG_PUBLIC {
            bail!("Expected public tag, got {}", data[0].value());
        }
        let receiver_id = data[1];
        let disc = data[2].value();
        let content = NoteContent::decode(disc, &data[3..])?;
        Ok(Self {
            receiver_id,
            content,
        })
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

    pub fn into_message(self) -> Vec<BFieldElement> {
        let mut msg = vec![BFieldElement::new(TAG_PRIVATE), self.receiver_id];
        msg.extend(self.ciphertext);
        msg
    }

    pub fn from_message(data: &[BFieldElement]) -> Result<Self> {
        if data.len() < 2 {
            bail!("Private note too short");
        }
        if data[0].value() != TAG_PRIVATE {
            bail!("Expected private tag, got {}", data[0].value());
        }
        let receiver_id = data[1];
        let ciphertext = data[2..].to_vec();
        Ok(Self {
            receiver_id,
            ciphertext,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Note {
    Public(PublicNote),
    Private(PrivateNote),
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

    pub fn into_announcement(self) -> Announcement {
        let msg = match self {
            Self::Public(p) => p.into_message(),
            Self::Private(p) => p.into_message(),
        };
        Announcement::new(msg)
    }

    pub fn try_from_announcement(ann: &Announcement) -> Result<Self> {
        let msg = &ann.message;
        if msg.is_empty() {
            bail!("Empty announcement");
        }
        match msg[0].value() {
            TAG_PUBLIC => Ok(Self::Public(PublicNote::from_message(msg)?)),
            TAG_PRIVATE => Ok(Self::Private(PrivateNote::from_message(msg)?)),
            other => bail!("Unknown tag: {other}"),
        }
    }

    pub fn into_bech32m(self, network: Network) -> String {
        let hrp = Self::hrp(network);
        let msg = self.into_announcement().message;
        let payload =
            bincode::serialize(&msg).expect("BFieldElement vec serialization never fails");
        let payload_base32 = payload.to_base32();
        bech32::encode(&hrp, payload_base32, bech32::Variant::Bech32m)
            .expect("bech32m encoding never fails")
    }

    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(encoded)?;
        ensure!(
            variant == bech32::Variant::Bech32m,
            "Only bech32m is supported"
        );
        ensure!(hrp == Self::hrp(network), "Invalid HRP for network");
        let payload = Vec::<u8>::from_base32(&data)?;
        let msg: Vec<BFieldElement> = bincode::deserialize(&payload)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize bech32 payload: {e}"))?;
        let ann = Announcement::new(msg);
        Self::try_from_announcement(&ann)
    }

    fn hrp(network: Network) -> String {
        format!("note{}", network_hrp_char(network))
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
