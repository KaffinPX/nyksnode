use nyks_consensus::BFieldElement;
use nyks_consensus::network::Network;
use nyks_consensus::tasm_lib::prelude::Digest;
use nyks_consensus::transaction::lock_script::LockScript;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::wallet::keys::schemes::generation::GenerationAddress;
use crate::wallet::keys::schemes::symmetric::SymmetricAddress;
use crate::wallet::notes::content::NoteContent;
use crate::wallet::notes::note::Note;

#[derive(Debug, Error)]
pub enum Bech32mDecodeError {
    #[error("Failed to decode bech32 string")]
    DecodeError(#[from] bech32::Error),

    #[error("Invalid variant: expected Bech32m")]
    InvalidVariant,

    #[error("Invalid HRP prefix")]
    InvalidHrp,

    #[error("Deserialization error: {0}")]
    DeserializeError(#[from] bincode::Error),
}

pub trait Recipient: Sync {
    /// Decodes an address from a bech32m string.
    fn from_bech32m(address: &str, network: Network) -> Result<Self, Bech32mDecodeError>
    where
        Self: Sized;

    /// Encodes the address as a bech32m string.
    fn to_bech32m(&self, network: Network) -> String;

    /// Returns the type flag associated with this address.
    ///
    /// This is embedded in announcements to allow receivers to quickly filter
    /// relevant messages.
    fn flag(&self) -> BFieldElement;

    /// Returns a public fingerprint used to identify whether an encrypted
    /// payload is intended for this receiver.
    fn receiver_identifier(&self) -> BFieldElement;

    /// Used when building UTXO commitment to avoid linkability by sender.
    fn privacy_digest(&self) -> Digest;

    /// Returns the spending lock associated with this address.
    ///
    /// Satisfaction of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    fn lock_script(&self) -> LockScript;

    /// TODO: comment
    fn create_private_note(&self, content: &NoteContent) -> Note;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Address {
    Generation(GenerationAddress),
    Symmetric(SymmetricAddress),
}

impl Recipient for Address {
    fn from_bech32m(address: &str, network: Network) -> Result<Self, Bech32mDecodeError> {
        if let Ok(addr) = GenerationAddress::from_bech32m(address, network) {
            return Ok(Address::Generation(addr));
        }

        let addr = SymmetricAddress::from_bech32m(address, network)?;
        Ok(Address::Symmetric(addr))
    }

    fn to_bech32m(&self, network: Network) -> String {
        match self {
            Address::Generation(a) => a.to_bech32m(network),
            Address::Symmetric(a) => a.to_bech32m(network),
        }
    }

    fn flag(&self) -> BFieldElement {
        match self {
            Address::Generation(a) => a.flag(),
            Address::Symmetric(a) => a.flag(),
        }
    }

    fn receiver_identifier(&self) -> BFieldElement {
        match self {
            Address::Generation(a) => a.receiver_identifier(),
            Address::Symmetric(a) => a.receiver_identifier(),
        }
    }

    fn privacy_digest(&self) -> Digest {
        match self {
            Address::Generation(a) => a.privacy_digest(),
            Address::Symmetric(a) => a.privacy_digest(),
        }
    }

    fn lock_script(&self) -> LockScript {
        match self {
            Address::Generation(a) => a.lock_script(),
            Address::Symmetric(a) => a.lock_script(),
        }
    }

    fn create_private_note(&self, content: &NoteContent) -> Note {
        match self {
            Address::Generation(a) => a.create_private_note(content),
            Address::Symmetric(a) => a.create_private_note(content),
        }
    }
}

impl From<GenerationAddress> for Address {
    fn from(addr: GenerationAddress) -> Self {
        Address::Generation(addr)
    }
}

impl From<SymmetricAddress> for Address {
    fn from(addr: SymmetricAddress) -> Self {
        Address::Symmetric(addr)
    }
}
