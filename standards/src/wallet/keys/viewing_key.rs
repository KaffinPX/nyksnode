use nyks_consensus::BFieldElement;
use nyks_consensus::twenty_first::tip5::Digest;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::wallet::keys::address::Address;
use crate::wallet::keys::key::KeyType;
use crate::wallet::keys::schemes::generation::GenerationViewingKey;
use crate::wallet::keys::schemes::symmetric::SymmetricViewingKey;

pub trait Decryptor {
    type Address;
    type Error;

    // The address viewing key corresponds to.
    fn address(&self) -> Self::Address;

    // Needed to extract indices of an UTXO and see if it is/was part of mutator set.
    fn privacy_preimage(&self) -> Digest;

    fn decrypt(&self, ciphertext: &[BFieldElement]) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug)]
pub enum ViewingKeyError {
    Generation(<GenerationViewingKey as Decryptor>::Error),
    Symmetric(<SymmetricViewingKey as Decryptor>::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum ViewingKey {
    Generation(GenerationViewingKey),
    Symmetric(SymmetricViewingKey),
}

impl Decryptor for ViewingKey {
    type Address = Address;
    type Error = ViewingKeyError;

    fn address(&self) -> Address {
        match self {
            ViewingKey::Generation(k) => k.address().into(),
            ViewingKey::Symmetric(k) => k.address().into(),
        }
    }

    fn privacy_preimage(&self) -> Digest {
        match self {
            ViewingKey::Generation(k) => k.privacy_preimage(),
            ViewingKey::Symmetric(k) => k.privacy_preimage(),
        }
    }

    fn decrypt(&self, ciphertext: &[BFieldElement]) -> Result<Vec<u8>, Self::Error> {
        match self {
            ViewingKey::Generation(k) => k.decrypt(ciphertext).map_err(ViewingKeyError::Generation),
            ViewingKey::Symmetric(k) => k.decrypt(ciphertext).map_err(ViewingKeyError::Symmetric),
        }
    }
}

impl From<&ViewingKey> for KeyType {
    fn from(key: &ViewingKey) -> Self {
        match key {
            ViewingKey::Generation(_) => KeyType::Generation,
            ViewingKey::Symmetric(_) => KeyType::Symmetric,
        }
    }
}

impl From<GenerationViewingKey> for ViewingKey {
    fn from(key: GenerationViewingKey) -> Self {
        ViewingKey::Generation(key)
    }
}

impl From<SymmetricViewingKey> for ViewingKey {
    fn from(key: SymmetricViewingKey) -> Self {
        ViewingKey::Symmetric(key)
    }
}
