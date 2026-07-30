use nyks_consensus::BFieldElement;
use nyks_consensus::tasm_lib::prelude::Digest;
use nyks_consensus::transaction::announcement::Announcement;
use nyks_consensus::transaction::lock_script::LockScriptAndWitness;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::wallet::keys::address::Address;
use crate::wallet::keys::address::Recipient;
use crate::wallet::keys::schemes::generation::GENERATION_FLAG_U8;
use crate::wallet::keys::schemes::generation::GenerationKey;
use crate::wallet::keys::schemes::symmetric::SYMMETRIC_FLAG_U8;
use crate::wallet::keys::schemes::symmetric::SymmetricKey;
use crate::wallet::keys::viewing_key::Decryptor;
use crate::wallet::keys::viewing_key::ViewingKey;

/// A spending-capable cryptographic identity in the Nyks.
///
/// This trait abstracts over different key constructions (e.g. generation-based
/// lattice keys or symmetric keys) that can:
///
/// - derive a corresponding receiving address
/// - identify incoming UTXOs via a receiver identifier
/// - decrypt encrypted UTXO payloads
/// - provide ownership proofs via privacy preimages
///
/// ## Architectural note
///
/// This trait deliberately separates *cryptographic responsibilities*
/// from *wallet-level logic* (such as scanning transactions or parsing
/// blockchain state).
///
/// Methods in this trait should remain purely key-centric and must not
/// depend on transaction structures or network scanning logic.
pub trait Spender: Sync {
    type Addr: Recipient;
    type ViewKey: Decryptor;

    /// Returns the receiving address corresponding to this spending key.
    fn to_address(&self) -> Self::Addr;

    /// Returns the corresponding viewing key corresponding to this spending key and its address.
    fn to_viewing_key(&self) -> Self::ViewKey;

    /// Returns the lock script hash.
    fn lock_script_hash(&self) -> Digest {
        self.lock_script_and_witness().program.hash()
    }

    /// Returns the lock script and witness required to satisfy spending
    /// conditions associated with this key.
    fn lock_script_and_witness(&self) -> LockScriptAndWitness;

    /// Returns the privacy preimage associated with this key.
    ///
    /// The hash of this value is stored in the receiving address as
    /// `privacy_digest`. This has to be known for discovering UTXOs.
    fn privacy_preimage(&self) -> Digest;

    /// Returns the unlock key associated with this key.
    ///
    /// The hash of this value is embedded in the locking script of UTXOs
    /// created for the corresponding address. To spend such a UTXO, the
    /// spender must reveal this value and thereby prove knowledge of a
    /// preimage whose hash matches the committed value.
    fn unlock_key(&self) -> Digest;
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum Key {
    Generation(GenerationKey),
    Symmetric(SymmetricKey),
}

impl Spender for Key {
    type Addr = Address;
    type ViewKey = ViewingKey;

    fn to_address(&self) -> Self::Addr {
        match self {
            Key::Generation(k) => k.to_address().into(),
            Key::Symmetric(k) => k.to_address().into(),
        }
    }

    fn to_viewing_key(&self) -> Self::ViewKey {
        match self {
            Key::Generation(k) => k.to_viewing_key().into(),
            Key::Symmetric(k) => k.to_viewing_key().into(),
        }
    }

    fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        match self {
            Key::Generation(k) => k.lock_script_and_witness(),
            Key::Symmetric(k) => k.lock_script_and_witness(),
        }
    }

    fn privacy_preimage(&self) -> Digest {
        match self {
            Key::Generation(k) => k.privacy_preimage(),
            Key::Symmetric(k) => k.privacy_preimage(),
        }
    }

    fn unlock_key(&self) -> Digest {
        match self {
            Key::Generation(k) => k.unlock_key(),
            Key::Symmetric(k) => k.unlock_key(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyType {
    Generation = GENERATION_FLAG_U8,
    Symmetric = SYMMETRIC_FLAG_U8,
}

impl From<&Key> for KeyType {
    fn from(key: &Key) -> Self {
        match key {
            Key::Generation(_) => KeyType::Generation,
            Key::Symmetric(_) => KeyType::Symmetric,
        }
    }
}

impl From<KeyType> for BFieldElement {
    fn from(key_type: KeyType) -> Self {
        (key_type as u8).into()
    }
}

impl KeyType {
    pub fn from_announcement(announcement: &Announcement) -> Option<Self> {
        match announcement.message.first().copied()? {
            kt if kt == Self::Generation.into() => Some(Self::Generation),
            kt if kt == Self::Symmetric.into() => Some(Self::Symmetric),
            _ => None,
        }
    }
}

impl From<GenerationKey> for Key {
    fn from(key: GenerationKey) -> Self {
        Key::Generation(key)
    }
}

impl From<SymmetricKey> for Key {
    fn from(key: SymmetricKey) -> Self {
        Key::Symmetric(key)
    }
}
