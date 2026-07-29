use aead::Aead;
use aead::Key as AesKey;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use bech32::FromBase32;
use bech32::ToBase32;
use bech32::Variant;
use nyks_consensus::BFieldElement;
use nyks_consensus::network::Network;
use nyks_consensus::tasm_lib::prelude::Digest;
use nyks_consensus::tasm_lib::prelude::Tip5;
use nyks_consensus::transaction::announcement::Announcement;
use nyks_consensus::transaction::lock_script::LockScript;
use nyks_consensus::transaction::lock_script::LockScriptAndWitness;
use nyks_consensus::transaction::utxo::Utxo;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::wallet::keys::address::Bech32mDecodeError;
use crate::wallet::keys::address::Recipient;
use crate::wallet::keys::bfes_to_bytes;
use crate::wallet::keys::bytes_to_bfes;
use crate::wallet::keys::deterministically_derive_seed_and_nonce;
use crate::wallet::keys::key::Spender;
use crate::wallet::keys::network_hrp_char;
use crate::wallet::keys::shake256;
use crate::wallet::keys::viewing_key::Decryptor;
use crate::wallet::notes::encrypted_utxo_notification::EncryptedUtxoNotification;
use crate::wallet::notes::utxo_notification::UtxoNotificationPayload;

pub(crate) const SYMMETRIC_FLAG_U8: u8 = 80;
pub const SYMMETRIC_FLAG: BFieldElement = BFieldElement::new(SYMMETRIC_FLAG_U8 as u64);

/// A symmetric address.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymmetricAddress {
    /// Commitment to the sender's ephemeral secret.
    lock_postimage: Digest,
    /// Privacy digest that also lets anyone (including the sender) derive the
    /// shared encryption key without revealing the receiver's spending key.
    receiver_postimage: Digest,
}

impl SymmetricAddress {
    fn prefix(network: Network) -> String {
        // NSYMA: Nyks symmetric address
        let mut hrp = "nsyma".to_string();
        let network_byte = network_hrp_char(network);
        hrp.push(network_byte);
        hrp
    }

    fn encrypt(&self, payload: &UtxoNotificationPayload) -> Vec<BFieldElement> {
        // 1. derive nonce deterministically
        let (_randomness, nonce_bfe) = deterministically_derive_seed_and_nonce(payload);

        let nonce_bytes = [&nonce_bfe.value().to_be_bytes(), [0u8; 4].as_slice()].concat();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 2. serialize payload
        let plaintext = bincode::serialize(payload).unwrap();

        // 3. encrypt
        let cipher = Aes256Gcm::new(&derive_encryption_secret(&self.receiver_postimage));
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // 4. convert to BFEs
        let ciphertext_bfes = bytes_to_bfes(&ciphertext);

        // 5. return nonce + ciphertext
        [&[nonce_bfe], ciphertext_bfes.as_slice()].concat()
    }
}

impl Recipient for SymmetricAddress {
    fn from_bech32m(address: &str, network: Network) -> Result<Self, Bech32mDecodeError> {
        let (hrp, data, variant) = bech32::decode(address)?;

        if variant != Variant::Bech32m {
            return Err(Bech32mDecodeError::InvalidVariant);
        }
        if hrp != Self::prefix(network) {
            return Err(Bech32mDecodeError::InvalidHrp);
        }

        let payload = Vec::<u8>::from_base32(&data)?;
        Ok(bincode::deserialize(&payload)?)
    }

    fn to_bech32m(&self, network: Network) -> String {
        let hrp = Self::prefix(network);
        let payload = bincode::serialize(self).unwrap();
        bech32::encode(&hrp, payload.to_base32(), Variant::Bech32m).unwrap()
    }

    fn flag(&self) -> BFieldElement {
        SYMMETRIC_FLAG
    }

    fn receiver_identifier(&self) -> BFieldElement {
        Tip5::hash(&self.privacy_digest()).values()[0]
    }

    fn privacy_digest(&self) -> Digest {
        self.receiver_postimage
    }

    fn lock_script(&self) -> LockScript {
        LockScript::standard_hash_lock_from_after_image(self.lock_postimage)
    }

    fn create_note_announcement(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
    ) -> Announcement {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: SYMMETRIC_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_announcement()
    }

    fn create_note(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
        network: Network,
    ) -> String {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: SYMMETRIC_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_bech32m(network)
    }
}

/// The private counterpart to a [`SymmetricAddress`].
///
/// Holds the seed from which all key material is derived deterministically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymmetricKey {
    seed: Digest,
}

impl SymmetricKey {
    pub fn new(seed: Digest) -> Self {
        SymmetricKey { seed }
    }
}

impl Spender for SymmetricKey {
    type Addr = SymmetricAddress;
    type ViewKey = SymmetricViewingKey;

    fn to_address(&self) -> SymmetricAddress {
        let privacy_digest = self.privacy_preimage().hash(); // TBD: get it out of spender trait

        SymmetricAddress {
            receiver_postimage: privacy_digest,
            lock_postimage: self.unlock_key().hash(),
        }
    }

    fn to_viewing_key(&self) -> SymmetricViewingKey {
        self.clone().into() // TODO: Looks bad... cleanup
    }

    fn unlock_key(&self) -> Digest {
        Tip5::hash_varlen(&[self.seed.values().to_vec(), vec![BFieldElement::new(0)]].concat())
    }

    fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        LockScriptAndWitness::standard_hash_lock_from_preimage(self.unlock_key())
    }

    fn privacy_preimage(&self) -> Digest {
        Tip5::hash_varlen(&[self.seed.values().to_vec(), vec![BFieldElement::new(1)]].concat())
    }
}

#[derive(Debug, Error)]
pub enum SymmetricDecryptError {
    #[error("Ciphertext too short (missing nonce)")]
    MissingNonce,

    #[error("Byte conversion failed")]
    ByteConversion,

    #[error("Decryption failed")]
    Decryption(#[from] aes_gcm::Error),

    #[error("Deserialization failed")]
    Deserialization(#[from] bincode::Error),
}

impl Zeroize for SymmetricKey {
    fn zeroize(&mut self) {
        self.seed = Digest::default();
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SymmetricKey {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymmetricViewingKey {
    address: SymmetricAddress,
    privacy_preimage: Digest,
    key: AesKey<Aes256Gcm>,
}

impl From<SymmetricKey> for SymmetricViewingKey {
    fn from(key: SymmetricKey) -> Self {
        let address = key.to_address();

        SymmetricViewingKey {
            address,
            privacy_preimage: key.privacy_preimage(),
            key: derive_encryption_secret(&address.receiver_postimage),
        }
    }
}

impl Decryptor for SymmetricViewingKey {
    type Address = SymmetricAddress;
    type Error = SymmetricDecryptError;

    fn address(&self) -> SymmetricAddress {
        self.address
    }

    fn privacy_preimage(&self) -> Digest {
        self.privacy_preimage
    }

    fn decrypt(&self, ciphertext: &[BFieldElement]) -> Result<(Utxo, Digest), Self::Error> {
        const NONCE_LEN: usize = 1;

        if ciphertext.len() <= NONCE_LEN {
            return Err(SymmetricDecryptError::MissingNonce);
        }

        let (nonce_ctxt, ciphertext) = ciphertext.split_at(NONCE_LEN);

        let nonce_bytes = [&nonce_ctxt[0].value().to_be_bytes(), [0u8; 4].as_slice()].concat();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext_bytes =
            bfes_to_bytes(ciphertext).map_err(|_| SymmetricDecryptError::ByteConversion)?;

        let cipher = Aes256Gcm::new(&self.key);
        let plaintext = cipher.decrypt(nonce, ciphertext_bytes.as_ref())?;

        Ok(bincode::deserialize(&plaintext)?)
    }
}

impl Zeroize for SymmetricViewingKey {
    fn zeroize(&mut self) {
        self.privacy_preimage = Digest::default();
        self.key = AesKey::<Aes256Gcm>::default();
    }
}

impl Drop for SymmetricViewingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SymmetricViewingKey {}

/// Derive 256-bit encryption secret from shared common.
fn derive_encryption_secret(receiver_postimage: &Digest) -> AesKey<Aes256Gcm> {
    let key_bytes = shake256::<32>(&bincode::serialize(receiver_postimage).unwrap());
    key_bytes.into()
}
