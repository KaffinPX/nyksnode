use aead::Aead;
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
use nyks_consensus::twenty_first::math::lattice;
use nyks_consensus::twenty_first::math::lattice::kem::CIPHERTEXT_SIZE_IN_BFES;
use nyks_consensus::twenty_first::math::lattice::kem::PublicKey;
use nyks_consensus::twenty_first::math::lattice::kem::SecretKey;
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

pub(crate) const GENERATION_FLAG_U8: u8 = 79;
pub const GENERATION_FLAG: BFieldElement = BFieldElement::new(GENERATION_FLAG_U8 as u64);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationAddress {
    // Public key used to encrypt and share UTXO data
    encryption_key: lattice::kem::PublicKey,

    /// Post-image of the receiver preimage
    receiver_postimage: Digest,

    /// Post-image of the hashlock key
    lock_postimage: Digest,
}

impl GenerationAddress {
    fn prefix(network: Network) -> String {
        // NOLGA: Nyks lattice-based generation address
        let mut hrp = "nolga".to_string();
        let network_byte = network_hrp_char(network);
        hrp.push(network_byte);
        hrp
    }

    // Used beneath private_note etc.
    fn encrypt(&self, payload: &UtxoNotificationPayload) -> Vec<BFieldElement> {
        let (randomness, nonce_bfe) = deterministically_derive_seed_and_nonce(payload);
        let (shared_key, kem_ctxt) = lattice::kem::enc(self.encryption_key, randomness);

        // convert payload to bytes
        let plaintext = bincode::serialize(payload).unwrap();

        // generate symmetric ciphertext
        let cipher = Aes256Gcm::new(&shared_key.into());
        let nonce_as_bytes = [nonce_bfe.value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let ciphertext_bfes = bytes_to_bfes(&ciphertext);

        // concatenate and return
        [
            std::convert::Into::<[BFieldElement; CIPHERTEXT_SIZE_IN_BFES]>::into(kem_ctxt).to_vec(),
            vec![nonce_bfe],
            ciphertext_bfes,
        ]
        .concat()
    }
}

impl Recipient for GenerationAddress {
    fn from_bech32m(address: &str, network: Network) -> Result<Self, Bech32mDecodeError> {
        let (hrp, data, variant) = bech32::decode(address)?;

        if variant != Variant::Bech32m {
            return Err(Bech32mDecodeError::InvalidVariant);
        }
        if hrp[0..=5] != Self::prefix(network) {
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
        GENERATION_FLAG
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
            flag: GENERATION_FLAG_U8.into(),
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
            flag: GENERATION_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_bech32m(network)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationKey {
    seed: Digest,
}

impl GenerationKey {
    pub fn new(seed: Digest) -> Self {
        GenerationKey { seed }
    }
}

impl Spender for GenerationKey {
    type Addr = GenerationAddress;
    type ViewKey = GenerationViewingKey;

    fn to_address(&self) -> GenerationAddress {
        let (_, pk) = derive_kem_keypair(&self.seed);
        let privacy_digest = self.privacy_preimage().hash();

        GenerationAddress {
            encryption_key: pk,
            receiver_postimage: privacy_digest,
            lock_postimage: self.unlock_key().hash(),
        }
    }

    fn to_viewing_key(&self) -> GenerationViewingKey {
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
pub enum GenerationDecryptError {
    #[error("Ciphertext does not have nonce")]
    MissingNonce,

    #[error("Ciphertext does not have payload")]
    MissingPayload,

    #[error("Failed to convert ciphertext slice")]
    SliceConversion,

    #[error("Could not establish shared secret key")]
    KemDecryptionFailed,

    #[error("Failed to decrypt symmetric payload")]
    SymmetricDecryptionFailed,

    #[error("Failed to convert BFieldElements to bytes")]
    BfeToBytes,

    #[error("Deserialization failed")]
    Deserialization(#[from] bincode::Error),
}

impl Zeroize for GenerationKey {
    fn zeroize(&mut self) {
        self.seed = Digest::default();
    }
}

impl Drop for GenerationKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for GenerationKey {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationViewingKey {
    address: GenerationAddress,
    privacy_preimage: Digest,
    key: SecretKey,
}

impl From<GenerationKey> for GenerationViewingKey {
    fn from(key: GenerationKey) -> Self {
        let (secret_key, _) = derive_kem_keypair(&key.seed);

        GenerationViewingKey {
            address: key.to_address(),
            privacy_preimage: key.privacy_preimage(),
            key: secret_key,
        }
    }
}

impl Decryptor for GenerationViewingKey {
    type Address = GenerationAddress;
    type Error = GenerationDecryptError;

    fn address(&self) -> GenerationAddress {
        self.address
    }

    fn privacy_preimage(&self) -> Digest {
        self.privacy_preimage
    }

    fn decrypt(&self, ciphertext: &[BFieldElement]) -> Result<(Utxo, Digest), Self::Error> {
        // parse ciphertext
        if ciphertext.len() <= CIPHERTEXT_SIZE_IN_BFES {
            return Err(GenerationDecryptError::MissingNonce);
        }

        let (kem_ctxt, remainder_ctxt) = ciphertext.split_at(CIPHERTEXT_SIZE_IN_BFES);

        if remainder_ctxt.len() <= 1 {
            return Err(GenerationDecryptError::MissingPayload);
        }

        let (nonce_ctxt, dem_ctxt) = remainder_ctxt.split_at(1);

        let kem_ctxt_array: [BFieldElement; CIPHERTEXT_SIZE_IN_BFES] = kem_ctxt
            .try_into()
            .map_err(|_| GenerationDecryptError::SliceConversion)?;

        // decrypt
        let shared_key = lattice::kem::dec(self.key, kem_ctxt_array.into())
            .ok_or(GenerationDecryptError::KemDecryptionFailed)?;

        let cipher = Aes256Gcm::new(&shared_key.into());

        let nonce_as_bytes = [nonce_ctxt[0].value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();

        let nonce = Nonce::from_slice(&nonce_as_bytes);

        let ciphertext_bytes =
            bfes_to_bytes(dem_ctxt).map_err(|_| GenerationDecryptError::BfeToBytes)?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext_bytes.as_ref())
            .map_err(|_| GenerationDecryptError::SymmetricDecryptionFailed)?;

        // convert plaintext to utxo and digest
        let result = bincode::deserialize(&plaintext)?; // uses #[from]

        Ok(result)
    }
}

impl Zeroize for GenerationViewingKey {
    fn zeroize(&mut self) {
        self.privacy_preimage = Digest::default();
        self.key.zeroize();
    }
}

impl Drop for GenerationViewingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for GenerationViewingKey {}

fn derive_kem_keypair(seed: &Digest) -> (SecretKey, PublicKey) {
    let randomness: [u8; 32] = shake256::<32>(&bincode::serialize(seed).unwrap());
    lattice::kem::keygen(randomness)
}
