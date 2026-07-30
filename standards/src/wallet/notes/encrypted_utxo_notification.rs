use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use bech32::FromBase32;
use bech32::ToBase32;
use nyks_consensus::BFieldElement;
use nyks_consensus::network::Network;
use nyks_consensus::transaction::announcement::Announcement;
use nyks_consensus::triton_vm::prelude::BFieldCodec;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::wallet::keys::network_hrp_char;

/// an encrypted wrapper for UTXO notifications.
///
/// This type is intended to be serialized and actually transferred between
/// parties.
///
/// note: bech32m encoding of this type is considered standard and is
/// recommended over serde serialization.
///
/// the receiver_identifier enables the receiver to find the matching
/// `SpendingKey` in their wallet.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, BFieldCodec)]
pub struct EncryptedUtxoNotification {
    /// Describes the type of encoding used here
    pub(crate) flag: BFieldElement,

    /// enables the receiver to find the matching `SpendingKey` in their wallet.
    pub(crate) receiver_identifier: BFieldElement,

    /// Encrypted UTXO notification payload.
    pub(crate) ciphertext: Vec<BFieldElement>,
}

#[derive(Debug, Copy, Clone, Error)]
pub enum ConversionFromMessageError {
    #[error("message too short: length is {0}, minimum required is 2")]
    MessageTooShort(usize),
}

impl EncryptedUtxoNotification {
    fn into_message(self) -> Vec<BFieldElement> {
        [vec![self.flag, self.receiver_identifier], self.ciphertext].concat()
    }

    fn from_message(message: Vec<BFieldElement>) -> Result<Self, ConversionFromMessageError> {
        if message.len() < 2 {
            Err(ConversionFromMessageError::MessageTooShort(message.len()))
        } else {
            Ok(Self {
                flag: message[0],
                receiver_identifier: message[1],
                ciphertext: message[2..].to_vec(),
            })
        }
    }

    /// Convert an encrypted UTXO notification to a announcement. Leaks
    /// privacy in the form of `receiver_identifier` is addresses are reused.
    /// Never leaks actual UTXO info such as amount transferred.
    pub(crate) fn into_announcement(self) -> Announcement {
        // We could use `BfieldCodec` encode here. But it might be a bit faster
        // to filter out irrelevant announcement if we don't have to
        // attempt a decoding to a specific data type first but can instead just
        // read out b-field elements and skip items based on that.
        Announcement::new(self.into_message())
    }

    pub fn into_bech32m(self, network: Network) -> String {
        let hrp = Self::get_hrp(network);
        let message = self.into_message();
        let payload = bincode::serialize(&message).unwrap_or_else(|e| {
            panic!("Serialization shouldn't fail. Message was: {message:?}\nerror: {e}")
        });
        let payload_base_32 = payload.to_base32();
        let variant = bech32::Variant::Bech32m;
        bech32::encode(&hrp, payload_base_32, variant).unwrap_or_else(|e| panic!(
            "bech32 encoding shouldn't fail. Arguments were:\n\n{hrp}\n\n{payload:?}\n\n{variant:?}\n\nerror: {e}"
        ))
    }

    /// decodes from a bech32m string and verifies it matches `network`
    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(encoded)?;

        ensure!(
            variant == bech32::Variant::Bech32m,
            "Can only decode bech32m addresses."
        );
        ensure!(
            hrp == *Self::get_hrp(network),
            "Could not decode bech32m address because of invalid prefix",
        );

        let payload = Vec::<u8>::from_base32(&data)?;
        let message = bincode::deserialize(&payload)
            .map_err(|e| anyhow!("Could not decode bech32m because of error: {e}"))?;
        let encrypted_utxo_notification = Self::from_message(message)
            .map_err(|e| anyhow!("conversion from bech32m failed: {e}"))?;

        Ok(encrypted_utxo_notification)
    }

    /// returns human readable prefix (hrp) of a utxo-transfer-encrypted, specific to `network`
    pub(crate) fn get_hrp(network: Network) -> String {
        format!("utxo{}", network_hrp_char(network))
    }
}
