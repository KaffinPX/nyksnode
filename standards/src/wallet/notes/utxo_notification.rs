use nyks_protocol::consensus::transaction::utxo::Utxo;
use nyks_protocol::twenty_first::tip5::Digest;
use serde::Deserialize;
use serde::Serialize;

use crate::wallet::keys::address::Address;

/// The payload of a UTXO notification, containing all information necessary
/// to claim it, provided that the decryptor already has access to the
/// associated spending key.
///
/// future work:
/// we should consider adding functionality that would facilitate passing
/// these payloads from sender to receiver off-chain for lower-fee transfers
/// between trusted parties or eg wallets owned by the same person/org.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UtxoNotificationPayload {
    pub(crate) utxo: Utxo,
    pub(crate) sender_randomness: Digest,
}

impl UtxoNotificationPayload {
    pub fn new(utxo: Utxo, sender_randomness: Digest) -> Self {
        Self {
            utxo,
            sender_randomness,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateNotificationData {
    pub cleartext: UtxoNotificationPayload,
    pub ciphertext: String,
    pub recipient_address: Address,
}
