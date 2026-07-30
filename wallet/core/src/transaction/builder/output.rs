//! provides an interface to transaction outputs and associated types

use std::ops::Deref;
use std::ops::DerefMut;

use nyks_consensus::tasm_lib::prelude::Digest;
use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::address::Recipient;
use nyks_standards::wallet::notes::utxo_notification::PrivateNotificationData;
use nyks_standards::wallet::notes::utxo_notification::UtxoNotificationPayload;
use serde::Deserialize;
use serde::Serialize;

use nyks_consensus::mutator_set::addition_record::AdditionRecord;
use nyks_consensus::network::Network;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::transaction::announcement::Announcement;
use nyks_consensus::transaction::utxo::Utxo;
use nyks_consensus::transaction::utxo_triple::UtxoTriple;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

use crate::transaction::utxo::notifications::UtxoNotificationMedium;
use crate::transaction::utxo::notifications::UtxoNotificationMethod;

/// represents a transaction output, as used by
/// [TransactionDetailsBuilder](crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder)
///
/// Contains data that a UTXO recipient requires in order to be notified about
/// and claim a given UTXO.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    utxo: Utxo,
    sender_randomness: Digest,
    receiver_digest: Digest,
    notification_method: UtxoNotificationMethod,

    /// Indicates if this client can unlock the UTXO
    is_change: bool,
}

impl TxOutput {
    // note: normally use one of the other constructors.
    pub fn new(
        utxo: Utxo,
        sender_randomness: Digest,
        receiver_digest: Digest,
        notification_method: UtxoNotificationMethod,
        is_change: bool,
    ) -> Self {
        Self {
            utxo,
            sender_randomness,
            receiver_digest,
            notification_method,
            is_change,
        }
    }

    fn notification_payload(&self) -> UtxoNotificationPayload {
        UtxoNotificationPayload::new(self.utxo(), self.sender_randomness())
    }

    /// retrieve native currency amount
    pub fn native_currency_amount(&self) -> NativeCurrencyAmount {
        self.utxo.get_native_currency_amount()
    }

    /// Instantiate a [TxOutput] for native currency intended for on-chain UTXO
    /// notification.
    pub fn onchain_native_currency(
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        recipient: Address,
    ) -> Self {
        let utxo = Utxo::new_native_currency(recipient.lock_script().hash(), amount);
        Self {
            utxo,
            sender_randomness,
            receiver_digest: recipient.privacy_digest(),
            notification_method: UtxoNotificationMethod::OnChain(recipient),
            is_change: false,
        }
    }

    /// Instantiate a [TxOutput] for native currency intended for on-chain UTXO
    /// notification.
    pub fn onchain_native_currency_as_change(
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        recipient: Address,
    ) -> Self {
        let utxo = Utxo::new_native_currency(recipient.lock_script().hash(), amount);
        Self {
            utxo,
            sender_randomness,
            receiver_digest: recipient.privacy_digest(),
            notification_method: UtxoNotificationMethod::OnChain(recipient),
            is_change: true,
        }
    }

    /// Instantiate a [TxOutput] for native currency intended for off-chain UTXO
    /// notification.
    pub fn offchain_native_currency(
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        recipient: Address,
    ) -> Self {
        Self::native_currency(
            amount,
            sender_randomness,
            recipient,
            UtxoNotificationMedium::OffChain,
        )
    }

    /// Instantiate a [TxOutput] for native currency.
    pub fn native_currency(
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        recipient: Address,
        notification_medium: UtxoNotificationMedium,
    ) -> Self {
        let receiver_digest = recipient.privacy_digest();
        let utxo = Utxo::new_native_currency(recipient.lock_script().hash(), amount);
        let notify_method = UtxoNotificationMethod::new(notification_medium, recipient);
        Self {
            utxo,
            sender_randomness,
            receiver_digest,
            notification_method: notify_method,
            is_change: false,
        }
    }

    /// Instantiate a [TxOutput] for native currency intended for off-chain UTXO
    /// notification.
    pub fn offchain_native_currency_as_change(
        amount: NativeCurrencyAmount,
        sender_randomness: Digest,
        recipient: Address,
    ) -> Self {
        let utxo = Utxo::new_native_currency(recipient.lock_script().hash(), amount);
        Self {
            utxo,
            sender_randomness,
            receiver_digest: recipient.privacy_digest(),
            notification_method: UtxoNotificationMethod::OffChain(recipient),
            is_change: true,
        }
    }

    pub fn is_change(&self) -> bool {
        self.is_change
    }

    /// Determine whether there is a time-lock, with any release date, on the
    /// UTXO.
    pub fn is_timelocked(&self) -> bool {
        self.utxo.is_timelocked()
    }

    /// Add to the amount with a delta.
    pub fn add_to_amount(mut self, delta: NativeCurrencyAmount) -> Self {
        self.utxo = self.utxo.add_to_amount(delta);
        self
    }

    pub fn is_offchain(&self) -> bool {
        matches!(
            self.notification_method,
            UtxoNotificationMethod::OffChain(_)
        )
    }

    pub fn utxo(&self) -> Utxo {
        self.utxo.clone()
    }

    #[inline(always)]
    pub fn sender_randomness(&self) -> Digest {
        self.sender_randomness
    }

    pub fn set_sender_randomness(&mut self, sender_randomness: Digest) {
        self.sender_randomness = sender_randomness;
    }

    #[inline(always)]
    pub fn receiver_digest(&self) -> Digest {
        self.receiver_digest
    }

    #[inline(always)]
    pub fn notification_method(&self) -> &UtxoNotificationMethod {
        &self.notification_method
    }

    /// Retrieve on-chain UTXO notification announcement, if any.
    pub fn announcement(&self) -> Option<Announcement> {
        match &self.notification_method {
            UtxoNotificationMethod::None => None,
            UtxoNotificationMethod::OffChain(_) => None,
            UtxoNotificationMethod::OnChain(receiving_address) => {
                let notification_payload = self.notification_payload();
                Some(receiving_address.create_note_announcement(&notification_payload))
            }
        }
    }

    pub(crate) fn offchain_notification(&self, network: Network) -> Option<(String, Address)> {
        match &self.notification_method {
            UtxoNotificationMethod::OnChain(_) => None,
            UtxoNotificationMethod::OffChain(recipient) => {
                let notification_payload = self.notification_payload();

                Some((
                    recipient.create_note(&notification_payload, network),
                    recipient.to_owned(),
                ))
            }
            UtxoNotificationMethod::None => None,
        }
    }

    /// Adds a time lock coin, if necessary.
    ///
    /// Does nothing if there already is a time lock coin whose release date is
    /// later than the argument.
    pub fn with_time_lock(self, release_date: Timestamp) -> Self {
        Self {
            utxo: self.utxo.with_time_lock(release_date),
            sender_randomness: self.sender_randomness,
            receiver_digest: self.receiver_digest,
            notification_method: self.notification_method,
            is_change: self.is_change,
        }
    }

    pub(crate) fn utxo_triple(&self) -> UtxoTriple {
        UtxoTriple {
            utxo: self.utxo(),
            sender_randomness: self.sender_randomness,
            receiver_digest: self.receiver_digest(),
        }
    }

    pub fn addition_record(&self) -> AdditionRecord {
        self.utxo_triple().addition_record()
    }
}

/// Represents a list of [TxOutput]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TxOutputList(Vec<TxOutput>);

impl Deref for TxOutputList {
    type Target = Vec<TxOutput>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TxOutputList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<&TxOutputList> for Vec<AdditionRecord> {
    fn from(list: &TxOutputList) -> Self {
        list.addition_records_iter().into_iter().collect()
    }
}

impl From<&TxOutputList> for Vec<Utxo> {
    fn from(list: &TxOutputList) -> Self {
        list.utxos_iter().into_iter().collect()
    }
}

impl From<TxOutputList> for Vec<TxOutput> {
    fn from(list: TxOutputList) -> Self {
        list.0
    }
}

impl<I: Into<TxOutput>, T: IntoIterator<Item = I>> From<T> for TxOutputList {
    fn from(v: T) -> Self {
        Self(v.into_iter().map(|i| i.into()).collect())
    }
}

impl TxOutputList {
    /// calculates total amount in native currency, regardless of which other
    /// coins are present (even if that makes the native currency unspendable).
    pub fn total_native_coins(&self) -> NativeCurrencyAmount {
        self.0
            .iter()
            .map(|u| u.utxo.get_native_currency_amount())
            .sum()
    }

    /// retrieves utxos
    pub fn utxos_iter(&self) -> impl IntoIterator<Item = Utxo> + '_ {
        self.0.iter().map(|u| u.utxo.clone())
    }

    /// retrieves utxos
    pub fn utxos(&self) -> Vec<Utxo> {
        self.utxos_iter().into_iter().collect()
    }

    pub(crate) fn sender_randomnesses(&self) -> Vec<Digest> {
        self.iter().map(|x| x.sender_randomness()).collect()
    }

    pub(crate) fn receiver_digests(&self) -> Vec<Digest> {
        self.iter().map(|x| x.receiver_digest()).collect()
    }

    /// retrieves addition_records
    pub fn addition_records_iter(&self) -> impl IntoIterator<Item = AdditionRecord> + '_ {
        self.0.iter().map(|u| u.addition_record())
    }

    /// retrieves addition_records
    pub fn addition_records(&self) -> Vec<AdditionRecord> {
        self.addition_records_iter().into_iter().collect()
    }

    /// Return all on-chain UTXO notification announcement for this
    /// [`TxOutputList`].
    pub(crate) fn announcements(&self) -> Vec<Announcement> {
        let mut announcements = vec![];
        for tx_output in &self.0 {
            if let Some(pa) = tx_output.announcement() {
                announcements.push(pa);
            }
        }

        announcements
    }

    pub fn offchain_notifications(
        &self,
        network: Network,
    ) -> impl Iterator<Item = PrivateNotificationData> + use<'_> {
        self.0.iter().filter_map(move |tx_output| {
            if let Some((ciphertext, receiver_address)) = tx_output.offchain_notification(network) {
                Some(PrivateNotificationData {
                    cleartext: tx_output.notification_payload(),
                    ciphertext,
                    recipient_address: receiver_address,
                })
            } else {
                None
            }
        })
    }

    /// indicates if any offchain notifications exist
    pub fn has_offchain(&self) -> bool {
        self.0.iter().any(|u| u.is_offchain())
    }

    pub fn change_iter(&self) -> impl Iterator<Item = &TxOutput> + '_ {
        self.0.iter().filter(|o| o.is_change)
    }

    pub fn change_amount(&self) -> NativeCurrencyAmount {
        self.change_iter().map(|o| o.native_currency_amount()).sum()
    }

    pub fn has_change_output(&self) -> bool {
        self.0.iter().any(|o| o.is_change)
    }
}
