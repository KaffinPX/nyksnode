use std::fmt::Debug;
use std::sync::Arc;

use nyks_standards::wallet::keys::address::Address;

use crate::transaction::utxo::notifications::UtxoNotificationMedium;

/// specifies how to handle change for a transaction.
///
/// When the selected inputs represent more coins than the outputs (with fee)
/// where does this change go?
///
/// The default behavior is to recover to the next unused (symmetric) key with
/// onchain utxo notifications.
#[derive(Debug, Clone)] // TODO: deserialize?
pub enum ChangePolicy {
    /// Inputs must exactly equal spend amount, or else an error will result.
    ExactChange,

    /// Recover change to the provided address.
    ///
    /// (via specified notification medium)
    RecoverToAddress {
        address: Arc<Address>,
        medium: UtxoNotificationMedium,
    },

    /// If the change is non-zero, the excess funds will be lost forever.
    Burn,
}

/// The default behavior is an exact change.
impl Default for ChangePolicy {
    fn default() -> Self {
        Self::exact_change()
    }
}

impl ChangePolicy {
    /// Instantiate `ExactChange` variant
    pub fn exact_change() -> Self {
        Self::ExactChange
    }

    /// Instantiate `RecoverToProvidedKey` variant
    ///
    /// Enable change-recovery and configure which key and notification medium
    /// to use for that purpose.
    pub fn recover_to_address(
        address: Arc<Address>,
        notification_medium: UtxoNotificationMedium,
    ) -> Self {
        Self::RecoverToAddress {
            address,
            medium: notification_medium,
        }
    }

    /// instantiate `Burn` variant
    pub fn burn() -> Self {
        Self::Burn
    }
}
