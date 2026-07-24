use std::fmt::Display;
use std::str::FromStr;

use nyks_standards::wallet::keys::address::Address;
use serde::Deserialize;
use serde::Serialize;

/// Enumerates the medium of exchange for UTXO-notifications.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum UtxoNotificationMedium {
    /// The UTXO notification should be sent on-chain
    #[default]
    OnChain,

    /// The UTXO notification should be sent off-chain
    OffChain,
}

impl Display for UtxoNotificationMedium {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UtxoNotificationMedium::OnChain => write!(f, "on-chain"),
            UtxoNotificationMedium::OffChain => write!(f, "off-chain"),
        }
    }
}

impl FromStr for UtxoNotificationMedium {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "on-chain" => Ok(UtxoNotificationMedium::OnChain),
            "off-chain" => Ok(UtxoNotificationMedium::OffChain),
            other => Err(format!("Invalid UtxoNotificationMedium: '{other}'")),
        }
    }
}

/// enumerates how utxos and spending information is communicated, including how
/// to encrypt this information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UtxoNotificationMethod {
    /// the utxo notification should be transferred to recipient encrypted on the blockchain
    OnChain(Address),

    /// the utxo notification should be transferred to recipient off the blockchain
    OffChain(Address),

    /// No UTXO notification is intended
    None,
}

impl Display for UtxoNotificationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UtxoNotificationMethod::OnChain(_) => write!(f, "on-chain"),
            UtxoNotificationMethod::OffChain(_) => write!(f, "off-chain"),
            UtxoNotificationMethod::None => write!(f, "none"),
        }
    }
}

impl UtxoNotificationMethod {
    pub(crate) fn new(medium: UtxoNotificationMedium, recipient: Address) -> Self {
        match medium {
            UtxoNotificationMedium::OnChain => Self::OnChain(recipient),
            UtxoNotificationMedium::OffChain => Self::OffChain(recipient),
        }
    }

    pub fn recipient(&self) -> Option<&Address> {
        match self {
            UtxoNotificationMethod::OnChain(address) => Some(address),
            UtxoNotificationMethod::OffChain(address) => Some(address),
            UtxoNotificationMethod::None => None,
        }
    }
}
