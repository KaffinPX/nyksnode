use std::collections::BTreeMap;
use std::collections::HashMap;

use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::key::Key;
use nyks_standards::wallet::keys::key::KeyType;
use nyks_standards::wallet::keys::key::Spender;
use nyks_standards::wallet::keys::viewing_key::ViewingKey;

use nyks_wallet_core::entropy::wallet_entropy::WalletEntropy;

/// Owns the wallet's entropy and derives/tracks its addresses and keys.
#[derive(Debug)]
pub struct AddressBook {
    entropy: WalletEntropy,
    addresses: HashMap<KeyType, BTreeMap<u64, (Address, ViewingKey)>>,
}

impl AddressBook {
    /// Tracks every used derivation index, plus the next unused address for
    /// each key type. Index 0 is reserved for the special key and is included.
    pub fn with_address_indexes(
        entropy: WalletEntropy,
        generation_index: u64,
        symmetric_index: u64,
    ) -> Self {
        let mut addresses = HashMap::new();

        for (key_type, index) in [
            (KeyType::Generation, generation_index),
            (KeyType::Symmetric, symmetric_index),
        ] {
            let mut by_index = BTreeMap::new();

            for index in 0..=index + 1 {
                by_index.insert(index, derive(&entropy, key_type, index));
            }

            addresses.insert(key_type, by_index);
        }

        AddressBook { entropy, addresses }
    }

    pub fn viewing_keys(&self) -> impl Iterator<Item = &ViewingKey> {
        self.addresses
            .values()
            .flat_map(|by_index| by_index.values().map(|(_, viewing_key)| viewing_key))
    }

    pub(crate) fn entropy(&self) -> &WalletEntropy {
        &self.entropy
    }

    /// Returns the highest tracked address, which is the wallet's current
    /// unused address.
    pub fn latest_address(&self, key_type: KeyType) -> Address {
        self.addresses
            .get(&key_type)
            .and_then(|by_index| by_index.last_key_value())
            .map(|(_, (address, _))| address.clone())
            .unwrap()
    }

    /// Derives and records a new address, then returns it with its index and
    /// viewing key.
    pub fn next_address(&mut self, key_type: KeyType) -> (Address, u64, ViewingKey) {
        let index = self.addresses[&key_type]
            .last_key_value()
            .map(|(&index, _)| index + 1)
            .unwrap_or(1);
        let (address, viewing_key) = derive(&self.entropy, key_type, index);
        self.addresses
            .entry(key_type)
            .or_default()
            .insert(index, (address.clone(), viewing_key.clone()));

        (address, index, viewing_key)
    }

    /// Derives the spending key for whichever address matches, if any.
    pub fn spending_key(&self, matches: impl Fn(&Address) -> bool) -> Option<Key> {
        let (key_type, index) = self.find(matches)?;

        Some(match key_type {
            KeyType::Generation => self.entropy.nth_generation_key(index).into(),
            KeyType::Symmetric => self.entropy.nth_symmetric_key(index).into(),
        })
    }

    fn find(&self, matches: impl Fn(&Address) -> bool) -> Option<(KeyType, u64)> {
        for (key_type, addrs) in self.addresses.iter() {
            for (&index, address) in addrs.iter() {
                if matches(&address.0) {
                    return Some((*key_type, index));
                }
            }
        }
        None
    }
}

fn derive(entropy: &WalletEntropy, key_type: KeyType, index: u64) -> (Address, ViewingKey) {
    match key_type {
        KeyType::Generation => {
            let key = entropy.nth_generation_key(index);
            (key.to_address().into(), key.to_viewing_key().into())
        }
        KeyType::Symmetric => {
            let key = entropy.nth_symmetric_key(index);
            (key.to_address().into(), key.to_viewing_key().into())
        }
    }
}
