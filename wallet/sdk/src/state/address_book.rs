use std::collections::{BTreeMap, HashMap};

use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::key::Key;
use nyks_standards::wallet::keys::key::KeyType;
use nyks_standards::wallet::keys::key::Spender;
use nyks_standards::wallet::keys::viewing_key::ViewingKey;

use nyks_wallet_core::entropy::wallet_entropy::WalletEntropy;

/// Owns the wallet's entropy and derives/tracks its addresses and keys.
#[derive(Debug)]
pub(crate) struct AddressBook {
    entropy: WalletEntropy,
    addresses: HashMap<KeyType, BTreeMap<u64, Address>>,
    viewing_keys: Vec<ViewingKey>,
}

impl AddressBook {
    /// Creates an address book tracking every derivation index through the
    /// requested index for each key type. Index 0 is reserved for the special
    /// key and is always included.
    pub(crate) fn with_address_indexes(
        entropy: WalletEntropy,
        generation_index: u64,
        symmetric_index: u64,
    ) -> Self {
        let mut addresses = HashMap::new();
        let mut viewing_keys = Vec::new();

        for (key_type, index) in [
            (KeyType::Generation, generation_index),
            (KeyType::Symmetric, symmetric_index),
        ] {
            let mut by_index = BTreeMap::new();

            for index in 0..=index {
                let (address, viewing_key) = derive(&entropy, key_type, index);

                by_index.insert(index, address);
                viewing_keys.push(viewing_key);
            }

            addresses.insert(key_type, by_index);
        }

        AddressBook {
            entropy,
            addresses,
            viewing_keys,
        }
    }

    pub(crate) fn viewing_keys(&self) -> &[ViewingKey] {
        &self.viewing_keys
    }

    /// Escape hatch for entropy-derived stuff that isn't really about
    /// addresses (e.g. sender randomness), so this struct doesn't need a
    /// proxy method per use.
    pub(crate) fn entropy(&self) -> &WalletEntropy {
        &self.entropy
    }

    pub(crate) fn latest(&self, key_type: KeyType) -> Address {
        self.addresses
            .get(&key_type)
            .and_then(|v| v.last_key_value())
            .map(|(_, address)| address.clone())
            .unwrap()
    }

    /// Derives the next address for a key type, registers it, and returns
    /// it along with its viewing key.
    pub(crate) fn next_address(&mut self, key_type: KeyType) -> (Address, ViewingKey) {
        let next_index = self.next_index(key_type);
        let (address, view_key) = derive(&self.entropy, key_type, next_index);

        self.addresses
            .entry(key_type)
            .or_default()
            .insert(next_index, address.clone());
        self.viewing_keys.push(view_key.clone());

        (address, view_key)
    }

    /// Derives the spending key for whichever address matches, if any.
    pub(crate) fn spending_key(&self, matches: impl Fn(&Address) -> bool) -> Option<Key> {
        let (key_type, index) = self.find(matches)?;

        Some(match key_type {
            KeyType::Generation => self.entropy.nth_generation_key(index).into(),
            KeyType::Symmetric => self.entropy.nth_symmetric_key(index).into(),
        })
    }

    fn next_index(&self, key_type: KeyType) -> u64 {
        self.addresses
            .get(&key_type)
            .and_then(|v| v.last_key_value().map(|(&index, _)| index + 1))
            .unwrap_or(1)
    }

    fn find(&self, matches: impl Fn(&Address) -> bool) -> Option<(KeyType, u64)> {
        for (key_type, addrs) in self.addresses.iter() {
            for (&index, address) in addrs.iter() {
                if matches(address) {
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
