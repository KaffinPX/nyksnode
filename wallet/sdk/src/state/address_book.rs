use std::collections::HashMap;

use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::key::Key;
use nyks_standards::wallet::keys::key::KeyType;
use nyks_standards::wallet::keys::key::Spender;
use nyks_standards::wallet::keys::viewing_key::ViewingKey;

use nyks_wallet_core::entropy::wallet_entropy::WalletEntropy;

/// Owns the wallet's entropy and derives/tracks its addresses and keys.
///
/// Addresses are grouped by key type in derivation order - index `i` is
/// the `i`-th derived key of that type, with index 0 being the special key.
/// `view_keys` mirrors that same order and stays in sync as addresses are
/// added.
#[derive(Debug)]
pub(crate) struct AddressBook {
    entropy: WalletEntropy,
    addresses: HashMap<KeyType, Vec<Address>>,
    view_keys: Vec<ViewingKey>,
}

impl AddressBook {
    /// Seeds each key type with the special key and index-1 address.
    pub(crate) fn new(entropy: WalletEntropy) -> Self {
        let mut addresses: HashMap<KeyType, Vec<Address>> = HashMap::new();

        addresses.insert(
            KeyType::Generation,
            vec![
                entropy.special_generation_key().to_address().into(),
                entropy.nth_generation_address(1).into(),
            ],
        );
        addresses.insert(
            KeyType::Symmetric,
            vec![
                entropy.special_symmetric_key().to_address().into(),
                entropy.nth_symmetric_address(1).into(),
            ],
        );

        let view_keys = vec![
            entropy.special_generation_key().to_viewing_key().into(),
            entropy.nth_generation_key(1).to_viewing_key().into(),
            entropy.special_symmetric_key().to_viewing_key().into(),
            entropy.nth_symmetric_key(1).to_viewing_key().into(),
        ];

        AddressBook {
            entropy,
            addresses,
            view_keys,
        }
    }

    pub(crate) fn view_keys(&self) -> &[ViewingKey] {
        &self.view_keys
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
            .and_then(|v| v.last())
            .cloned()
            .unwrap()
    }

    /// Derives the next address for a key type, registers it, and returns
    /// it along with its viewing key.
    pub(crate) fn next_address(&mut self, key_type: KeyType) -> (Address, ViewingKey) {
        let next_index = self.next_index(key_type);

        let (address, view_key): (Address, ViewingKey) = match key_type {
            KeyType::Generation => {
                let key = self.entropy.nth_generation_key(next_index);
                (key.to_address().into(), key.to_viewing_key().into())
            }
            KeyType::Symmetric => {
                let key = self.entropy.nth_symmetric_key(next_index);
                (key.to_address().into(), key.to_viewing_key().into())
            }
        };

        self.addresses
            .entry(key_type)
            .or_default()
            .push(address.clone());
        self.view_keys.push(view_key.clone());

        (address, view_key)
    }

    /// Derives the spending key for whichever address matches, if any.
    pub(crate) fn spending_key(&self, matches: impl Fn(&Address) -> bool) -> Option<Key> {
        let (key_type, index) = self.find(matches)?;

        Some(match key_type {
            KeyType::Generation => self.entropy.nth_generation_key(index as u64).into(),
            KeyType::Symmetric => self.entropy.nth_symmetric_key(index as u64).into(),
        })
    }

    fn next_index(&self, key_type: KeyType) -> u64 {
        self.addresses.get(&key_type).map(|v| v.len()).unwrap_or(0) as u64
    }

    fn find(&self, matches: impl Fn(&Address) -> bool) -> Option<(KeyType, usize)> {
        for (key_type, addrs) in self.addresses.iter() {
            for (index, address) in addrs.iter().enumerate() {
                if matches(address) {
                    return Some((*key_type, index));
                }
            }
        }
        None
    }
}
