use std::fmt::Display;
use std::hash::Hash as StdHash;
use std::hash::Hasher as StdHasher;

use get_size2::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::timestamp::Timestamp;
use crate::type_scripts::known_type_scripts::is_known_type_script_with_valid_state;
use crate::type_scripts::native_currency::NativeCurrency;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::type_scripts::time_lock::TimeLock;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject)]
pub struct Coin {
    pub type_script_hash: Digest,
    pub state: Vec<BFieldElement>,
}

impl Display for Coin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = if self.type_script_hash == NativeCurrency.hash() {
            let amount = match NativeCurrencyAmount::decode(&self.state) {
                Ok(boxed_amount) => boxed_amount.to_string(),
                Err(_) => "Error: Unable to decode amount".to_owned(),
            };
            format!("Native currency: {amount}")
        } else if self.type_script_hash == TimeLock.hash() {
            let release_date = self.release_date().unwrap();
            format!("Timelock until: {release_date}")
        } else {
            "Unknown type script hash".to_owned()
        };

        write!(f, "{}", output)
    }
}

impl Coin {
    pub fn release_date(&self) -> Option<Timestamp> {
        if self.type_script_hash == TimeLock.hash() {
            Timestamp::decode(&self.state).ok().map(|b| *b)
        } else {
            None
        }
    }

    pub fn new_native_currency(amount: NativeCurrencyAmount) -> Self {
        Self {
            type_script_hash: NativeCurrency.hash(),
            state: amount.encode(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject)]
pub struct Utxo {
    lock_script_hash: Digest,
    coins: Vec<Coin>,
}

impl Display for Utxo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.coins
                .iter()
                .enumerate()
                .map(|(i, coin)| format!("coin {i}: {coin}"))
                .join("; ")
        )
    }
}

impl GetSize for Utxo {
    fn get_stack_size() -> usize {
        size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        let mut total = self.lock_script_hash().get_heap_size();
        for v in &self.coins {
            total += size_of::<Digest>();
            total += v.state.len() * size_of::<BFieldElement>();
        }

        total
    }
}

impl Utxo {
    pub fn new(lock_script_hash: Digest, coins: Vec<Coin>) -> Self {
        Self {
            lock_script_hash,
            coins,
        }
    }

    pub fn new_native_currency(lock_script_hash: Digest, amount: NativeCurrencyAmount) -> Self {
        Self {
            coins: vec![Coin::new_native_currency(amount)],
            lock_script_hash,
        }
    }

    pub fn coins(&self) -> &[Coin] {
        &self.coins
    }

    pub fn lock_script_hash(&self) -> Digest {
        self.lock_script_hash
    }

    /// Add to the amount of the UTXO with a delta.
    pub fn add_to_amount(mut self, delta: NativeCurrencyAmount) -> Self {
        let current_amount = self.get_native_currency_amount();
        let new_amount = current_amount + delta;
        let new_amount = Coin::new_native_currency(new_amount);
        let remove = self
            .coins
            .iter()
            .find_position(|coin| coin.type_script_hash == NativeCurrency.hash());
        if let Some((idx, _)) = remove {
            self.coins[idx] = new_amount;
        } else {
            self.coins.push(new_amount);
        };

        self
    }

    pub fn has_native_currency(&self) -> bool {
        self.coins
            .iter()
            .any(|coin| coin.type_script_hash == NativeCurrency.hash())
    }

    /// Return all type script hashes referenced by any coin in any UTXO,
    /// without duplicates.
    ///
    /// Always includes [`NativeCurrency`].
    pub fn type_script_hashes<'a, I: Iterator<Item = &'a Self>>(utxos: I) -> Vec<Digest> {
        vec![NativeCurrency.hash()]
            .into_iter()
            .chain(
                utxos
                    .into_iter()
                    .flat_map(|utxo| utxo.coins.iter().map(|c| c.type_script_hash).collect_vec()),
            )
            .unique()
            .collect()
    }

    /// Get the amount of native currency that are encapsulated in this UTXO,
    /// regardless of which other coins are present. (Even if that makes the
    /// native currency unspendable.)
    pub fn get_native_currency_amount(&self) -> NativeCurrencyAmount {
        self.coins
            .iter()
            .filter(|coin| coin.type_script_hash == NativeCurrency.hash())
            .map(|coin| match NativeCurrencyAmount::decode(&coin.state) {
                Ok(boxed_amount) => *boxed_amount,
                Err(_) => NativeCurrencyAmount::zero(),
            })
            .sum()
    }

    /// If the UTXO has a timelock, find out what the release date is.
    pub fn release_date(&self) -> Option<Timestamp> {
        self.coins.iter().find_map(Coin::release_date)
    }

    /// Test the coins for state validity, relative to known type scripts.
    pub fn all_type_script_states_are_valid(&self) -> bool {
        self.coins.iter().all(is_known_type_script_with_valid_state)
    }

    /// Determine if the UTXO can be spent at a given date in the future,
    /// assuming it can be unlocked. Currently, this boils down to checking
    /// whether it has a time lock and if it does, verifying that the release
    /// date is in the past.
    pub fn can_spend_at(&self, timestamp: Timestamp) -> bool {
        // unknown type script
        if !self.all_type_script_states_are_valid() {
            return false;
        }

        // decode and test release date(s) (if any)
        for coin in self
            .coins
            .iter()
            .filter(|c| c.type_script_hash == TimeLock.hash())
        {
            match Timestamp::decode(&coin.state) {
                Ok(release_date) => {
                    if timestamp <= *release_date {
                        return false;
                    }
                }
                Err(_) => {
                    return false;
                }
            };
        }

        true
    }

    /// Adds a time-lock coin, if necessary.
    ///
    /// Does nothing if there is a time lock present already whose release date
    /// is later than the argument.
    pub fn with_time_lock(self, release_date: Timestamp) -> Self {
        if self.release_date().is_some_and(|x| x >= release_date) {
            self
        } else {
            let mut coins = self
                .coins
                .into_iter()
                .filter(|c| c.type_script_hash != TimeLock.hash())
                .collect_vec();
            coins.push(TimeLock::until(release_date));
            Self {
                lock_script_hash: self.lock_script_hash,
                coins,
            }
        }
    }

    /// Determine whether there is a time-lock, with any release date, on the
    /// UTXO.
    pub fn is_timelocked(&self) -> bool {
        self.coins
            .iter()
            .filter_map(Coin::release_date)
            .any(|_| true)
    }
}

/// Make `Utxo` hashable with `StdHash` for using it in `HashMap`.
///
/// The Clippy warning is safe to suppress, because we do not violate the invariant: k1 == k2 => hash(k1) == hash(k2).
impl StdHash for Utxo {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        StdHash::hash(&self.encode(), state);
    }
}
