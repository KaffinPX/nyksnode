use num_traits::Zero;
use nyks_consensus::mutator_set::addition_record::AdditionRecord;
use nyks_consensus::mutator_set::commit;
use nyks_consensus::network::Network;
use nyks_consensus::tasm_lib::prelude::Digest;
use nyks_consensus::tasm_lib::prelude::Tip5;
use nyks_consensus::tasm_lib::twenty_first::bfe_array;
use nyks_consensus::transaction::utxo::Coin;
use nyks_consensus::transaction::utxo::Utxo;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

use crate::BFieldElement;
use crate::wallet::keys::address::Address;
use crate::wallet::keys::address::Recipient;

#[derive(Debug, Clone)]
pub struct Allocations {
    network: Network,
    entries: Vec<(Address, NativeCurrencyAmount)>,
}

impl Allocations {
    pub fn genesis(network: Network) -> Allocations {
        Self {
          network,
          entries: vec![
            (Address::from_bech32m("nsymam1jcarsuxtz7fsyzmtpzjgpqzvunlu6d2h74vpagmxfxr5tehgnttaaph3tgyjf8qf20625w4tnqycqhzksw38rtcpqst69xsr9z9cxzv20t99yxvemk7le6h4r6nz95l9gvzkuk", Network::Main).unwrap(), NativeCurrencyAmount::coins(50000)),
            (Address::from_bech32m("nsymat1rge9uhc7mwqn82fwaw5nkrnj2vafsz9myntxk3vpe6deh008h6qa3lwjghkktcx9j28zzqlcra7uek8gegt5pxfkghcunjafdepfpufkkumxwp4z257gxr8vajr3yqu0jtkfzy", Network::Testnet(0)).unwrap(), NativeCurrencyAmount::coins(50000))
        ]}
    }

    pub fn total(&self) -> NativeCurrencyAmount {
        self.entries
            .iter()
            .fold(NativeCurrencyAmount::zero(), |acc, (_, amount)| {
                acc + *amount
            })
    }

    pub fn utxos(&self) -> impl Iterator<Item = Utxo> + '_ {
        self.entries.iter().map(|(receiving_address, amount)| {
            let coins = vec![Coin::new_native_currency(*amount)];
            Utxo::new(receiving_address.lock_script().hash(), coins)
        })
    }

    pub fn sender_randomness(&self) -> Digest {
        Digest::new(bfe_array![u64::from(self.network.id()), 0, 0, 0, 0])
    }

    pub fn addition_records(&self) -> Vec<AdditionRecord> {
        self.entries
            .iter()
            .zip(self.utxos())
            .map(|((addr, _), utxo)| {
                commit(
                    Tip5::hash(&utxo),
                    self.sender_randomness(),
                    addr.privacy_digest(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use nyks_consensus::block::Block;

    use super::*;

    #[test]
    fn allocations_match_with_genesis_allocations() {
        // Create genesis allocations
        let allocations = Allocations::genesis(Network::Testnet(0));

        let total = allocations.total();
        assert!(total > NativeCurrencyAmount::zero(), "Total should be > 0"); // Make sure it matches our emission schedule

        let utxos = allocations.utxos();
        assert_eq!(
            utxos.collect::<Vec<_>>().len(),
            allocations.entries.len(),
            "UTXO count mismatch"
        );

        let addition_records = allocations.addition_records();
        assert_eq!(
            addition_records.len(),
            allocations.entries.len(),
            "Addition records count mismatch"
        );

        let commitments: Vec<Digest> = addition_records
            .clone()
            .into_iter()
            .map(|a| a.canonical_commitment)
            .collect();
        for commitment in commitments {
            println!("{}", commitment.to_hex());
        }

        let genesis_block = Block::genesis(Network::Main);
        let genesis_addition_records = genesis_block.all_addition_records().unwrap();

        assert_eq!(addition_records, genesis_addition_records);
    }
}
