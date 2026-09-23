use std::time::Duration;

use nyks_wallet_sdk::wallet::Wallet;
use nyks_wallet_sdk::wallet::WalletEvent;
use tracing::info;

use crate::core::storage::Storage;

/// Runs the periodic sync loop: polls the wallet for new chain state,
/// persists discovered/invalidated UTXOs to storage, and updates the stored
/// chain height.
pub async fn run(wallet: Wallet, storage: Storage) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        interval.tick().await;

        let events = match wallet.sync().await {
            Ok(events) => events,
            Err(err) => {
                tracing::error!("sync failed: {err}");
                continue;
            }
        };

        for event in events {
            match event {
                WalletEvent::UtxoReceived { key, utxo } => {
                    match utxo.inclusion_block {
                        Some((_, block_height)) => info!(
                            "Discovered new UTXO containing {} NYKS on block {} (AOCL leaf {}).",
                            utxo.get_native_currency_amount(),
                            block_height,
                            utxo.membership_proof.aocl_leaf_index,
                        ),
                        None => info!(
                            "Discovered new UTXO containing {} NYKS (AOCL leaf {}).",
                            utxo.get_native_currency_amount(),
                            utxo.membership_proof.aocl_leaf_index,
                        ),
                    }

                    storage.utxos.put(&key, &utxo);
                }
                WalletEvent::UtxoInvalidated { key, utxo } => {
                    info!(
                        "UTXO containing {} NYKS was invalidated and marked as spent in an unknown block (AOCL leaf {}).",
                        utxo.get_native_currency_amount(),
                        utxo.membership_proof.aocl_leaf_index,
                    );

                    storage.utxos.put(&key, &utxo);
                }
                WalletEvent::UtxosOutgoing { id, utxos } => {
                    info!("{} UTXOs being spent on transaction {}.", utxos.len(), id);
                }
            }
        }

        storage.chain.set_height(wallet.height().await);
    }
}
