use num_traits::CheckedSub;
use nyks_standards::wallet::keys::{address::Recipient, key::KeyType};
use nyks_wallet_sdk::wallet::Wallet;

/// Everything the dashboard shows, refreshed on a timer so draw code never
/// has to `.await` a wallet call.
pub struct Snapshot {
    pub height: String,
    pub tip_height: String,
    pub total_balance: String,
    pub spendable_balance: String,
    pub timelocked_balance: String,
    pub unconfirmed_balance: String,
    pub outgoing_balance: String,
    pub utxo_count: usize,
    pub generation_address: String,
    pub symmetric_address: String,
}

impl Snapshot {
    pub async fn fetch(wallet: &Wallet) -> Self {
        let total_balance = wallet.total_balance().await;
        let spendable_balance = wallet.spendable_balance().await;
        let timelocked_balance = total_balance
            .checked_sub(&spendable_balance)
            .unwrap_or(total_balance);

        Snapshot {
            height: wallet.height().await.to_string(),
            tip_height: wallet.tip_height().await.to_string(),
            total_balance: total_balance.to_string(),
            spendable_balance: spendable_balance.to_string(),
            timelocked_balance: timelocked_balance.to_string(),
            unconfirmed_balance: wallet.unconfirmed_balance().await.to_string(),
            outgoing_balance: wallet.outgoing_balance().await.to_string(),
            utxo_count: wallet.utxo_count().await,
            generation_address: wallet
                .address(KeyType::Generation)
                .await
                .to_bech32m(wallet.network),
            symmetric_address: wallet
                .address(KeyType::Symmetric)
                .await
                .to_bech32m(wallet.network),
        }
    }
}
