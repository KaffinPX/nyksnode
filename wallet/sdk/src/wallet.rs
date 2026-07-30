use std::sync::Arc;

use nyks_consensus::block::block_height::BlockHeight;
use nyks_consensus::network::Network;
use nyks_consensus::proof_abstractions::timestamp::Timestamp;
use nyks_consensus::transaction::Transaction;
use nyks_consensus::transaction::transaction_kernel_id::TransactionKernelId;
use nyks_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::RpcError;
use nyks_rpc_client::http::HttpClient;
use nyks_standards::wallet::keys::address::Address;
use nyks_standards::wallet::keys::address::Recipient;
use nyks_standards::wallet::keys::key::KeyType;
use nyks_standards::wallet::keys::key::Spender;

use nyks_wallet_core::entropy::wallet_entropy::WalletEntropy;
use nyks_wallet_core::transaction::builder::TransactionBuilder;
use nyks_wallet_core::transaction::builder::output::TxOutput;
use nyks_wallet_core::transaction::utxo::spendable::SpendableUtxo;
use thiserror::Error;
use tokio::sync::RwLock;

use crate::scanners::chain::AdvanceError;
use crate::scanners::chain::ChainScanner;
use crate::state::address_book::AddressBook;
use crate::state::utxos::pool::UtxoPool;
use crate::state::utxos::utxo::MonitoredUtxo;
use crate::state::utxos::utxo::UtxoKey;

const BATCH_SIZE: usize = 100;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),

    #[error("scanner advance failed: {0}")]
    Advance(#[from] AdvanceError),
}

/// Events emitted by the wallet as a result of chain-sync activity.
///
/// This is intentionally an enum (rather than just returning the raw utxo
/// pairs) so that future sync-driven activity (e.g. spent-utxo detection,
/// reorgs, balance-threshold crossings, etc.) can be represented without
/// changing the signature of `Wallet::sync`.
#[derive(Debug, Clone)]
pub enum WalletEvent {
    /// A new UTXO was discovered and added to the wallet's UTXO pool.
    UtxoReceived { key: UtxoKey, utxo: MonitoredUtxo },

    /// A previously-tracked UTXO was found to be spent (or otherwise
    /// invalid) while syncing membership proofs, and was evicted from the
    /// pool.
    UtxoInvalidated { key: UtxoKey, utxo: MonitoredUtxo },
}

impl WalletEvent {
    pub fn utxo_received(key: UtxoKey, utxo: MonitoredUtxo) -> Self {
        WalletEvent::UtxoReceived { key, utxo }
    }

    pub fn utxo_invalidated(key: UtxoKey, utxo: MonitoredUtxo) -> Self {
        WalletEvent::UtxoInvalidated { key, utxo }
    }
}

#[derive(Clone)]
pub struct Wallet {
    rpc: HttpClient,
    addresses: Arc<RwLock<AddressBook>>,
    scanner: Arc<RwLock<ChainScanner>>,
    utxos: Arc<RwLock<UtxoPool>>,
    pub network: Network,

    /// Events raised outside of `sync` (e.g. by `send`, when it evicts spent
    /// UTXOs) that haven't been handed to a caller yet. Drained and merged
    /// into the next `sync()` call's returned events.
    pending_events: Arc<RwLock<Vec<WalletEvent>>>,
}

impl Wallet {
    pub fn new(
        rpc: HttpClient,
        entropy: WalletEntropy,
        height: Option<BlockHeight>,
        network: Network,
    ) -> Self {
        let addresses = AddressBook::new(entropy);
        let view_keys = addresses.view_keys().to_vec();

        Wallet {
            rpc: rpc.clone(),
            addresses: Arc::new(RwLock::new(addresses)),
            scanner: Arc::new(RwLock::new(ChainScanner::new(
                height, None, view_keys, network,
            ))),
            utxos: Arc::new(RwLock::new(UtxoPool::new(rpc))),
            network,
            pending_events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    // Will panic if wallet cannot unlock any of these UTXOs
    pub async fn import_utxos(&self, utxos: Vec<MonitoredUtxo>) {
        self.unlock_utxos(utxos.clone()).await;

        let mut utxos_pool = self.utxos.write().await;

        for utxo in utxos {
            let is_unique = utxos_pool.import_utxo(utxo);
            assert!(is_unique);
        }
    }

    pub async fn tip_height(&self) -> BlockHeight {
        self.scanner.read().await.tip_height()
    }

    pub async fn height(&self) -> BlockHeight {
        self.scanner.read().await.height
    }

    pub async fn address(&self, key_type: KeyType) -> Address {
        self.addresses.read().await.latest(key_type)
    }

    pub async fn next_address(&self, key_type: KeyType) -> Address {
        let mut addresses = self.addresses.write().await;
        let mut scanner = self.scanner.write().await;

        let (address, view_key) = addresses.next_address(key_type);
        scanner.add_key(view_key);

        address
    }

    pub async fn utxo_count(&self) -> usize {
        self.utxos.read().await.utxo_count()
    }

    pub async fn spendable_balance(&self) -> NativeCurrencyAmount {
        self.utxos.read().await.spendable_balance()
    }

    pub async fn total_balance(&self) -> NativeCurrencyAmount {
        self.utxos.read().await.total_balance()
    }

    pub async fn unconfirmed_balance(&self) -> NativeCurrencyAmount {
        self.scanner.read().await.unconfirmed_balance()
    }

    /// Sync wallet forward by at most `BATCH_SIZE` blocks.
    ///
    /// Does not necessarily reach the current chain tip in one call, call
    /// repeatedly to fully catch up.
    ///
    /// Returns the [`WalletEvent`]s discovered during this batch, plus any
    /// events queued by other wallet operations since the last `sync` call
    /// (e.g. `UtxoInvalidated` events raised by `send`).
    ///
    /// # Important
    ///
    /// Must not be called concurrently, parallel calls will duplicate work.
    pub async fn sync(&self) -> Result<Vec<WalletEvent>, SyncError> {
        let network_height = self.rpc.height().await.unwrap().height;

        // Use scan_tip (including unconfirmed blocks) for both the check and the start height.
        let scan_tip = {
            let scanner = self.scanner.read().await;
            let tip = scanner.tip_height();
            if tip >= network_height {
                return Ok(self.drain_pending_events().await);
            }
            tip
        };

        let from = scan_tip.next();
        let to = {
            let end = from + (BATCH_SIZE - 1);
            if end > network_height {
                network_height
            } else {
                end
            }
        };

        let blocks = self.rpc.get_blocks(from, to).await?.blocks;
        let confirmed = {
            let mut scanner = self.scanner.write().await;
            scanner.advance(&blocks).map_err(SyncError::Advance)?
        };

        let keys = {
            let mut utxos = self.utxos.write().await;
            utxos.add_utxos(confirmed).await
        };

        let mut events = self.drain_pending_events().await;
        events.extend(
            keys.into_iter()
                .map(|(key, utxo)| WalletEvent::utxo_received(key, utxo)),
        );

        Ok(events)
    }

    /// Takes and returns all events queued by other operations (e.g. `send`)
    /// since the last drain, leaving the queue empty.
    async fn drain_pending_events(&self) -> Vec<WalletEvent> {
        std::mem::take(&mut *self.pending_events.write().await)
    }

    /// Builds, signs and submits a transaction sending `amount` to `recipient`.
    ///
    /// Returns the submitted transaction's kernel id. Any `UtxoInvalidated`
    /// events raised while selecting inputs (UTXOs found spent during
    /// proof-syncing) are queued and surfaced on the next call to
    /// [`Wallet::sync`], rather than returned here directly.
    pub async fn send(
        &self,
        recipient: Address,
        amount: NativeCurrencyAmount,
        fee: NativeCurrencyAmount,
    ) -> Result<TransactionKernelId, RpcError> {
        let height = self.tip_height().await;

        // Generate "spendable" UTXOs and prepare them for spending.
        let timestamp = Timestamp::now();
        let mut utxos = self.utxos.write().await;
        let selection = utxos.select_utxos(amount + fee, timestamp).await;
        drop(utxos);

        if !selection.invalidated_utxos.is_empty() {
            let mut pending = self.pending_events.write().await;
            pending.extend(
                selection
                    .invalidated_utxos
                    .into_iter()
                    .map(|(key, utxo)| WalletEvent::utxo_invalidated(key, utxo)),
            );
        }

        let inputs = self.unlock_utxos(selection.utxos).await;

        // Generate change address and randomnesses for outputs.
        let change_address = self.address(KeyType::Symmetric).await; // TODO: increment symmetric address count
        let (sender_randomness, change_sender_randomness) = {
            let addresses = self.addresses.read().await;
            let entropy = addresses.entropy();

            (
                entropy.generate_sender_randomness(height, recipient.privacy_digest()),
                entropy.generate_sender_randomness(height, change_address.privacy_digest()),
            )
        };

        let transaction = TransactionBuilder::new()
            .inputs(inputs.into())
            .outputs(
                vec![
                    TxOutput::onchain_native_currency(amount, sender_randomness, recipient),
                    TxOutput::onchain_native_currency_as_change(
                        selection.change,
                        change_sender_randomness,
                        self.address(KeyType::Symmetric).await,
                    ),
                ]
                .into(),
            )
            .fee(fee)
            .timestamp(timestamp)
            .mutator_set_accumulator(selection.msa)
            .build()
            .unwrap();
        let transaction = transaction.upgrade();
        let transaction: Transaction = transaction.try_into().unwrap();
        let transaction_kernel_id = transaction.txid();

        self.rpc.submit_transaction(transaction.into()).await?;

        Ok(transaction_kernel_id)
    }

    async fn unlock_utxos(&self, utxos: Vec<MonitoredUtxo>) -> Vec<SpendableUtxo> {
        let addresses = self.addresses.read().await;
        let mut unlocked = Vec::new();

        for utxo in utxos {
            let spending_key = addresses
                .spending_key(|address| address.lock_script().hash() == utxo.lock_script_hash())
                .expect("wallet cannot unlock utxo");

            let unlocked_utxo = SpendableUtxo::new(
                utxo.utxo,
                utxo.membership_proof,
                spending_key.lock_script_and_witness(),
            );

            unlocked.push(unlocked_utxo);
        }

        unlocked
    }
}
