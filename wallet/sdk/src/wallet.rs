use std::sync::Arc;

use num_traits::CheckedSub;
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
use crate::scanners::mempool::MempoolScanner;
use crate::state::address_book::AddressBook;
use crate::state::utxos::MonitoredUtxo;
use crate::state::utxos::UtxoKey;
use crate::state::utxos::pool::UtxoPool;

const BATCH_SIZE: usize = 100;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),

    #[error("scanner advance failed: {0}")]
    Advance(#[from] AdvanceError),
}

/// Events emitted by the wallet as a result of sync and scan activity.
#[derive(Debug, Clone)]
pub enum WalletEvent {
    /// A new UTXO was discovered and added to the wallet's UTXO pool.
    UtxoReceived { key: UtxoKey, utxo: MonitoredUtxo },

    /// A previously-tracked UTXO was found to be spent (or otherwise
    /// invalid) while syncing membership proofs, and was evicted from the
    /// pool.
    UtxoInvalidated { key: UtxoKey, utxo: MonitoredUtxo },

    /// A mempool transaction was found to spend one or more of the
    /// wallet's UTXOs. Emitted once per transaction, the first time it's
    /// observed as relevant.
    UtxosOutgoing {
        id: TransactionKernelId,
        utxos: Vec<UtxoKey>,
    },
}

impl WalletEvent {
    pub fn utxo_received(key: UtxoKey, utxo: MonitoredUtxo) -> Self {
        WalletEvent::UtxoReceived { key, utxo }
    }

    pub fn utxo_invalidated(key: UtxoKey, utxo: MonitoredUtxo) -> Self {
        WalletEvent::UtxoInvalidated { key, utxo }
    }

    pub fn utxos_outgoing(id: TransactionKernelId, utxos: Vec<UtxoKey>) -> Self {
        WalletEvent::UtxosOutgoing { id, utxos }
    }
}

#[derive(Clone)]
pub struct Wallet {
    rpc: HttpClient,
    addresses: Arc<RwLock<AddressBook>>,
    scanner: Arc<RwLock<ChainScanner>>,
    mempool_scanner: Arc<RwLock<MempoolScanner>>,
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
        let utxos = UtxoPool::new(rpc.clone());

        let view_keys = addresses.view_keys().to_vec();

        Wallet {
            rpc,
            addresses: Arc::new(RwLock::new(addresses)),
            scanner: Arc::new(RwLock::new(ChainScanner::new(
                height, None, view_keys, network,
            ))),
            mempool_scanner: Arc::new(RwLock::new(MempoolScanner::new(utxos.index()))),
            utxos: Arc::new(RwLock::new(utxos)),
            network,
            pending_events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    // Will panic if wallet cannot unlock any of these UTXOs
    pub async fn import_utxos(&self, utxos: Vec<MonitoredUtxo>) {
        self.unlock_utxos(utxos.clone()).await;

        let mut utxos_pool = self.utxos.write().await;

        for utxo in utxos {
            let is_unique = utxos_pool.import_utxo(utxo).await;
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

    pub async fn total_balance(&self) -> NativeCurrencyAmount {
        self.utxos.read().await.total_balance()
    }

    pub async fn spendable_balance(&self) -> NativeCurrencyAmount {
        let mempool_scanner = self.mempool_scanner.read().await;
        let pending_spend_utxos = mempool_scanner.pending_spend_utxos();

        let utxos = self.utxos.read().await;
        let spendable = utxos.spendable_balance();
        let outgoing = utxos.total_balance_from_utxos(pending_spend_utxos).await;

        spendable.checked_sub(&outgoing).unwrap()
    }

    pub async fn unconfirmed_balance(&self) -> NativeCurrencyAmount {
        self.scanner.read().await.unconfirmed_balance()
    }

    pub async fn outgoing_balance(&self) -> NativeCurrencyAmount {
        let mempool_scanner = self.mempool_scanner.read().await;
        let utxos = mempool_scanner.pending_spend_utxos();

        self.utxos
            .read()
            .await
            .total_balance_from_utxos(utxos)
            .await
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

        let mut events = self.drain_pending_events().await;

        events.extend(self.sync_mempool().await);

        if let Some(chain_events) = self.sync_chain(network_height).await? {
            events.extend(chain_events);
        }

        Ok(events)
    }

    /// Advances the chain scanner by at most `BATCH_SIZE` blocks (up to
    /// `network_height`) and updates the UTXO pool with any newly confirmed
    /// UTXOs.
    ///
    /// Returns `None` if the scanner is already caught up to
    /// `network_height`, in which case there is nothing to do. Otherwise
    /// returns the `UtxoReceived` events discovered in this batch (which may
    /// be empty).
    async fn sync_chain(
        &self,
        network_height: BlockHeight,
    ) -> Result<Option<Vec<WalletEvent>>, SyncError> {
        // Use scan_tip (including unconfirmed blocks) for both the check and the start height.
        let scan_tip = {
            let scanner = self.scanner.read().await;
            let tip = scanner.tip_height();
            if tip >= network_height {
                return Ok(None);
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

        Ok(Some(
            keys.into_iter()
                .map(|(key, utxo)| WalletEvent::utxo_received(key, utxo))
                .collect(),
        ))
    }

    /// Fetches the current mempool's transactions and feeds their kernels
    /// to the mempool scanner.
    async fn sync_mempool(&self) -> Vec<WalletEvent> {
        let mempool_txs = self.rpc.transactions().await.unwrap().transactions;
        let ids_to_fetch = self
            .mempool_scanner
            .read()
            .await
            .ids_to_fetch(&mempool_txs)
            .await;

        let mut kernels = Vec::with_capacity(ids_to_fetch.len());
        for id in ids_to_fetch {
            let kernel = self
                .rpc
                .get_transaction_kernel(id.clone())
                .await
                .unwrap()
                .kernel;
            if let Some(kernel) = kernel {
                kernels.push((id, kernel));
            }
        }

        let mut mempool_scanner = self.mempool_scanner.write().await;
        let outgoing_utxos = mempool_scanner.scan(kernels).await;

        // keep cache from growing unbounded as txs leave the mempool
        mempool_scanner.evict_stale(mempool_txs).await;

        outgoing_utxos
            .into_iter()
            .map(|(id, utxos)| WalletEvent::utxos_outgoing(id, utxos))
            .collect()
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
        let timestamp = Timestamp::now();

        // Generate "spendable" UTXOs and prepare them for spending.
        let mut utxos = self.utxos.write().await;
        let excluded_utxos = self
            .mempool_scanner
            .read()
            .await
            .pending_spend_utxos()
            .copied()
            .collect();
        let selection = utxos
            .select_utxos(amount + fee, timestamp, Some(excluded_utxos))
            .await;

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
