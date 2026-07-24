use nyks_protocol::consensus::block::Block;
use nyks_prover::{JobCancelReceiver, JobCancelSender, ProverJobSettings};
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::composer::prover::block::{BlockProver, BlockProverError};
use crate::composer::prover::transaction::{TransactionProver, TransactionProverError};
use crate::core::args::Args;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::http::HttpClient;

#[derive(Debug, Error)]
pub enum BlockBuilderError {
    #[error("cancelled")]
    Cancelled,

    #[error(transparent)]
    Transaction(#[from] TransactionProverError),

    #[error(transparent)]
    Block(#[from] BlockProverError),
}

/// Coordinates `TransactionProver` and `BlockProver` into a single build
/// pipeline. Call `start()` to spawn a background task, `halt()` to cancel it.
pub struct BlockBuilder {
    args: Args,
    client: HttpClient,
    job_settings: ProverJobSettings,
    cancel_tx: Option<JobCancelSender>,
    handle: Option<JoinHandle<()>>,
}

impl BlockBuilder {
    pub fn new(args: Args, client: HttpClient, job_settings: ProverJobSettings) -> Self {
        Self {
            args,
            client,
            job_settings,
            cancel_tx: None,
            handle: None,
        }
    }

    /// Returns true if a build task is currently running.
    pub fn is_running(&self) -> bool {
        self.handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }

    /// Spawns the build pipeline in a background task.
    /// If a task is already running it is halted first.
    pub async fn start(&mut self) {
        if self.is_running() {
            self.halt().await;
        }

        let (cancel_tx, cancel_rx) = watch::channel(());

        let mut tx_prover = TransactionProver::new(
            self.args.clone(),
            self.client.clone(),
            self.job_settings.clone(),
        );
        let mut block_prover = BlockProver::new(self.args.clone(), self.job_settings.clone());

        let client = self.client.clone();

        let handle = tokio::spawn(async move {
            match Self::run_pipeline(&mut tx_prover, &mut block_prover, &client, cancel_rx).await {
                Err(e) if !matches!(e, BlockBuilderError::Cancelled) => {
                    warn!("Building template failed: {e}!");
                }
                _ => {}
            }
        });

        self.cancel_tx = Some(cancel_tx);
        self.handle = Some(handle);
    }

    /// Cancels the running pipeline and waits for it to stop.
    /// No-op if nothing is running.
    pub async fn halt(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }

    async fn run_pipeline(
        tx_prover: &mut TransactionProver,
        block_prover: &mut BlockProver,
        client: &HttpClient,
        rx: JobCancelReceiver,
    ) -> Result<(), BlockBuilderError> {
        // Always compose on the freshest tip.
        let composing_tip: Block = client.tip().await.unwrap().block.into();

        tx_prover.set_tip(composing_tip.clone());
        block_prover.set_tip(composing_tip.clone());

        let transaction = tx_prover
            .prepare_block_transaction(rx.clone())
            .await
            .map_err(|e| match e {
                TransactionProverError::Cancelled => BlockBuilderError::Cancelled,
                other => BlockBuilderError::Transaction(other),
            })?;
        let timestamp = transaction.kernel.timestamp;
        let block = block_prover
            .compose_block(transaction, timestamp, rx)
            .await
            .map_err(|e| match e {
                BlockProverError::Cancelled => BlockBuilderError::Cancelled,
                other => BlockBuilderError::Block(other),
            })?;

        match client.submit_block_template((&block).into()).await {
            Ok(response) => match response.success {
                true => info!("Block template submitted successfully!"),
                false => warn!("Block template submission failed: channel error."),
            },
            Err(e) => warn!("Block template submission failed: {e}."),
        }

        Ok(())
    }
}
