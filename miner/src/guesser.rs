use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use nyks_protocol::BFieldElement;
use nyks_protocol::consensus::block::block_header::BlockPow;
use nyks_protocol::consensus::block::pow::GuesserBuffer;
use nyks_protocol::consensus::block::pow::POW_MEMORY_TREE_HEIGHT;
use nyks_protocol::tasm_lib::prelude::Digest;
use nyks_protocol::tasm_lib::twenty_first::bfe_array;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::http::HttpClient;
use nyks_rpc_client::mining::template::RpcBlockTemplate;
use rand::Rng;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::info;
use tracing::warn;

// ~10 GB, shared via Arc rather than cloned per task.
#[derive(Debug)]
struct MinerBuffer {
    digest: Digest,
    buffer: Arc<GuesserBuffer<POW_MEMORY_TREE_HEIGHT>>,
}

// Holds the cancel flag so stop() can signal the blocking thread directly.
#[derive(Debug)]
struct MinerTask {
    template: RpcBlockTemplate,
    cancel: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

#[derive(Clone, Debug)]
pub struct Guesser {
    client: HttpClient,
    buffer: Arc<RwLock<Option<MinerBuffer>>>,
    task: Arc<RwLock<Option<MinerTask>>>,
}

impl Guesser {
    pub fn new(client: HttpClient) -> Self {
        Guesser {
            client,
            buffer: Arc::new(RwLock::new(None)),
            task: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn is_running(&self) -> bool {
        self.task.read().await.is_some()
    }

    pub async fn override_task(&self, prev_block_digest: Digest, template: RpcBlockTemplate) {
        self.stop().await;

        let guesser_buffer = self.get_or_recompute_buffer(prev_block_digest).await;
        info!(
            "Switching to mining template {}...",
            template.block.kernel.mast_hash().to_hex()
        );

        let client = self.client.clone();
        let task_template = template.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let task_cancel = Arc::clone(&cancel);

        let handle = tokio::spawn(async move {
            Self::run_mining_task(client, task_template, guesser_buffer, task_cancel).await;
        });

        *self.task.write().await = Some(MinerTask {
            template,
            cancel,
            handle,
        });
    }

    // Only recomputes when the chain tip changes.
    async fn get_or_recompute_buffer(
        &self,
        prev_block_digest: Digest,
    ) -> Arc<GuesserBuffer<POW_MEMORY_TREE_HEIGHT>> {
        let mut guard = self.buffer.write().await;

        let needs_recompute = guard
            .as_ref()
            .map(|b| b.digest != prev_block_digest)
            .unwrap_or(true);
        if needs_recompute {
            info!(
                "Computing guesser buffer for digest {}...",
                prev_block_digest.to_hex()
            );

            let new_buffer = Arc::new(BlockPow::preprocess(prev_block_digest));

            *guard = Some(MinerBuffer {
                digest: prev_block_digest,
                buffer: Arc::clone(&new_buffer),
            });
            new_buffer
        } else {
            Arc::clone(&guard.as_ref().unwrap().buffer)
        }
    }

    pub async fn stop(&self) {
        let mut guard = self.task.write().await;

        if let Some(task) = guard.take() {
            info!(
                "Stopping mining task for template {:x}...",
                task.template.block.kernel.mast_hash()
            );
            task.cancel.store(true, Ordering::Relaxed);
            let _ = task.handle.await;
        }
    }

    async fn run_mining_task(
        client: HttpClient,
        template: RpcBlockTemplate,
        guesser_buffer: Arc<GuesserBuffer<POW_MEMORY_TREE_HEIGHT>>,
        cancel: Arc<AtomicBool>,
    ) {
        let mining_template = template.clone();
        let mine_result =
            tokio::task::spawn_blocking(move || mine(&mining_template, &guesser_buffer, &cancel))
                .await;
        let pow = match mine_result {
            Ok(Some(pow)) => pow,

            Ok(None) => {
                info!("Mining stopped (cancelled or nonce space exhausted).");
                return;
            }

            Err(e) => {
                info!("Mining task panicked: {e}");
                return;
            }
        };

        info!("Found the solution! Submitting to node...");

        match client.submit_block(template.block, pow.into()).await {
            Ok(response) => {
                if response.success {
                    info!("Block is accepted by node.");
                } else {
                    warn!("Block is rejected by node, channel error.");
                }
            }
            Err(e) => {
                // TODO: RETRY
                warn!("Block is rejected by node, reason: {}", e);
            }
        }
    }
}

// Parallel nonce search. Returns None if cancelled or exhausted.
fn mine(
    template: &RpcBlockTemplate,
    guesser_buffer: &GuesserBuffer<POW_MEMORY_TREE_HEIGHT>,
    cancel: &AtomicBool,
) -> Option<BlockPow> {
    // Check for cancellation every ~500k nonces rather than every iteration.
    const CHECKPOINT_DISTANCE: u64 = 1 << 19;

    let index_picker_preimage =
        guesser_buffer.index_picker_preimage(&template.metadata.pow_mast_paths);

    // Each mining run gets its own random 256‑bit prefix on nonce space.
    let mut rng = rand::rng();
    let n0: u64 = rng.random();
    let n1: u64 = rng.random();
    let n2: u64 = rng.random();
    let n3: u64 = rng.random();

    info!(
        "Mining with nonce prefix [{:#018x}, {:#018x}, {:#018x}, {:#018x}]",
        n0, n1, n2, n3
    );

    (0u64..u64::MAX)
        .into_par_iter()
        .find_map_any(|i| {
            if i % CHECKPOINT_DISTANCE == 0 && cancel.load(Ordering::Relaxed) {
                return Some(None);
            }

            let nonce = Digest(bfe_array![n0, n1, n2, n3, i]);

            BlockPow::guess(
                guesser_buffer,
                &template.metadata.pow_mast_paths,
                index_picker_preimage,
                nonce,
                template.metadata.threshold,
            )
            .map(Some)
        })
        .flatten()
}
