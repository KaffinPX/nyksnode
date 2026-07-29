use std::sync::Arc;
use std::time::{Duration, Instant};

use num_traits::Zero;
use nyks_protocol::consensus::block::Block;
use nyks_protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::http::HttpClient;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::miner::guesser::Guesser;

#[derive(Clone, Debug)]
pub struct Miner {
    client: HttpClient,
    address: String,
    min_reward_fraction: f64,
    guesser_reward: Arc<RwLock<NativeCurrencyAmount>>,
    guesser: Guesser,
    composing_since: Arc<RwLock<Option<Instant>>>,
}

impl Miner {
    pub fn new(client: HttpClient, address: String, min_reward_fraction: f64) -> Self {
        Miner {
            client: client.clone(),
            address,
            min_reward_fraction,
            guesser_reward: Arc::new(RwLock::new(NativeCurrencyAmount::zero())),
            guesser: Guesser::new(client),
            composing_since: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn main_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            self.scan_templates().await;
        }
    }

    pub async fn scan_templates(&self) {
        let template = self
            .client
            .get_block_template(Some(self.address.clone()))
            .await
            .unwrap()
            .template;

        if let Some(template) = template {
            // If we were waiting on a template, capture how long composing took
            let composing_time = {
                let mut composing_since = self.composing_since.write().await;
                composing_since
                    .take()
                    .map(|start| start.elapsed().as_secs_f64())
            };

            let new_guesser_reward = template.metadata.total_guesser_reward.0;
            let total_reward = Block::block_subsidy(template.block.kernel.header.height);
            let guesser_share = new_guesser_reward.to_nau() as f64 / total_reward.to_nau() as f64;

            if guesser_share < self.min_reward_fraction {
                debug!(
                    "Skipping template: guesser share {:.2}% below minimum {:.2}%.",
                    guesser_share * 100.0,
                    self.min_reward_fraction * 100.0
                );
                return;
            }

            let mut current_guesser_reward = self.guesser_reward.write().await;

            if new_guesser_reward > *current_guesser_reward {
                match composing_time {
                    Some(secs) => info!(
                        "Switching to mining of new template with {} NYKS reward (composed in {:.2}s).",
                        new_guesser_reward, secs
                    ),
                    None => info!(
                        "Switching to mining of new template with {} NYKS reward.",
                        new_guesser_reward
                    ),
                }
                *current_guesser_reward = new_guesser_reward;

                self.guesser
                    .override_task(template.metadata.prev_block, template)
                    .await;
            }
        } else {
            {
                let mut composing_since = self.composing_since.write().await;
                if composing_since.is_none() {
                    info!("Waiting for a template...");
                    *composing_since = Some(Instant::now());
                }
            }

            if self.guesser.is_running().await {
                info!("New tip is found, waiting for a composed template...");
                *self.guesser_reward.write().await = NativeCurrencyAmount::zero();
                self.guesser.stop().await;
            }
        }
    }
}
