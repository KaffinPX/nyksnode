use std::sync::Arc;
use std::time::Duration;

use num_traits::Zero;
use nyks_protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::http::HttpClient;
use tokio::sync::RwLock;
use tracing::info;

use crate::miner::guesser::Guesser;

#[derive(Clone, Debug)]
pub struct Miner {
    client: HttpClient,
    address: String,
    guesser_reward: Arc<RwLock<NativeCurrencyAmount>>,
    guesser: Guesser,
}

impl Miner {
    pub fn new(client: HttpClient, address: String) -> Self {
        Miner {
            client: client.clone(),
            address,
            guesser_reward: Arc::new(RwLock::new(NativeCurrencyAmount::zero())),
            guesser: Guesser::new(client),
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
            let new_guesser_reward = template.metadata.total_guesser_reward.0;
            let mut current_guesser_reward = self.guesser_reward.write().await;

            if new_guesser_reward > *current_guesser_reward {
                info!(
                    "Switching to mining of new template with {} NYKS reward.",
                    new_guesser_reward
                );
                *current_guesser_reward = new_guesser_reward;

                self.guesser
                    .override_task(template.metadata.prev_block, template)
                    .await;
            }
        } else if self.guesser.is_running().await {
            info!("New tip is found, waiting for a composed template...");

            *self.guesser_reward.write().await = NativeCurrencyAmount::zero();
            self.guesser.stop().await;
        }
    }
}
