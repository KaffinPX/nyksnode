use std::sync::Arc;
use std::time::Duration;

use nyks_prover::ProverJobSettings;
use nyks_rpc_client::RpcApi;
use nyks_rpc_client::http::HttpClient;
use tokio::sync::Mutex;
use tracing::info;

use crate::composer::builder::BlockBuilder;
use crate::core::args::Args;

#[derive(Clone)]
pub struct Composer {
    client: HttpClient,
    builder: Arc<Mutex<BlockBuilder>>,
}

impl Composer {
    pub fn new(args: Args, client: HttpClient) -> Self {
        Composer {
            client: client.clone(),
            builder: Arc::new(Mutex::new(BlockBuilder::new(
                args,
                client,
                ProverJobSettings::default(),
            ))),
        }
    }

    pub async fn main_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;
            self.scan_network().await;
        }
    }

    async fn scan_network(&self) {
        let best_proposal = self.client.get_block_template(None).await.unwrap().template;

        if let Some(_) = best_proposal {
            // A competing block already exists. If we're building, halt —
            // no point burning resources on a block that would lose.
            //
            // TODO: Check if our template would be cheaper, if yes compose...
            let mut builder = self.builder.lock().await;

            if builder.is_running() {
                info!("Competing proposal found, halting builder...");
                builder.halt().await;
            }
        } else {
            let mut builder = self.builder.lock().await;

            if !builder.is_running() {
                info!("No proposal found, starting builder...");
                builder.start().await;
            }
        }
    }
}
