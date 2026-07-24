pub mod updater;
pub mod upgrader;

use nyks_rpc_client::block::transaction_kernel::RpcTransactionKernelId;

use crate::upgrader::pipeline::updater::Updater;
use crate::upgrader::pipeline::upgrader::UpgraderQueue;

/// Anything that can be reaped against a live-mempool id set.
pub(crate) trait Reapable {
    async fn tracked_ids(&self) -> Vec<RpcTransactionKernelId>;
    async fn forget_transaction(&self, id: &RpcTransactionKernelId);
}

impl Reapable for UpgraderQueue {
    async fn tracked_ids(&self) -> Vec<RpcTransactionKernelId> {
        self.tracked_ids().await
    }

    async fn forget_transaction(&self, id: &RpcTransactionKernelId) {
        self.forget_transaction(id).await
    }
}

impl Reapable for Updater {
    async fn tracked_ids(&self) -> Vec<RpcTransactionKernelId> {
        self.tracked_ids().await
    }

    async fn forget_transaction(&self, id: &RpcTransactionKernelId) {
        self.forget_transaction(id).await
    }
}
