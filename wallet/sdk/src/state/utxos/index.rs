use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use nyks_consensus::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;

use crate::state::utxos::UtxoKey;

/// Cheap, independently-lockable index from a UTXO's absolute index set to
/// its pool key. Kept in sync with `UtxoPool` at every insert/evict.
#[derive(Clone, Default)]
pub struct UtxoIndex(Arc<RwLock<HashMap<AbsoluteIndexSet, UtxoKey>>>);

impl UtxoIndex {
    pub fn new() -> Self {
        UtxoIndex(Arc::new(RwLock::new(HashMap::new())))
    }

    pub async fn get(&self, idx: &AbsoluteIndexSet) -> Option<UtxoKey> {
        self.0.read().await.get(idx).copied()
    }

    pub(crate) async fn insert(&self, idx: AbsoluteIndexSet, key: UtxoKey) {
        self.0.write().await.insert(idx, key);
    }

    pub(crate) async fn remove(&self, idx: &AbsoluteIndexSet) {
        self.0.write().await.remove(idx);
    }
}
