use std::fmt::Debug;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::Arc;

use nyks_locks::tokio::AtomicRw;
use nyks_locks::tokio::LockCallbackFn;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::storage::storage_schema::DbtMap;

use super::traits::*;
use super::DbtSingleton;
use super::DbtVec;
use super::PendingWrites;
use super::SimpleRustyReader;

/// Provides a virtual database schema.
///
/// `DbtSchema` can create any number of instances of types that
/// implement the trait [`DbTable`].  We refer to these instances as
/// `table`.  Examples are [`DbtVec`], [`DbtSingleton`], and [`DbtMap`].
///
/// With proper usage (below), the application can perform writes
/// to any subset of the `table`s and then persist (write) the data
/// atomically to the database.
///
/// Thus we get something like relational database transactions using `LevelDB`
/// key/val store.
///
/// Important!  Operations over multiple `table`s are NOT atomic
/// without additional locking by the application.
///
/// This can be achieved by placing the `table`s into a heterogenous
/// container such as a `struct` or `tuple`. Then place an
/// `Arc<Mutex<..>>` or `Arc<Mutex<RwLock<..>>` around the container.
/// This crate provides [`AtomicRw`] and
/// [`AtomicMutex`](crate::application::locks::tokio::AtomicMutex)
/// which are simple wrappers around `Arc<RwLock<T>>` and `Arc<Mutex<T>>`.
///
/// This is the recommended usage.
#[derive(Debug)]
pub struct DbtSchema {
    /// Pending writes for all tables in this Schema.
    /// These get written/cleared by StorageWriter::persist()
    ///
    /// todo: Can we get rid of this lock?
    pub(super) pending_writes: AtomicRw<PendingWrites>,

    /// Database Reader
    pub reader: Arc<SimpleRustyReader>,

    /// If present, the provided callback function will be called
    /// whenever a lock is acquired by a `DbTable` instantiated
    /// by this `DbtSchema`.  See [AtomicRw]
    pub lock_callback_fn: Option<LockCallbackFn>,

    /// indicates count of tables in this schema
    pub table_count: u8,
}

impl DbtSchema {
    /// Instantiate a `DbtSchema` from a `SimpleRustyReader` and
    /// optional `name` and lock acquisition callback.
    /// See [AtomicRw]
    pub fn new(
        reader: SimpleRustyReader,
        name: Option<&str>,
        lock_callback_fn: Option<LockCallbackFn>,
    ) -> Self {
        Self {
            pending_writes: AtomicRw::from((PendingWrites::default(), name, lock_callback_fn)),
            reader: Arc::new(reader),
            lock_callback_fn,
            table_count: 0,
        }
    }

    /// Create a new DbtVec
    ///
    /// All pending write operations of the DbtVec are stored
    /// in the schema
    #[inline]
    pub async fn new_vec<V>(&mut self, name: &str) -> DbtVec<V>
    where
        V: Clone + 'static,
        V: Serialize + DeserializeOwned + Send + Sync,
    {
        let pending_writes = self.pending_writes.clone();
        let reader = self.reader.clone();
        let key_prefix = self.table_count;
        self.table_count += 1;

        let mut vector = DbtVec::<V>::new(pending_writes, reader, key_prefix, name).await;
        vector.restore_or_new().await;

        vector
    }

    /// Create a new DbtSingleton
    ///
    /// All pending write operations of the DbtSingleton are stored
    /// in the schema
    #[inline]
    pub async fn new_singleton<V>(&mut self, name: impl Into<String> + Display) -> DbtSingleton<V>
    where
        V: Default + Clone + 'static,
        V: Serialize + DeserializeOwned + Send + Sync,
    {
        let key = self.table_count;
        self.table_count += 1;

        let mut singleton = DbtSingleton::<V>::new(
            key,
            self.pending_writes.clone(),
            self.reader.clone(),
            name.into(),
        );
        singleton.restore_or_new().await;
        singleton
    }

    /// Create a new DbtMap
    ///
    /// All pending write operations of the DbtMap are stored
    /// in the schema
    pub async fn new_map<K, V>(&mut self, name: &str) -> DbtMap<K, V>
    where
        K: Clone + Debug + Serialize + DeserializeOwned + Eq + Hash + Send + Sync,
        V: Clone + Debug + Serialize + DeserializeOwned + Send + Sync,
    {
        let key_prefixes = [self.table_count, self.table_count + 1];
        self.table_count += 2;
        let mut map = DbtMap::<K, V>::new(
            self.pending_writes.clone(),
            self.reader.clone(),
            key_prefixes,
            name,
        )
        .await;
        map.restore_or_new().await;
        map
    }
}
