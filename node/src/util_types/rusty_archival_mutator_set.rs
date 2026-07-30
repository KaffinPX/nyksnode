use tasm_lib::twenty_first::tip5::digest::Digest;

use super::archival_mutator_set::ArchivalMutatorSet;
use crate::util_types::archival_mmr::ArchivalMmr;
use nyks_consensus::mutator_set::active_window::ActiveWindow;
use nyks_consensus::mutator_set::removal_record::chunk::Chunk;
use nyks_database::storage::storage_schema::traits::*;
use nyks_database::storage::storage_schema::DbtSingleton;
use nyks_database::storage::storage_schema::DbtVec;
use nyks_database::storage::storage_schema::RustyKey;
use nyks_database::storage::storage_schema::RustyValue;
use nyks_database::storage::storage_schema::SimpleRustyStorage;
use nyks_database::NeptuneLevelDb;

type AmsMmrStorage = DbtVec<Digest>;
type AmsChunkStorage = DbtVec<Chunk>;

#[derive(Debug)]
pub struct RustyArchivalMutatorSet {
    ams: ArchivalMutatorSet<AmsMmrStorage, AmsChunkStorage>,
    storage: SimpleRustyStorage,
    active_window_storage: DbtSingleton<Vec<u32>>,
    sync_label: DbtSingleton<Digest>,
}

impl RustyArchivalMutatorSet {
    pub async fn connect(db: NeptuneLevelDb<RustyKey, RustyValue>) -> Self {
        let mut storage = SimpleRustyStorage::new_with_callback(
            db,
            "RustyArchivalMutatorSet-Schema",
            crate::LOG_TOKIO_LOCK_EVENT_CB,
        );

        let aocl = storage.schema.new_vec::<Digest>("aocl").await;
        let swbfi = storage.schema.new_vec::<Digest>("swbfi").await;
        let chunks = storage.schema.new_vec::<Chunk>("chunks").await;
        let active_window = storage
            .schema
            .new_singleton::<Vec<u32>>("active_window")
            .await;
        let sync_label = storage.schema.new_singleton::<Digest>("sync_label").await;

        let ams = ArchivalMutatorSet::<AmsMmrStorage, AmsChunkStorage> {
            chunks,
            aocl: ArchivalMmr::<AmsMmrStorage>::new(aocl).await,
            swbf_inactive: ArchivalMmr::<AmsMmrStorage>::new(swbfi).await,
            swbf_active: ActiveWindow::new(),
        };

        Self {
            ams,
            storage,
            sync_label,
            active_window_storage: active_window,
        }
    }

    #[inline]
    pub fn ams(&self) -> &ArchivalMutatorSet<AmsMmrStorage, AmsChunkStorage> {
        &self.ams
    }

    #[inline]
    pub fn ams_mut(&mut self) -> &mut ArchivalMutatorSet<AmsMmrStorage, AmsChunkStorage> {
        &mut self.ams
    }

    #[inline]
    pub fn get_sync_label(&self) -> Digest {
        self.sync_label.get()
    }

    #[inline]
    pub async fn set_sync_label(&mut self, sync_label: Digest) {
        self.sync_label.set(sync_label).await;
    }

    pub async fn restore_or_new(&mut self) {
        // The field `digests` of ArchivalMMR should always have at
        // least one element (a dummy digest), owing to 1-indexation.
        self.ams_mut().aocl.fix_dummy_async().await;
        self.ams_mut().swbf_inactive.fix_dummy_async().await;

        // populate active window
        self.ams_mut().swbf_active.sbf = self.active_window_storage.get();
    }
}

impl StorageWriter for RustyArchivalMutatorSet {
    async fn persist(&mut self) {
        self.active_window_storage
            .set(self.ams().swbf_active.sbf.clone())
            .await;

        self.storage.persist().await;
    }

    async fn drop_unpersisted(&mut self) {
        self.ams_mut().swbf_active.sbf = self.active_window_storage.get();
        self.storage.drop_unpersisted().await;
        self.ams_mut().aocl.delete_cache().await;
        self.ams_mut().swbf_inactive.delete_cache().await;
        self.ams_mut().chunks.delete_cache().await;
    }
}
