use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use nyks_consensus::block::block_height::BlockHeight;
use nyks_standards::wallet::keys::key::KeyType;
use nyks_wallet_sdk::state::utxos::utxo::MonitoredUtxo;
use nyks_wallet_sdk::state::utxos::utxo::UtxoKey;
use serde::Deserialize;
use serde::Serialize;

// ---------------------------------------------------------------------------
// Directory layout inside <root>:
//
//   keys.json          – KeysData  { external, internal, mnemonic }
//   chain.json         – ChainData { height }
//   utxos/
//     <leaf>-<digest>.json   – LockedUtxo (one file per UTXO)
// ---------------------------------------------------------------------------

/// Write `contents` to `path` atomically via a `.tmp` sibling + `rename`.
///
/// Readers always see either the previous complete file or the new complete
/// file — never a partial write. `sync_all` ensures bytes reach the device
/// before the rename commits, guarding against crash-after-rename data loss.
fn atomic_write(path: &Path, contents: &[u8]) {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)
            .unwrap_or_else(|e| panic!("failed to create {}: {e}", tmp.display()));
        f.write_all(contents)
            .unwrap_or_else(|e| panic!("failed to write {}: {e}", tmp.display()));
        f.sync_all()
            .unwrap_or_else(|e| panic!("failed to sync {}: {e}", tmp.display()));
    }
    fs::rename(&tmp, path).unwrap_or_else(|e| {
        panic!(
            "failed to rename {} → {}: {e}",
            tmp.display(),
            path.display()
        )
    });
}

/// Deserialize a JSON file into `T`. Panics if the file is absent or corrupt.
fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("corrupt {}: {e}", path.display()))
}

/// Deserialize a JSON file into `T`, returning `T::default()` if the file is absent.
fn read_json_or_default<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> T {
    if path.exists() {
        read_json(path)
    } else {
        T::default()
    }
}

/// Serialize `value` to `path` atomically.
fn write_json<T: Serialize>(path: &Path, value: &T) {
    let raw = serde_json::to_string_pretty(value).expect("serialization failed");
    atomic_write(path, raw.as_bytes());
}

pub struct Storage {
    pub keys: KeysStore,
    pub utxos: UtxosStore,
    pub chain: ChainStore,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(&root).expect("failed to create storage root");
        fs::create_dir_all(root.join("utxos")).expect("failed to create utxos dir");

        Storage {
            keys: KeysStore::new(root.join("keys.json")),
            utxos: UtxosStore::new(root.join("utxos")),
            chain: ChainStore::new(root.join("chain.json")),
        }
    }
}

/// Typed on-disk representation for `keys.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct KeysData {
    generation_index: u64,
    symmetric_index: u64,
    mnemonic: Option<String>,
}

pub struct KeysStore {
    path: PathBuf,
}

impl KeysStore {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn read(&self) -> KeysData {
        read_json_or_default(&self.path)
    }

    fn write(&self, data: &KeysData) {
        write_json(&self.path, data);
    }

    /// Returns the next derivation index (stored index + 1) for display.
    pub fn next_index(&self, key: KeyType) -> u64 {
        let data = self.read();
        match key {
            KeyType::Generation => data.generation_index + 1,
            KeyType::Symmetric => data.symmetric_index + 1,
        }
    }

    pub fn increment(&self, key: KeyType) {
        let mut data = self.read();
        match key {
            KeyType::Generation => data.generation_index += 1,
            KeyType::Symmetric => data.symmetric_index += 1,
        }
        self.write(&data);
    }

    pub fn set_mnemonic(&self, mnemonic: &str) {
        let mut data = self.read();
        data.mnemonic = Some(mnemonic.to_owned());
        self.write(&data);
    }

    pub fn get_mnemonic(&self) -> Option<String> {
        self.read().mnemonic
    }
}

pub struct UtxosStore {
    dir: PathBuf,
}

impl UtxosStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn file_stem(key: &UtxoKey) -> String {
        format!(
            "{}-{:x}",
            key.aocl_index, key.addition_record.canonical_commitment
        )
    }

    fn file_path(&self, key: &UtxoKey) -> PathBuf {
        self.dir.join(format!("{}.json", Self::file_stem(key)))
    }

    pub fn get(&self, key: &UtxoKey) -> Option<MonitoredUtxo> {
        let path = self.file_path(key);
        path.exists().then(|| read_json(&path))
    }

    /// Inserts a UTXO. Returns `true` if newly inserted, `false` if it
    /// already existed (mirrors the original `fetch_update` / `is_none` semantics).
    pub fn put(&self, key: &UtxoKey, utxo: &MonitoredUtxo) -> bool {
        let path = self.file_path(key);
        let is_new = !path.exists();
        write_json(&path, utxo);
        is_new
    }

    pub fn remove(&self, key: &UtxoKey) {
        let path = self.file_path(key);
        if path.exists() {
            fs::remove_file(&path).expect("failed to remove utxo file");
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = MonitoredUtxo> {
        fs::read_dir(&self.dir)
            .expect("failed to read utxos dir")
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                if path.extension()? != "json" {
                    return None;
                }
                let utxo = read_json(&path);
                Some(utxo)
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// Typed on-disk representation for `chain.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ChainData {
    height: u64,
}

pub struct ChainStore {
    path: PathBuf,
}

impl ChainStore {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn set_height(&self, height: BlockHeight) {
        write_json(
            &self.path,
            &ChainData {
                height: height.value(),
            },
        );
    }

    pub fn get_height(&self) -> Option<BlockHeight> {
        if self.path.exists() {
            Some(read_json::<ChainData>(&self.path).height.into())
        } else {
            None
        }
    }
}
