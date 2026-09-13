//! Transaction contracts shared by the enclave adapter and local MVCC driver.
//! MemoryStorage is a development backend, never a substitute for CCF consensus.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("transaction conflicted; retry the complete operation")]
    Conflict,
    #[error("storage failure: {0}")]
    Backend(String),
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid encrypted snapshot")]
    InvalidSnapshot,
}
pub type Result<T> = std::result::Result<T, StorageError>;

/// CCF public collection names must be an explicit allowlist, never caller input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Collection {
    Zones,
    Records,
    Registrations,
    Grants,
    Nonces,
    RequestResults,
    AcmeChallenges,
    Policies,
    Lifecycle,
    SecondaryStatus,
    PrivateKeys,
    TsigSecrets,
}
impl Collection {
    pub const ALL: [Self; 12] = [
        Self::Zones,
        Self::Records,
        Self::Registrations,
        Self::Grants,
        Self::Nonces,
        Self::RequestResults,
        Self::AcmeChallenges,
        Self::Policies,
        Self::Lifecycle,
        Self::SecondaryStatus,
        Self::PrivateKeys,
        Self::TsigSecrets,
    ];
    pub fn ccf_name(self) -> &'static str {
        match self {
            Self::Zones => "public:agentdns.zones",
            Self::Records => "public:agentdns.records",
            Self::Registrations => "public:agentdns.registrations",
            Self::Grants => "public:agentdns.grants",
            Self::Nonces => "public:agentdns.nonces",
            Self::RequestResults => "public:agentdns.request_results",
            Self::AcmeChallenges => "public:agentdns.acme_challenges",
            Self::Policies => "public:agentdns.policies",
            Self::Lifecycle => "public:agentdns.lifecycle",
            Self::SecondaryStatus => "public:agentdns.secondary_status",
            Self::PrivateKeys => "agentdns.private_keys",
            Self::TsigSecrets => "agentdns.tsig_secrets",
        }
    }
    pub fn is_private(self) -> bool {
        matches!(self, Self::PrivateKeys | Self::TsigSecrets)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionedValue {
    pub version: u64,
    pub bytes: Vec<u8>,
}
pub type Entries = Vec<(Vec<u8>, VersionedValue)>;

pub trait ReadTx {
    fn get(&self, table: Collection, key: &[u8]) -> Result<Option<VersionedValue>>;
    fn scan_prefix(&self, table: Collection, prefix: &[u8]) -> Result<Entries>;
}
pub trait WriteTx: ReadTx {
    fn put(&mut self, table: Collection, key: Vec<u8>, value: Vec<u8>) -> Result<()>;
    fn remove(&mut self, table: Collection, key: &[u8]) -> Result<()>;
}
/// Discardable application writes over one live transaction. Dropping the
/// overlay changes no backend rows; flush only after the application succeeds.
/// If flushing returns an error, the caller must discard the entire backend
/// transaction because the backend may already contain a partial write set.
pub struct WriteOverlay<'a, T: WriteTx> {
    base: &'a mut T,
    writes: BTreeMap<(Collection, Vec<u8>), Option<Vec<u8>>>,
}
impl<'a, T: WriteTx> WriteOverlay<'a, T> {
    pub fn new(base: &'a mut T) -> Self {
        Self {
            base,
            writes: BTreeMap::new(),
        }
    }
    pub fn flush(self) -> Result<()> {
        for ((table, key), value) in self.writes {
            match value {
                Some(value) => self.base.put(table, key, value)?,
                None => self.base.remove(table, &key)?,
            }
        }
        Ok(())
    }
}
impl<T: WriteTx> ReadTx for WriteOverlay<'_, T> {
    fn get(&self, table: Collection, key: &[u8]) -> Result<Option<VersionedValue>> {
        match self.writes.get(&(table, key.to_vec())) {
            Some(value) => Ok(value.as_ref().map(|bytes| VersionedValue {
                version: 0,
                bytes: bytes.clone(),
            })),
            None => self.base.get(table, key),
        }
    }
    fn scan_prefix(&self, table: Collection, prefix: &[u8]) -> Result<Entries> {
        let mut rows: BTreeMap<_, _> = self.base.scan_prefix(table, prefix)?.into_iter().collect();
        for ((t, key), value) in &self.writes {
            if *t != table || !key.starts_with(prefix) {
                continue;
            }
            match value {
                Some(bytes) => {
                    rows.insert(
                        key.clone(),
                        VersionedValue {
                            version: 0,
                            bytes: bytes.clone(),
                        },
                    );
                }
                None => {
                    rows.remove(key);
                }
            }
        }
        Ok(rows.into_iter().collect())
    }
}
impl<T: WriteTx> WriteTx for WriteOverlay<'_, T> {
    fn put(&mut self, table: Collection, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.writes.insert((table, key), Some(value));
        Ok(())
    }
    fn remove(&mut self, table: Collection, key: &[u8]) -> Result<()> {
        self.writes.insert((table, key.to_vec()), None);
        Ok(())
    }
}
/// A backend returns a consistent read snapshot and isolated optimistic writer.
pub trait DnsStorage {
    type Reader: ReadTx;
    type Writer: WriteTx;
    fn read(&self) -> Result<Self::Reader>;
    fn write(&self) -> Result<Self::Writer>;
}
pub fn get_json<T: DeserializeOwned>(
    tx: &impl ReadTx,
    table: Collection,
    key: &[u8],
) -> Result<Option<T>> {
    tx.get(table, key)?
        .map(|v| serde_json::from_slice(&v.bytes).map_err(Into::into))
        .transpose()
}
pub fn put_json<T: Serialize>(
    tx: &mut impl WriteTx,
    table: Collection,
    key: Vec<u8>,
    value: &T,
) -> Result<()> {
    tx.put(table, key, serde_json::to_vec(value)?)
}
/// Length-delimited binary composite keys avoid separator ambiguity and support
/// prefix scans of whole components. Component count is deliberately not encoded.
pub fn composite_key(components: &[&[u8]]) -> Vec<u8> {
    let mut key = Vec::new();
    for c in components {
        key.extend_from_slice(&(c.len() as u64).to_be_bytes());
        key.extend_from_slice(c);
    }
    key
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct State {
    revision: u64,
    tables: BTreeMap<Collection, BTreeMap<Vec<u8>, VersionedValue>>,
}
#[derive(Clone, Default)]
pub struct MemoryStorage {
    inner: Arc<RwLock<Arc<State>>>,
}
#[derive(Clone)]
pub struct MemoryRead {
    state: Arc<State>,
}
pub struct MemoryWrite {
    store: MemoryStorage,
    base: Arc<State>,
    writes: BTreeMap<(Collection, Vec<u8>), Option<Vec<u8>>>,
}
impl DnsStorage for MemoryStorage {
    type Reader = MemoryRead;
    type Writer = MemoryWrite;
    fn read(&self) -> Result<MemoryRead> {
        Ok(MemoryRead {
            state: self
                .inner
                .read()
                .map_err(|_| StorageError::Backend("poisoned lock".into()))?
                .clone(),
        })
    }
    fn write(&self) -> Result<MemoryWrite> {
        Ok(MemoryWrite {
            store: self.clone(),
            base: self.read()?.state,
            writes: BTreeMap::new(),
        })
    }
}
impl ReadTx for MemoryRead {
    fn get(&self, t: Collection, k: &[u8]) -> Result<Option<VersionedValue>> {
        Ok(self.state.tables.get(&t).and_then(|m| m.get(k)).cloned())
    }
    fn scan_prefix(&self, t: Collection, p: &[u8]) -> Result<Entries> {
        Ok(self
            .state
            .tables
            .get(&t)
            .map(|m| {
                m.range(p.to_vec()..)
                    .take_while(|(k, _)| k.starts_with(p))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }
}
impl ReadTx for MemoryWrite {
    fn get(&self, t: Collection, k: &[u8]) -> Result<Option<VersionedValue>> {
        if let Some(v) = self.writes.get(&(t, k.to_vec())) {
            return Ok(v.as_ref().map(|bytes| VersionedValue {
                version: 0,
                bytes: bytes.clone(),
            }));
        }
        MemoryRead {
            state: self.base.clone(),
        }
        .get(t, k)
    }
    fn scan_prefix(&self, t: Collection, p: &[u8]) -> Result<Entries> {
        let mut m: BTreeMap<_, _> = MemoryRead {
            state: self.base.clone(),
        }
        .scan_prefix(t, p)?
        .into_iter()
        .collect();
        for ((table, k), v) in &self.writes {
            if *table == t && k.starts_with(p) {
                if let Some(bytes) = v {
                    m.insert(
                        k.clone(),
                        VersionedValue {
                            version: 0,
                            bytes: bytes.clone(),
                        },
                    );
                } else {
                    m.remove(k);
                }
            }
        }
        Ok(m.into_iter().collect())
    }
}
impl WriteTx for MemoryWrite {
    fn put(&mut self, t: Collection, k: Vec<u8>, v: Vec<u8>) -> Result<()> {
        self.writes.insert((t, k), Some(v));
        Ok(())
    }
    fn remove(&mut self, t: Collection, k: &[u8]) -> Result<()> {
        self.writes.insert((t, k.to_vec()), None);
        Ok(())
    }
}
impl MemoryWrite {
    /// Atomically publishes this local transaction. Does not claim CCF commitment.
    pub fn commit(self) -> Result<u64> {
        let mut guard = self
            .store
            .inner
            .write()
            .map_err(|_| StorageError::Backend("poisoned lock".into()))?;
        if guard.revision != self.base.revision {
            return Err(StorageError::Conflict);
        }
        if self.writes.is_empty() {
            return Ok(guard.revision);
        }
        let revision = guard
            .revision
            .checked_add(1)
            .ok_or_else(|| StorageError::Backend("revision exhausted".into()))?;
        let mut state = (**guard).clone();
        state.revision = revision;
        for ((table, key), value) in self.writes {
            let map = state.tables.entry(table).or_default();
            if let Some(bytes) = value {
                map.insert(
                    key,
                    VersionedValue {
                        version: revision,
                        bytes,
                    },
                );
            } else {
                map.remove(&key);
            }
        }
        *guard = Arc::new(state);
        Ok(revision)
    }
}
impl MemoryRead {
    pub fn revision(&self) -> u64 {
        self.state.revision
    }
}

/// Sealed local recovery image. Callers provision the 256-bit key separately.
/// CCF production recovery uses the CCF encrypted ledger and recovery protocol.
impl MemoryStorage {
    pub fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        use ring::{
            aead,
            rand::{SecureRandom, SystemRandom},
        };
        let state = self.read()?;
        // Maps contain binary keys, so encode as a vector instead of JSON objects.
        let entries: Vec<_> = state
            .state
            .tables
            .iter()
            .flat_map(|(t, m)| m.iter().map(move |(k, v)| (*t, k.clone(), v.clone())))
            .collect();
        let mut data = serde_json::to_vec(&(state.revision(), entries))?;
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| StorageError::InvalidSnapshot)?;
        let cipher = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, key)
                .map_err(|_| StorageError::InvalidSnapshot)?,
        );
        cipher
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(b"agentdns.local.snapshot.v1"),
                &mut data,
            )
            .map_err(|_| StorageError::InvalidSnapshot)?;
        let mut out = b"ADNSMV01".to_vec();
        out.extend(nonce);
        out.extend(data);
        Ok(out)
    }
    pub fn restore(image: &[u8], key: &[u8; 32]) -> Result<Self> {
        use ring::aead;
        if image.len() < 36 || &image[..8] != b"ADNSMV01" {
            return Err(StorageError::InvalidSnapshot);
        }
        let nonce: [u8; 12] = image[8..20]
            .try_into()
            .map_err(|_| StorageError::InvalidSnapshot)?;
        let cipher = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, key)
                .map_err(|_| StorageError::InvalidSnapshot)?,
        );
        let mut data = image[20..].to_vec();
        let plain = cipher
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(b"agentdns.local.snapshot.v1"),
                &mut data,
            )
            .map_err(|_| StorageError::InvalidSnapshot)?;
        type Image = (u64, Vec<(Collection, Vec<u8>, VersionedValue)>);
        let (revision, entries): Image = serde_json::from_slice(plain)?;
        let mut state = State {
            revision,
            ..State::default()
        };
        for (t, k, v) in entries {
            if v.version > revision || state.tables.entry(t).or_default().insert(k, v).is_some() {
                return Err(StorageError::InvalidSnapshot);
            }
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(Arc::new(state))),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discardable_overlay_isolates_reads_deletions_and_flush() {
        let db = MemoryStorage::default();
        let mut tx = db.write().unwrap();
        tx.put(Collection::Records, b"a/1".to_vec(), b"old".to_vec())
            .unwrap();
        tx.put(Collection::Records, b"a/2".to_vec(), b"keep".to_vec())
            .unwrap();
        tx.commit().unwrap();
        let mut tx = db.write().unwrap();
        {
            let mut overlay = WriteOverlay::new(&mut tx);
            overlay.remove(Collection::Records, b"a/1").unwrap();
            overlay
                .put(Collection::Records, b"a/3".to_vec(), b"new".to_vec())
                .unwrap();
            overlay
                .put(Collection::Nonces, b"a/1".to_vec(), b"separate".to_vec())
                .unwrap();
            assert!(overlay.get(Collection::Records, b"a/1").unwrap().is_none());
            assert_eq!(
                overlay
                    .scan_prefix(Collection::Records, b"a/")
                    .unwrap()
                    .iter()
                    .map(|(k, _)| k.clone())
                    .collect::<Vec<_>>(),
                vec![b"a/2".to_vec(), b"a/3".to_vec()]
            );
        }
        assert_eq!(
            tx.get(Collection::Records, b"a/1").unwrap().unwrap().bytes,
            b"old"
        );
        assert!(tx.get(Collection::Nonces, b"a/1").unwrap().is_none());
        assert!(tx.get(Collection::Records, b"a/3").unwrap().is_none());
        let mut overlay = WriteOverlay::new(&mut tx);
        overlay.remove(Collection::Records, b"a/1").unwrap();
        overlay
            .put(Collection::Records, b"a/3".to_vec(), b"new".to_vec())
            .unwrap();
        overlay.flush().unwrap();
        assert!(
            db.read()
                .unwrap()
                .get(Collection::Records, b"a/1")
                .unwrap()
                .is_some()
        );
        tx.commit().unwrap();
        let read = db.read().unwrap();
        assert!(read.get(Collection::Records, b"a/1").unwrap().is_none());
        assert_eq!(
            read.get(Collection::Records, b"a/3")
                .unwrap()
                .unwrap()
                .bytes,
            b"new"
        );
    }
    #[test]
    fn caller_discards_backend_transaction_after_partial_overlay_flush_failure() {
        struct FailSecondWrite {
            inner: MemoryWrite,
            writes: usize,
        }
        impl ReadTx for FailSecondWrite {
            fn get(&self, t: Collection, k: &[u8]) -> Result<Option<VersionedValue>> {
                self.inner.get(t, k)
            }
            fn scan_prefix(&self, t: Collection, p: &[u8]) -> Result<Entries> {
                self.inner.scan_prefix(t, p)
            }
        }
        impl WriteTx for FailSecondWrite {
            fn put(&mut self, t: Collection, k: Vec<u8>, v: Vec<u8>) -> Result<()> {
                self.writes += 1;
                if self.writes == 2 {
                    return Err(StorageError::Backend(
                        "injected second write failure".into(),
                    ));
                }
                self.inner.put(t, k, v)
            }
            fn remove(&mut self, t: Collection, k: &[u8]) -> Result<()> {
                self.inner.remove(t, k)
            }
        }
        let db = MemoryStorage::default();
        let mut failing = FailSecondWrite {
            inner: db.write().unwrap(),
            writes: 0,
        };
        let mut overlay = WriteOverlay::new(&mut failing);
        overlay
            .put(
                Collection::Records,
                b"first".to_vec(),
                b"tentative".to_vec(),
            )
            .unwrap();
        overlay
            .put(Collection::Records, b"second".to_vec(), b"fails".to_vec())
            .unwrap();
        assert!(matches!(overlay.flush(), Err(StorageError::Backend(_))));
        assert_eq!(
            failing
                .get(Collection::Records, b"first")
                .unwrap()
                .unwrap()
                .bytes,
            b"tentative"
        );
        // A backend transaction may now contain partial writes. The adapter
        // must discard that whole transaction, never commit its first row.
        drop(failing);
        assert!(
            db.read()
                .unwrap()
                .scan_prefix(Collection::Records, b"")
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn atomic_conflict_and_snapshot_isolation() {
        let db = MemoryStorage::default();
        let old = db.read().unwrap();
        let mut a = db.write().unwrap();
        let mut b = db.write().unwrap();
        a.put(Collection::Nonces, b"n".to_vec(), b"used".to_vec())
            .unwrap();
        a.put(Collection::RequestResults, b"r".to_vec(), b"ok".to_vec())
            .unwrap();
        assert!(
            db.read()
                .unwrap()
                .get(Collection::Nonces, b"n")
                .unwrap()
                .is_none()
        );
        assert_eq!(a.commit().unwrap(), 1);
        b.put(Collection::Records, vec![1], vec![2]).unwrap();
        assert!(matches!(b.commit(), Err(StorageError::Conflict)));
        assert!(old.get(Collection::Nonces, b"n").unwrap().is_none());
        let new = db.read().unwrap();
        assert_eq!(
            new.get(Collection::Nonces, b"n").unwrap().unwrap().version,
            new.get(Collection::RequestResults, b"r")
                .unwrap()
                .unwrap()
                .version
        );
    }
    #[test]
    fn recovery_preserves_private_and_replay_state_and_detects_tamper() {
        let db = MemoryStorage::default();
        let mut tx = db.write().unwrap();
        tx.put(Collection::PrivateKeys, vec![0], vec![42]).unwrap();
        tx.put(Collection::Nonces, vec![1], vec![2]).unwrap();
        tx.commit().unwrap();
        let mut sealed = db.seal(&[3; 32]).unwrap();
        let restored = MemoryStorage::restore(&sealed, &[3; 32]).unwrap();
        assert_eq!(
            restored
                .read()
                .unwrap()
                .get(Collection::PrivateKeys, &[0])
                .unwrap()
                .unwrap()
                .bytes,
            vec![42]
        );
        assert!(MemoryStorage::restore(&sealed, &[4; 32]).is_err());
        sealed[25] ^= 1;
        assert!(MemoryStorage::restore(&sealed, &[3; 32]).is_err());
    }
    #[test]
    fn prefix_scan_overlays_deletions_and_private_names_are_private() {
        let db = MemoryStorage::default();
        let mut tx = db.write().unwrap();
        for s in ["a/1", "a/2", "b/1"] {
            tx.put(Collection::Records, s.as_bytes().to_vec(), vec![])
                .unwrap();
        }
        tx.commit().unwrap();
        let mut tx = db.write().unwrap();
        tx.remove(Collection::Records, b"a/1").unwrap();
        assert_eq!(tx.scan_prefix(Collection::Records, b"a/").unwrap().len(), 1);
        for t in Collection::ALL {
            assert_eq!(!t.ccf_name().starts_with("public:"), t.is_private());
        }
        assert_ne!(
            composite_key(&[b"a|b", b"c"]),
            composite_key(&[b"a", b"b|c"])
        );
    }
}
