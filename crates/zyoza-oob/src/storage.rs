use crate::crypto::OobEnvelope;
use crate::error::OobError;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

/// Pluggable storage backend for out-of-band encrypted Zyoza envelopes.
pub trait OobStorage: Send + Sync {
    /// Stores an `OobEnvelope` and returns its pointer URI (e.g., `mem://<hash>` or `file://...`).
    fn put(&self, envelope: &OobEnvelope) -> Result<String, OobError>;

    /// Fetches an `OobEnvelope` by its pointer URI.
    fn get(&self, uri: &str) -> Result<OobEnvelope, OobError>;
}

/// In-memory OOB storage backend for tests and local demos.
#[derive(Default)]
pub struct InMemoryStorage {
    blobs: Mutex<HashMap<String, OobEnvelope>>,
}

impl OobStorage for InMemoryStorage {
    fn put(&self, envelope: &OobEnvelope) -> Result<String, OobError> {
        let hash = envelope.pointer_hash()?;
        let uri = format!("mem://{}", hex::encode(hash));
        self.blobs
            .lock()
            .unwrap()
            .insert(uri.clone(), envelope.clone());
        Ok(uri)
    }

    fn get(&self, uri: &str) -> Result<OobEnvelope, OobError> {
        self.blobs
            .lock()
            .unwrap()
            .get(uri)
            .cloned()
            .ok_or_else(|| OobError::Storage(format!("not found: {uri}")))
    }
}

/// Local filesystem OOB storage backend persisting envelopes as JSON files.
pub struct LocalFsStorage {
    root: PathBuf,
}

impl LocalFsStorage {
    /// Creates a new `LocalFsStorage` rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, OobError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| OobError::Storage(format!("mkdir failed: {e}")))?;
        Ok(Self { root })
    }
}

impl OobStorage for LocalFsStorage {
    fn put(&self, envelope: &OobEnvelope) -> Result<String, OobError> {
        let hash = hex::encode(envelope.pointer_hash()?);
        let path = self.root.join(format!("{hash}.json"));
        let json = serde_json::to_vec_pretty(envelope)?;
        fs::write(&path, json).map_err(|e| OobError::Storage(format!("write failed: {e}")))?;
        Ok(format!("zyoza-fs://{hash}"))
    }

    fn get(&self, uri: &str) -> Result<OobEnvelope, OobError> {
        let hash = uri
            .strip_prefix("zyoza-fs://")
            .ok_or_else(|| OobError::Storage(format!("unsupported uri scheme: {uri}")))?;
        let path = self.root.join(format!("{hash}.json"));
        let data = fs::read(&path).map_err(|e| OobError::Storage(format!("read failed: {e}")))?;
        Ok(serde_json::from_slice(&data)?)
    }
}
