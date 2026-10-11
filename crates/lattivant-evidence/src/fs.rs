//! A filesystem-backed evidence store.
//!
//! Blobs are written under `root/<tenant>/<hash[0:2]>/<hash>`. The two-character fan-out
//! keeps directories small; the tenant segment enforces isolation at the path level as well
//! as in the API.

use std::fs;
use std::path::{Path, PathBuf};

use lattivant_event::TenantId;

use crate::reference::EvidenceRef;
use crate::{EvidenceStore, Verification};

/// A content-addressed evidence store backed by a directory tree.
pub struct FsEvidenceStore {
    root: PathBuf,
}

impl FsEvidenceStore {
    /// Open (creating if needed) a store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(FsEvidenceStore { root })
    }

    /// Sanitize a tenant id into a safe single path segment.
    fn tenant_segment(tenant: &TenantId) -> String {
        tenant
            .as_str()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect()
    }

    fn path(&self, tenant: &TenantId, reference: &EvidenceRef) -> PathBuf {
        let hex = reference.hex();
        self.root
            .join(Self::tenant_segment(tenant))
            .join(&hex[..2])
            .join(hex)
    }
}

impl EvidenceStore for FsEvidenceStore {
    fn put(&self, tenant: &TenantId, bytes: &[u8]) -> std::io::Result<EvidenceRef> {
        let reference = EvidenceRef::of(bytes);
        let path = self.path(tenant, &reference);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Write to a temp file then rename, so a reader never sees a partial blob.
        let tmp = path.with_extension("part");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &path)?;
        Ok(reference)
    }

    fn get(&self, tenant: &TenantId, reference: &EvidenceRef) -> std::io::Result<Option<Vec<u8>>> {
        let path = self.path(tenant, reference);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn verify(&self, tenant: &TenantId, reference: &EvidenceRef) -> std::io::Result<Verification> {
        Ok(match self.get(tenant, reference)? {
            None => Verification::Missing,
            Some(bytes) if reference.matches(&bytes) => Verification::Ok,
            Some(_) => Verification::Corrupt,
        })
    }

    fn delete(&self, tenant: &TenantId, reference: &EvidenceRef) -> std::io::Result<bool> {
        let path = self.path(tenant, reference);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// A unique temporary directory for a test, removed when dropped.
#[doc(hidden)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a fresh temp directory.
    pub fn new(label: &str) -> std::io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("lattivant-{label}-{nanos}-{n}"));
        fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }

    /// The directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alpha() -> TenantId {
        TenantId::new("alpha")
    }

    #[test]
    fn put_get_verify_on_disk() {
        let dir = TempDir::new("evidence").unwrap();
        let store = FsEvidenceStore::open(dir.path()).unwrap();
        let r = store.put(&alpha(), b"a request/response capture").unwrap();
        assert_eq!(
            store.get(&alpha(), &r).unwrap().as_deref(),
            Some(&b"a request/response capture"[..])
        );
        assert_eq!(store.verify(&alpha(), &r).unwrap(), Verification::Ok);
    }

    #[test]
    fn corruption_is_detected() {
        let dir = TempDir::new("evidence").unwrap();
        let store = FsEvidenceStore::open(dir.path()).unwrap();
        let r = store.put(&alpha(), b"original").unwrap();
        // tamper with the stored file
        let path = store.path(&alpha(), &r);
        fs::write(&path, b"tampered").unwrap();
        assert_eq!(store.verify(&alpha(), &r).unwrap(), Verification::Corrupt);
    }

    #[test]
    fn tenant_isolation_on_disk() {
        let dir = TempDir::new("evidence").unwrap();
        let store = FsEvidenceStore::open(dir.path()).unwrap();
        let r = store.put(&alpha(), b"alpha-only").unwrap();
        assert!(store.get(&TenantId::new("bravo"), &r).unwrap().is_none());
    }

    #[test]
    fn tenant_id_is_sanitized_into_a_single_segment() {
        assert_eq!(FsEvidenceStore::tenant_segment(&TenantId::new("a/../b")), "a____b");
    }

    #[test]
    fn delete_removes_the_file() {
        let dir = TempDir::new("evidence").unwrap();
        let store = FsEvidenceStore::open(dir.path()).unwrap();
        let r = store.put(&alpha(), b"x").unwrap();
        assert!(store.delete(&alpha(), &r).unwrap());
        assert_eq!(store.verify(&alpha(), &r).unwrap(), Verification::Missing);
    }
}
