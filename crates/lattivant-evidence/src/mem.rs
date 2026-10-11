//! An in-memory evidence store.

use std::collections::HashMap;
use std::sync::Mutex;

use lattivant_event::TenantId;

use crate::reference::EvidenceRef;
use crate::{EvidenceStore, Verification};

/// An in-memory, tenant-scoped evidence store, suitable for tests and single-process use.
#[derive(Default)]
pub struct InMemoryEvidenceStore {
    // keyed by (tenant, reference hex) -> bytes
    blobs: Mutex<HashMap<(String, String), Vec<u8>>>,
}

impl InMemoryEvidenceStore {
    /// An empty store.
    pub fn new() -> Self {
        InMemoryEvidenceStore::default()
    }

    /// How many blobs are stored for a tenant.
    pub fn count(&self, tenant: &TenantId) -> usize {
        self.blobs
            .lock()
            .unwrap()
            .keys()
            .filter(|(t, _)| t == tenant.as_str())
            .count()
    }

    fn key(tenant: &TenantId, reference: &EvidenceRef) -> (String, String) {
        (tenant.as_str().to_string(), reference.hex().to_string())
    }
}

impl EvidenceStore for InMemoryEvidenceStore {
    fn put(&self, tenant: &TenantId, bytes: &[u8]) -> std::io::Result<EvidenceRef> {
        let reference = EvidenceRef::of(bytes);
        self.blobs
            .lock()
            .unwrap()
            .insert(Self::key(tenant, &reference), bytes.to_vec());
        Ok(reference)
    }

    fn get(&self, tenant: &TenantId, reference: &EvidenceRef) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.blobs.lock().unwrap().get(&Self::key(tenant, reference)).cloned())
    }

    fn verify(&self, tenant: &TenantId, reference: &EvidenceRef) -> std::io::Result<Verification> {
        Ok(match self.get(tenant, reference)? {
            None => Verification::Missing,
            Some(bytes) if reference.matches(&bytes) => Verification::Ok,
            Some(_) => Verification::Corrupt,
        })
    }

    fn delete(&self, tenant: &TenantId, reference: &EvidenceRef) -> std::io::Result<bool> {
        Ok(self
            .blobs
            .lock()
            .unwrap()
            .remove(&Self::key(tenant, reference))
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alpha() -> TenantId {
        TenantId::new("alpha")
    }

    #[test]
    fn put_get_round_trips() {
        let store = InMemoryEvidenceStore::new();
        let r = store.put(&alpha(), b"evidence bytes").unwrap();
        assert_eq!(store.get(&alpha(), &r).unwrap().as_deref(), Some(&b"evidence bytes"[..]));
        assert_eq!(store.verify(&alpha(), &r).unwrap(), Verification::Ok);
        assert_eq!(store.count(&alpha()), 1);
    }

    #[test]
    fn cross_tenant_fetch_is_isolated() {
        let store = InMemoryEvidenceStore::new();
        let r = store.put(&alpha(), b"alpha secret").unwrap();
        let bravo = TenantId::new("bravo");
        assert!(store.get(&bravo, &r).unwrap().is_none());
        assert_eq!(store.verify(&bravo, &r).unwrap(), Verification::Missing);
    }

    #[test]
    fn missing_and_delete() {
        let store = InMemoryEvidenceStore::new();
        let r = EvidenceRef::of(b"never stored");
        assert_eq!(store.verify(&alpha(), &r).unwrap(), Verification::Missing);
        assert!(!store.delete(&alpha(), &r).unwrap());
        let stored = store.put(&alpha(), b"x").unwrap();
        assert!(store.delete(&alpha(), &stored).unwrap());
        assert!(!store.exists(&alpha(), &stored).unwrap());
    }

    #[test]
    fn identical_content_dedups_to_one_blob() {
        let store = InMemoryEvidenceStore::new();
        let a = store.put(&alpha(), b"same").unwrap();
        let b = store.put(&alpha(), b"same").unwrap();
        assert_eq!(a, b);
        assert_eq!(store.count(&alpha()), 1);
    }
}
