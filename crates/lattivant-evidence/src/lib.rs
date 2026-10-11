//! Content-addressed evidence storage.
//!
//! Investigations must be reproducible, which means the raw bytes behind a finding or event
//! have to be retrievable and verifiable. This crate stores evidence by the SHA-256 of its
//! content — so a stored blob's id *is* a proof of its content — scopes every blob to a
//! tenant (a cross-tenant fetch returns nothing), and can [`EvidenceStore::verify`] that a
//! stored blob still matches its reference.
//!
//! Two backends are provided: an in-memory store for tests and embedding, and a
//! filesystem store for a real deployment.

pub mod fs;
pub mod mem;
pub mod reference;

pub use fs::FsEvidenceStore;
pub use mem::InMemoryEvidenceStore;
pub use reference::EvidenceRef;

use lattivant_event::TenantId;

/// The result of verifying a stored blob against its reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// Present and the content hash matches the reference.
    Ok,
    /// No blob is stored for the reference in this tenant.
    Missing,
    /// A blob is stored but its content no longer hashes to the reference.
    Corrupt,
}

/// A tenant-scoped, content-addressed blob store.
pub trait EvidenceStore {
    /// Store `bytes` for `tenant`, returning the content-addressed reference.
    fn put(&self, tenant: &TenantId, bytes: &[u8]) -> std::io::Result<EvidenceRef>;

    /// Fetch the bytes for `reference` in `tenant`, or `None` if absent (including when the
    /// blob exists only in another tenant).
    fn get(&self, tenant: &TenantId, reference: &EvidenceRef) -> std::io::Result<Option<Vec<u8>>>;

    /// Verify a stored blob's integrity.
    fn verify(&self, tenant: &TenantId, reference: &EvidenceRef) -> std::io::Result<Verification>;

    /// Delete a stored blob. Returns whether something was removed.
    fn delete(&self, tenant: &TenantId, reference: &EvidenceRef) -> std::io::Result<bool>;

    /// Whether a blob exists for `reference` in `tenant`.
    fn exists(&self, tenant: &TenantId, reference: &EvidenceRef) -> std::io::Result<bool> {
        Ok(self.get(tenant, reference)?.is_some())
    }
}
