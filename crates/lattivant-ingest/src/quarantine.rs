//! Quarantine for events that cannot be accepted.
//!
//! Ingestion never silently drops input. An event that fails to parse or validate is kept
//! here with the reason and its raw bytes, so an operator can inspect bad producers and so no
//! signal is lost to a schema bug. Quarantine is tenant-scoped where a tenant could be
//! determined; input that could not even be parsed is filed under [`UNKNOWN_TENANT`].

use chrono::{DateTime, Utc};

/// Where unparseable input is filed when no tenant could be extracted.
pub const UNKNOWN_TENANT: &str = "_unknown";

/// Why an event was quarantined rather than accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuarantineReason {
    /// The raw bytes were not valid JSON.
    Unparseable(String),
    /// Parsed, but failed envelope validation.
    Invalid(String),
    /// Parsed and valid, but the payload exceeded a configured size limit.
    TooLarge {
        /// Observed size in bytes.
        size: usize,
        /// The configured maximum.
        limit: usize,
    },
}

impl QuarantineReason {
    /// A short, stable category label for metrics and reporting.
    pub fn category(&self) -> &'static str {
        match self {
            QuarantineReason::Unparseable(_) => "unparseable",
            QuarantineReason::Invalid(_) => "invalid",
            QuarantineReason::TooLarge { .. } => "too_large",
        }
    }
}

impl std::fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuarantineReason::Unparseable(e) => write!(f, "unparseable: {e}"),
            QuarantineReason::Invalid(e) => write!(f, "invalid: {e}"),
            QuarantineReason::TooLarge { size, limit } => {
                write!(f, "too large: {size} bytes exceeds limit {limit}")
            }
        }
    }
}

/// A quarantined item: the reason, the raw input, and when it was quarantined.
#[derive(Clone, Debug)]
pub struct QuarantinedEvent {
    /// The tenant the input was filed under, or [`UNKNOWN_TENANT`].
    pub tenant: String,
    /// Why it was quarantined.
    pub reason: QuarantineReason,
    /// The raw input bytes, preserved verbatim for inspection.
    pub raw: Vec<u8>,
    /// When it was quarantined.
    pub at: DateTime<Utc>,
}

/// An in-memory quarantine buffer.
#[derive(Default)]
pub struct Quarantine {
    items: std::sync::Mutex<Vec<QuarantinedEvent>>,
}

impl Quarantine {
    /// An empty quarantine.
    pub fn new() -> Self {
        Quarantine::default()
    }

    /// File an item.
    pub fn file(&self, tenant: impl Into<String>, reason: QuarantineReason, raw: &[u8]) {
        self.items.lock().unwrap().push(QuarantinedEvent {
            tenant: tenant.into(),
            reason,
            raw: raw.to_vec(),
            at: Utc::now(),
        });
    }

    /// Total quarantined items.
    pub fn len(&self) -> usize {
        self.items.lock().unwrap().len()
    }

    /// Whether the quarantine is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Count of quarantined items in a category.
    pub fn count_category(&self, category: &str) -> usize {
        self.items
            .lock()
            .unwrap()
            .iter()
            .filter(|q| q.reason.category() == category)
            .count()
    }

    /// A snapshot of all quarantined items for a tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<QuarantinedEvent> {
        self.items
            .lock()
            .unwrap()
            .iter()
            .filter(|q| q.tenant == tenant)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_are_stable() {
        assert_eq!(QuarantineReason::Unparseable("x".into()).category(), "unparseable");
        assert_eq!(QuarantineReason::Invalid("x".into()).category(), "invalid");
        assert_eq!(
            QuarantineReason::TooLarge { size: 9, limit: 4 }.category(),
            "too_large"
        );
    }

    #[test]
    fn filing_is_tenant_scoped_and_counted() {
        let q = Quarantine::new();
        q.file("alpha", QuarantineReason::Invalid("missing engine".into()), b"{}");
        q.file(UNKNOWN_TENANT, QuarantineReason::Unparseable("eof".into()), b"{");
        assert_eq!(q.len(), 2);
        assert_eq!(q.count_category("invalid"), 1);
        assert_eq!(q.for_tenant("alpha").len(), 1);
        assert_eq!(q.for_tenant(UNKNOWN_TENANT).len(), 1);
    }
}
