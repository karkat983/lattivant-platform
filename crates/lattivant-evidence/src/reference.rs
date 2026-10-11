//! Content-addressed evidence references.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A reference to a stored blob: the SHA-256 of its content, rendered as hex.
///
/// The reference *is* the integrity proof: a blob can be checked against it by re-hashing.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// Lowercase hex SHA-256 of the content.
    hex: String,
}

impl EvidenceRef {
    /// Compute the reference for some bytes.
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        EvidenceRef {
            hex: hex::encode(hasher.finalize()),
        }
    }

    /// The hex digest.
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// The `evidence://sha256/<hex>` URI form.
    pub fn uri(&self) -> String {
        format!("evidence://sha256/{}", self.hex)
    }

    /// Parse a reference from a URI or a bare hex string.
    pub fn parse(s: &str) -> Option<Self> {
        let hex = s.strip_prefix("evidence://sha256/").unwrap_or(s);
        if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(EvidenceRef {
                hex: hex.to_ascii_lowercase(),
            })
        } else {
            None
        }
    }

    /// Whether `bytes` hash to this reference.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        EvidenceRef::of(bytes) == *self
    }
}

impl std::fmt::Display for EvidenceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.uri())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_is_content_addressed() {
        let a = EvidenceRef::of(b"hello");
        let b = EvidenceRef::of(b"hello");
        let c = EvidenceRef::of(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.matches(b"hello"));
        assert!(!a.matches(b"world"));
    }

    #[test]
    fn uri_round_trips() {
        let r = EvidenceRef::of(b"x");
        assert!(r.uri().starts_with("evidence://sha256/"));
        assert_eq!(EvidenceRef::parse(&r.uri()), Some(r.clone()));
        assert_eq!(EvidenceRef::parse(r.hex()), Some(r));
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert_eq!(EvidenceRef::parse("evidence://sha256/short"), None);
        assert_eq!(EvidenceRef::parse("not a hash"), None);
        assert_eq!(EvidenceRef::parse(&"z".repeat(64)), None);
    }
}
