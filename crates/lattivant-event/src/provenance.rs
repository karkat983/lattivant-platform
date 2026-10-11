//! Provenance: where an event came from and whether its claim is observed or inferred.

use serde::{Deserialize, Serialize};

/// Whether an event's core claim is directly observed or inferred by its producer.
///
/// The platform keeps these apart so a correlator never treats a producer's *conclusion*
/// (e.g. "this was an attack") as a *fact* with the same weight as a raw observation (e.g.
/// "this HTTP response had status 200").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assertion {
    /// Directly observed by the collector.
    Observed,
    /// Inferred/derived by the producer.
    Inferred,
}

/// Where an event came from, so every record is traceable to its collector and raw bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The collector or engine that produced the event.
    pub collector: String,
    /// A content-addressed reference to the raw evidence, if stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_ref: Option<String>,
    /// Whether the event's core claim is observed or inferred.
    pub assertion: Assertion,
}

impl Provenance {
    /// A provenance from `collector` with the given assertion and no raw reference.
    pub fn new(collector: impl Into<String>, assertion: Assertion) -> Self {
        Provenance {
            collector: collector.into(),
            raw_ref: None,
            assertion,
        }
    }

    /// Builder: attach a content-addressed raw-evidence reference.
    pub fn with_raw_ref(mut self, uri: impl Into<String>) -> Self {
        self.raw_ref = Some(uri.into());
        self
    }

    /// Whether the claim is observed (as opposed to inferred).
    pub fn is_observed(&self) -> bool {
        self.assertion == Assertion::Observed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_ref_omitted_when_absent() {
        let p = Provenance::new("authz", Assertion::Inferred);
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("raw_ref").is_none());
        assert_eq!(v["assertion"], "inferred");
    }

    #[test]
    fn with_raw_ref_present() {
        let p = Provenance::new("agenttrace", Assertion::Observed)
            .with_raw_ref("evidence://sha256/abc");
        assert!(p.is_observed());
        assert_eq!(p.raw_ref.as_deref(), Some("evidence://sha256/abc"));
    }
}
