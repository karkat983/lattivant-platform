//! The ingestion pipeline.
//!
//! One entry point, [`Ingestor::ingest_bytes`], takes raw producer input and drives it through
//! four stages, in order:
//!
//! 1. **parse** — JSON → [`Event`]; failure quarantines the raw bytes as `Unparseable`.
//! 2. **size** — oversized payloads quarantine as `TooLarge` before any further work.
//! 3. **validate** — [`Event::validate`]; failure quarantines as `Invalid`.
//! 4. **dedup** — a repeat (by id or content) is acknowledged but not stored.
//!
//! Only an event that clears all four reaches the [`EventStore`]. Nothing is ever dropped
//! silently: every rejected input lands in the [`Quarantine`] with its reason and raw bytes.

use lattivant_event::Event;

use crate::dedup::{Dedup, DedupIndex};
use crate::quarantine::{Quarantine, QuarantineReason, UNKNOWN_TENANT};
use crate::store::EventStore;

/// The disposition of a single ingested input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// Accepted and stored. Carries the event id.
    Accepted(String),
    /// A duplicate; acknowledged but not stored again.
    Duplicate(Dedup),
    /// Rejected; the raw input was quarantined with this reason.
    Quarantined(QuarantineReason),
}

impl Disposition {
    /// Whether the input was newly stored.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Disposition::Accepted(_))
    }

    /// A short, stable label for metrics.
    pub fn label(&self) -> &'static str {
        match self {
            Disposition::Accepted(_) => "accepted",
            Disposition::Duplicate(_) => "duplicate",
            Disposition::Quarantined(_) => "quarantined",
        }
    }
}

/// Configuration for the pipeline.
#[derive(Debug, Clone)]
pub struct IngestConfig {
    /// Maximum accepted payload size in bytes. Larger inputs are quarantined.
    pub max_payload_bytes: usize,
}

impl Default for IngestConfig {
    fn default() -> Self {
        // 256 KiB is generous for a single event envelope; anything larger is suspect.
        IngestConfig {
            max_payload_bytes: 256 * 1024,
        }
    }
}

/// Running totals across a batch of ingested inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestStats {
    /// Newly stored events.
    pub accepted: usize,
    /// Recognized duplicates.
    pub duplicates: usize,
    /// Quarantined inputs.
    pub quarantined: usize,
}

impl IngestStats {
    /// Fold a disposition into the totals.
    pub fn record(&mut self, d: &Disposition) {
        match d {
            Disposition::Accepted(_) => self.accepted += 1,
            Disposition::Duplicate(_) => self.duplicates += 1,
            Disposition::Quarantined(_) => self.quarantined += 1,
        }
    }

    /// Total inputs seen.
    pub fn total(&self) -> usize {
        self.accepted + self.duplicates + self.quarantined
    }
}

/// The ingestion pipeline over a given store, dedup index and quarantine.
pub struct Ingestor<'a, S: EventStore> {
    store: &'a S,
    dedup: &'a DedupIndex,
    quarantine: &'a Quarantine,
    config: IngestConfig,
}

impl<'a, S: EventStore> Ingestor<'a, S> {
    /// Build a pipeline wiring the three stores together with default config.
    pub fn new(store: &'a S, dedup: &'a DedupIndex, quarantine: &'a Quarantine) -> Self {
        Ingestor {
            store,
            dedup,
            quarantine,
            config: IngestConfig::default(),
        }
    }

    /// Override the configuration.
    pub fn with_config(mut self, config: IngestConfig) -> Self {
        self.config = config;
        self
    }

    /// Ingest raw bytes (one JSON event). Never panics; every failure is quarantined.
    pub fn ingest_bytes(&self, raw: &[u8]) -> Disposition {
        // Stage 2 (size) runs first on raw bytes so a huge blob is cheap to reject.
        if raw.len() > self.config.max_payload_bytes {
            let reason = QuarantineReason::TooLarge {
                size: raw.len(),
                limit: self.config.max_payload_bytes,
            };
            // Try to recover a tenant for filing, but don't fail if we can't.
            let tenant = tenant_hint(raw).unwrap_or_else(|| UNKNOWN_TENANT.to_string());
            self.quarantine.file(tenant, reason.clone(), raw);
            return Disposition::Quarantined(reason);
        }

        // Stage 1: parse.
        let event: Event = match serde_json::from_slice(raw) {
            Ok(e) => e,
            Err(e) => {
                let reason = QuarantineReason::Unparseable(e.to_string());
                let tenant = tenant_hint(raw).unwrap_or_else(|| UNKNOWN_TENANT.to_string());
                self.quarantine.file(tenant, reason.clone(), raw);
                return Disposition::Quarantined(reason);
            }
        };

        self.ingest_event(event, raw)
    }

    /// Ingest an already-parsed event. `raw` is the bytes to quarantine on validation failure;
    /// callers without the original bytes can pass the canonical form.
    pub fn ingest_event(&self, event: Event, raw: &[u8]) -> Disposition {
        // Stage 3: validate.
        if let Err(e) = event.validate() {
            let reason = QuarantineReason::Invalid(e.to_string());
            self.quarantine
                .file(event.tenant_id.to_string(), reason.clone(), raw);
            return Disposition::Quarantined(reason);
        }

        // Stage 4: dedup.
        match self.dedup.check_and_record(&event) {
            Dedup::Fresh => {
                let id = event.event_id.to_string();
                // The store also guards id uniqueness; a race that loses here is reported as a
                // duplicate rather than a double-store.
                if self.store.insert(event) {
                    Disposition::Accepted(id)
                } else {
                    Disposition::Duplicate(Dedup::DuplicateId)
                }
            }
            dup => Disposition::Duplicate(dup),
        }
    }

    /// Ingest a batch of raw inputs, returning each disposition and the folded stats.
    pub fn ingest_batch<I>(&self, inputs: I) -> (Vec<Disposition>, IngestStats)
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        let mut stats = IngestStats::default();
        let dispositions: Vec<Disposition> = inputs
            .into_iter()
            .map(|raw| {
                let d = self.ingest_bytes(&raw);
                stats.record(&d);
                d
            })
            .collect();
        (dispositions, stats)
    }
}

/// Best-effort extraction of a tenant id from raw JSON, for quarantine filing only. Never
/// trusted for isolation decisions.
fn tenant_hint(raw: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(raw).ok()?;
    value.get("tenant_id")?.as_str().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryEventStore;
    use lattivant_event::{ActorKind, Assertion, Event, TenantId};

    fn valid_event_json(id: &str) -> Vec<u8> {
        let event = Event::builder("agent.tool_call", "alpha")
            .event_id(id)
            .source_engine("agenttrace")
            .actor(ActorKind::AiAgent, "agent-1")
            .outcome("success", Some(200))
            .assertion(Assertion::Observed)
            .build()
            .unwrap();
        serde_json::to_vec(&event).unwrap()
    }

    fn harness() -> (InMemoryEventStore, DedupIndex, Quarantine) {
        (InMemoryEventStore::new(), DedupIndex::new(), Quarantine::new())
    }

    #[test]
    fn valid_event_is_accepted_and_stored() {
        let (store, dedup, quarantine) = harness();
        let ingestor = Ingestor::new(&store, &dedup, &quarantine);
        let d = ingestor.ingest_bytes(&valid_event_json("e1"));
        assert_eq!(d, Disposition::Accepted("e1".to_string()));
        assert_eq!(store.count(&TenantId::new("alpha")), 1);
        assert!(quarantine.is_empty());
    }

    #[test]
    fn re_sent_event_is_a_duplicate_not_a_second_store() {
        let (store, dedup, quarantine) = harness();
        let ingestor = Ingestor::new(&store, &dedup, &quarantine);
        ingestor.ingest_bytes(&valid_event_json("e1"));
        let d = ingestor.ingest_bytes(&valid_event_json("e1"));
        assert!(matches!(d, Disposition::Duplicate(_)));
        assert_eq!(store.count(&TenantId::new("alpha")), 1);
    }

    #[test]
    fn unparseable_input_is_quarantined() {
        let (store, dedup, quarantine) = harness();
        let ingestor = Ingestor::new(&store, &dedup, &quarantine);
        let d = ingestor.ingest_bytes(b"{not json");
        assert!(matches!(d, Disposition::Quarantined(QuarantineReason::Unparseable(_))));
        assert_eq!(store.total(), 0);
        assert_eq!(quarantine.count_category("unparseable"), 1);
    }

    #[test]
    fn invalid_event_is_quarantined_under_its_tenant() {
        let (store, dedup, quarantine) = harness();
        let ingestor = Ingestor::new(&store, &dedup, &quarantine);
        // valid JSON shape but empty source_engine -> validation fails
        let bad = br#"{"schema_version":"1.0","event_id":"e1","tenant_id":"alpha","event_type":"x","source_engine":"","timestamp":"2026-01-01T00:00:00Z","observed_at":"2026-01-01T00:00:00Z","actor":{"type":"service","id":"s"},"action":{},"target":{},"outcome":{"status":"success"},"provenance":{"collector":"agenttrace","assertion":"observed"}}"#;
        let d = ingestor.ingest_bytes(bad);
        assert!(matches!(d, Disposition::Quarantined(QuarantineReason::Invalid(_))));
        assert_eq!(quarantine.for_tenant("alpha").len(), 1);
    }

    #[test]
    fn oversized_payload_is_quarantined_before_parse() {
        let (store, dedup, quarantine) = harness();
        let ingestor = Ingestor::new(&store, &dedup, &quarantine)
            .with_config(IngestConfig { max_payload_bytes: 8 });
        let d = ingestor.ingest_bytes(&valid_event_json("e1"));
        assert!(matches!(d, Disposition::Quarantined(QuarantineReason::TooLarge { .. })));
        assert_eq!(store.total(), 0);
    }

    #[test]
    fn batch_folds_stats() {
        let (store, dedup, quarantine) = harness();
        let ingestor = Ingestor::new(&store, &dedup, &quarantine);
        let inputs = vec![
            valid_event_json("e1"),
            valid_event_json("e2"),
            valid_event_json("e1"), // duplicate
            b"garbage".to_vec(),    // quarantine
        ];
        let (dispositions, stats) = ingestor.ingest_batch(inputs);
        assert_eq!(dispositions.len(), 4);
        assert_eq!(stats.accepted, 2);
        assert_eq!(stats.duplicates, 1);
        assert_eq!(stats.quarantined, 1);
        assert_eq!(stats.total(), 4);
    }
}
