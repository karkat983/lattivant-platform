//! Event ingestion for the Lattivant platform.
//!
//! Producers (the AuthZ Fuzzer, AgentTrace, EastWest) emit [`lattivant_event::Event`]s; this
//! crate is the front door that turns a stream of raw producer input into a clean, queryable,
//! tenant-isolated event store. It is deliberately boring and defensive: ingestion is the one
//! place every event passes through, so it must never panic, never silently drop input, and
//! never let one tenant's data leak into another's.
//!
//! The [`pipeline::Ingestor`] drives four stages — parse, size check, validate, dedup — and
//! routes each input to one of three outcomes:
//!
//! * **accepted**: stored in an [`store::EventStore`];
//! * **duplicate**: recognized by id or content fingerprint and acknowledged without a second
//!   store (ingestion is idempotent);
//! * **quarantined**: kept in a [`quarantine::Quarantine`] with its reason and raw bytes, so
//!   nothing is lost and bad producers can be found.
//!
//! Queries ([`query::EventQuery`]) always name a tenant, and the store refuses to return
//! anything outside it.
//!
//! ```
//! use lattivant_ingest::{Ingestor, InMemoryEventStore, DedupIndex, Quarantine, EventStore, EventQuery};
//! use lattivant_event::{Event, ActorKind, Assertion};
//!
//! let store = InMemoryEventStore::new();
//! let dedup = DedupIndex::new();
//! let quarantine = Quarantine::new();
//! let ingestor = Ingestor::new(&store, &dedup, &quarantine);
//!
//! let event = Event::builder("authz.finding", "tenant-demo")
//!     .event_id("f-1")
//!     .source_engine("authz")
//!     .actor(ActorKind::Scanner, "fuzzer")
//!     .outcome("verified", None)
//!     .assertion(Assertion::Inferred)
//!     .build()
//!     .unwrap();
//! let bytes = serde_json::to_vec(&event).unwrap();
//!
//! assert!(ingestor.ingest_bytes(&bytes).is_accepted());
//! assert!(!ingestor.ingest_bytes(&bytes).is_accepted()); // idempotent
//!
//! let hits = store.query(&EventQuery::for_tenant("tenant-demo").event_type("authz.finding"));
//! assert_eq!(hits.len(), 1);
//! ```

pub mod dedup;
pub mod pipeline;
pub mod quarantine;
pub mod query;
pub mod store;

pub use dedup::{Dedup, DedupIndex};
pub use pipeline::{Disposition, IngestConfig, IngestStats, Ingestor};
pub use quarantine::{Quarantine, QuarantineReason, QuarantinedEvent, UNKNOWN_TENANT};
pub use query::EventQuery;
pub use store::{EventStore, InMemoryEventStore};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use lattivant_event::{ActorKind, Assertion, Event, TenantId};

    fn finding(tenant: &str, id: &str) -> Vec<u8> {
        let e = Event::builder("authz.finding", tenant)
            .event_id(id)
            .source_engine("authz")
            .actor(ActorKind::Scanner, "fuzzer")
            .target("id", "order-1")
            .outcome("verified", None)
            .assertion(Assertion::Inferred)
            .build()
            .unwrap();
        serde_json::to_vec(&e).unwrap()
    }

    #[test]
    fn end_to_end_ingest_then_query_is_tenant_isolated() {
        let store = InMemoryEventStore::new();
        let dedup = DedupIndex::new();
        let quarantine = Quarantine::new();
        let ingestor = Ingestor::new(&store, &dedup, &quarantine);

        ingestor.ingest_bytes(&finding("alpha", "f1"));
        ingestor.ingest_bytes(&finding("alpha", "f2"));
        ingestor.ingest_bytes(&finding("bravo", "f1"));
        ingestor.ingest_bytes(&finding("alpha", "f1")); // dup

        assert_eq!(store.count(&TenantId::new("alpha")), 2);
        assert_eq!(store.count(&TenantId::new("bravo")), 1);

        // a bravo-scoped query never sees alpha's two findings
        let bravo_hits = store.query(&EventQuery::for_tenant("bravo"));
        assert_eq!(bravo_hits.len(), 1);
        assert!(bravo_hits.iter().all(|e| e.tenant_id == TenantId::new("bravo")));

        // all accepted events are from the authz engine
        let authz = store.query(&EventQuery::for_tenant("alpha").source_engine("authz"));
        assert_eq!(authz.len(), 2);
        assert!(quarantine.is_empty());
    }
}
