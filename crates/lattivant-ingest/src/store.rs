//! Tenant-scoped event storage.
//!
//! A store holds accepted events keyed by `(tenant, event_id)`. Storage is the last stage of
//! the ingestion pipeline: events reach it only after validation and dedup, so the store
//! trusts that what it is handed is well-formed and not a duplicate — but it still enforces
//! tenant isolation on every read.

use lattivant_event::{Event, EventId, TenantId};

use crate::query::EventQuery;

/// A tenant-scoped append store for accepted events.
pub trait EventStore {
    /// Insert an accepted event. Returns `false` if an event with the same id already exists
    /// for the tenant (the store never overwrites).
    fn insert(&self, event: Event) -> bool;

    /// Fetch a single event by id within a tenant.
    fn get(&self, tenant: &TenantId, id: &EventId) -> Option<Event>;

    /// Whether an event id is already present for a tenant.
    fn contains(&self, tenant: &TenantId, id: &EventId) -> bool {
        self.get(tenant, id).is_some()
    }

    /// Count of stored events for a tenant.
    fn count(&self, tenant: &TenantId) -> usize;

    /// All events for a tenant that match the query, newest event-time first.
    fn query(&self, query: &EventQuery) -> Vec<Event>;
}

/// An in-memory [`EventStore`], suitable for tests, the lab, and single-process deployments.
#[derive(Default)]
pub struct InMemoryEventStore {
    inner: std::sync::Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    // insertion order preserved; (tenant, event_id) uniqueness enforced on insert.
    events: Vec<Event>,
}

impl InMemoryEventStore {
    /// An empty store.
    pub fn new() -> Self {
        InMemoryEventStore::default()
    }

    /// Total events across all tenants (test/metrics helper).
    pub fn total(&self) -> usize {
        self.inner.lock().unwrap().events.len()
    }
}

impl EventStore for InMemoryEventStore {
    fn insert(&self, event: Event) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let dup = inner
            .events
            .iter()
            .any(|e| e.tenant_id == event.tenant_id && e.event_id == event.event_id);
        if dup {
            return false;
        }
        inner.events.push(event);
        true
    }

    fn get(&self, tenant: &TenantId, id: &EventId) -> Option<Event> {
        self.inner
            .lock()
            .unwrap()
            .events
            .iter()
            .find(|e| &e.tenant_id == tenant && &e.event_id == id)
            .cloned()
    }

    fn count(&self, tenant: &TenantId) -> usize {
        self.inner
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|e| &e.tenant_id == tenant)
            .count()
    }

    fn query(&self, query: &EventQuery) -> Vec<Event> {
        let inner = self.inner.lock().unwrap();
        let mut hits: Vec<Event> = inner
            .events
            .iter()
            .filter(|e| query.matches(e))
            .cloned()
            .collect();
        // newest event-time first; ties broken by event id for determinism.
        hits.sort_by(|a, b| {
            b.timestamp
                .cmp(&a.timestamp)
                .then_with(|| a.event_id.as_str().cmp(b.event_id.as_str()))
        });
        if let Some(limit) = query.limit {
            hits.truncate(limit);
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattivant_event::{ActorKind, Assertion};

    fn event(tenant: &str, id: &str) -> Event {
        Event::builder("agent.tool_call", tenant)
            .event_id(id)
            .source_engine("agenttrace")
            .actor(ActorKind::AiAgent, "agent-1")
            .outcome("success", Some(200))
            .assertion(Assertion::Observed)
            .build()
            .unwrap()
    }

    #[test]
    fn insert_is_idempotent_per_tenant() {
        let store = InMemoryEventStore::new();
        assert!(store.insert(event("alpha", "e1")));
        assert!(!store.insert(event("alpha", "e1")));
        assert_eq!(store.count(&TenantId::new("alpha")), 1);
    }

    #[test]
    fn same_id_different_tenant_is_distinct() {
        let store = InMemoryEventStore::new();
        assert!(store.insert(event("alpha", "e1")));
        assert!(store.insert(event("bravo", "e1")));
        assert_eq!(store.count(&TenantId::new("alpha")), 1);
        assert_eq!(store.count(&TenantId::new("bravo")), 1);
    }

    #[test]
    fn get_is_tenant_isolated() {
        let store = InMemoryEventStore::new();
        store.insert(event("alpha", "e1"));
        assert!(store.get(&TenantId::new("alpha"), &EventId::new("e1")).is_some());
        assert!(store.get(&TenantId::new("bravo"), &EventId::new("e1")).is_none());
    }
}
