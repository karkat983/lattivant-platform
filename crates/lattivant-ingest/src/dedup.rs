//! Idempotent dedup for ingestion.
//!
//! Producers retry, collectors replay, and the same event can arrive more than once. Dedup
//! makes ingestion idempotent on two keys, both tenant-scoped:
//!
//! * **event id** — the producer's own idempotency key;
//! * **content fingerprint** — the canonical hash of the whole envelope, which catches a
//!   re-send that was assigned a fresh id but carries identical content.
//!
//! A match on either key means "already seen". The fingerprint key is what makes dedup robust
//! to producers that mint a new id on every retry.

use std::collections::HashSet;
use std::sync::Mutex;

use lattivant_event::Event;
use sha2::{Digest, Sha256};

/// A tenant-scoped set of seen event ids and content fingerprints.
#[derive(Default)]
pub struct DedupIndex {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    // keys are prefixed with the tenant so two tenants never collide.
    ids: HashSet<String>,
    fingerprints: HashSet<String>,
}

/// The verdict for one event checked against the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dedup {
    /// Not seen before; now recorded.
    Fresh,
    /// Already seen by event id.
    DuplicateId,
    /// Already seen by content fingerprint (a re-send under a new id).
    DuplicateContent,
}

impl Dedup {
    /// Whether this verdict means the event should be stored.
    pub fn is_fresh(self) -> bool {
        matches!(self, Dedup::Fresh)
    }
}

impl DedupIndex {
    /// An empty index.
    pub fn new() -> Self {
        DedupIndex::default()
    }

    fn id_key(event: &Event) -> String {
        format!("{}\u{1f}{}", event.tenant_id.as_str(), event.event_id.as_str())
    }

    fn fp_key(event: &Event) -> String {
        format!("{}\u{1f}{}", event.tenant_id.as_str(), content_fingerprint(event))
    }

    /// Check an event and, if fresh, record it. Returns the verdict.
    pub fn check_and_record(&self, event: &Event) -> Dedup {
        let id_key = Self::id_key(event);
        let fp_key = Self::fp_key(event);
        let mut inner = self.inner.lock().unwrap();
        if inner.ids.contains(&id_key) {
            return Dedup::DuplicateId;
        }
        if inner.fingerprints.contains(&fp_key) {
            return Dedup::DuplicateContent;
        }
        inner.ids.insert(id_key);
        inner.fingerprints.insert(fp_key);
        Dedup::Fresh
    }

    /// Check without recording (a dry run).
    pub fn peek(&self, event: &Event) -> Dedup {
        let inner = self.inner.lock().unwrap();
        if inner.ids.contains(&Self::id_key(event)) {
            Dedup::DuplicateId
        } else if inner.fingerprints.contains(&Self::fp_key(event)) {
            Dedup::DuplicateContent
        } else {
            Dedup::Fresh
        }
    }

    /// How many distinct events have been recorded.
    pub fn recorded(&self) -> usize {
        self.inner.lock().unwrap().ids.len()
    }
}

/// A fingerprint over an event's *content*, excluding fields that legitimately differ between
/// re-sends of the same logical event: the producer's `event_id` and the collector's
/// `observed_at` (ingestion time). Two events that agree on everything else — tenant, type,
/// engine, event time, actor, action, target, outcome, provenance — hash the same, so a
/// producer that mints a fresh id on each retry is still deduplicated.
pub fn content_fingerprint(event: &Event) -> String {
    let mut value = serde_json::to_value(event).expect("event serializes");
    if let serde_json::Value::Object(map) = &mut value {
        map.remove("event_id");
        map.remove("observed_at");
    }
    let canonical = canonicalize(&value);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// Serialize a JSON value with object keys sorted recursively, so logically equal values
/// produce identical bytes regardless of field order.
fn canonicalize(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonicalize(&map[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonicalize).collect();
            format!("[{}]", parts.join(","))
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use lattivant_event::{ActorKind, Assertion};

    fn epoch() -> DateTime<Utc> {
        Utc.timestamp_opt(0, 0).unwrap()
    }

    fn event(tenant: &str, id: &str, target: &str) -> Event {
        Event::builder("agent.tool_call", tenant)
            .event_id(id)
            .source_engine("agenttrace")
            .actor(ActorKind::AiAgent, "agent-1")
            .target("id", target)
            .outcome("success", Some(200))
            .assertion(Assertion::Observed)
            // fixed timestamps so identical content fingerprints match
            .timestamp(epoch())
            .observed_at(epoch())
            .build()
            .unwrap()
    }

    #[test]
    fn first_sight_is_fresh_then_duplicate_by_id() {
        let idx = DedupIndex::new();
        let e = event("alpha", "e1", "order-1");
        assert_eq!(idx.check_and_record(&e), Dedup::Fresh);
        assert_eq!(idx.check_and_record(&e), Dedup::DuplicateId);
    }

    #[test]
    fn identical_content_under_new_id_is_duplicate_content() {
        let idx = DedupIndex::new();
        assert_eq!(idx.check_and_record(&event("alpha", "e1", "order-1")), Dedup::Fresh);
        // same content, different id
        assert_eq!(
            idx.check_and_record(&event("alpha", "e2", "order-1")),
            Dedup::DuplicateContent
        );
    }

    #[test]
    fn dedup_is_tenant_scoped() {
        let idx = DedupIndex::new();
        assert_eq!(idx.check_and_record(&event("alpha", "e1", "order-1")), Dedup::Fresh);
        // same id and content but a different tenant is a distinct event
        assert_eq!(idx.check_and_record(&event("bravo", "e1", "order-1")), Dedup::Fresh);
        assert_eq!(idx.recorded(), 2);
    }

    #[test]
    fn peek_does_not_record() {
        let idx = DedupIndex::new();
        let e = event("alpha", "e1", "order-1");
        assert_eq!(idx.peek(&e), Dedup::Fresh);
        assert_eq!(idx.peek(&e), Dedup::Fresh);
        assert_eq!(idx.recorded(), 0);
    }
}
