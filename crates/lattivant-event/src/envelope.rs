//! The event envelope struct, its builder, validation and canonical serialization.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::actor::{Actor, ActorKind};
use crate::ids::{EventId, TenantId, TraceId};
use crate::outcome::Outcome;
use crate::privacy::Privacy;
use crate::provenance::{Assertion, Provenance};
use crate::SCHEMA_VERSION;

/// Errors validating or building an event.
#[derive(Debug, Error, PartialEq)]
pub enum EventError {
    /// A required field was empty.
    #[error("event field {0} must not be empty")]
    Empty(&'static str),
    /// The schema version is not the one this build speaks.
    #[error("unsupported schema_version {0:?}")]
    BadSchemaVersion(String),
    /// Ingestion time precedes event time.
    #[error("observed_at ({observed_at}) precedes timestamp ({timestamp})")]
    TimeTravel {
        /// The ingestion time.
        observed_at: DateTime<Utc>,
        /// The event time.
        timestamp: DateTime<Utc>,
    },
    /// A confidence value was outside 0.0..=1.0.
    #[error("confidence {0} is not in 0.0..=1.0")]
    BadConfidence(f64),
    /// A required builder field was missing.
    #[error("event builder is missing {0}")]
    Missing(&'static str),
}

/// The canonical Lattivant event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// The schema version of this envelope.
    pub schema_version: String,
    /// A unique event id.
    pub event_id: EventId,
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// A dotted event type, e.g. `agent.tool_call`, `authz.finding`, `net.flow`.
    pub event_type: String,
    /// Which engine produced it.
    pub source_engine: String,
    /// When the thing happened (event time).
    pub timestamp: DateTime<Utc>,
    /// When the collector observed it (ingestion time).
    pub observed_at: DateTime<Utc>,
    /// The acting principal.
    pub actor: Actor,
    /// A free-form action descriptor.
    pub action: IndexMap<String, String>,
    /// A free-form target descriptor.
    pub target: IndexMap<String, String>,
    /// The outcome.
    pub outcome: Outcome,
    /// Provenance.
    pub provenance: Provenance,

    // ---- optional fields ----
    /// A distributed-trace id.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub trace_id: Option<TraceId>,
    /// A span id within the trace.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub span_id: Option<String>,
    /// Parent event ids, for correlation.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub parent_event_ids: Vec<EventId>,
    /// A producer confidence in [0.0, 1.0].
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub confidence: Option<f64>,
    /// Privacy flags.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub privacy: Option<Privacy>,
    /// An OCSF class mapping for export, e.g. `api_activity`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ocsf_mapping: Option<String>,
    /// ATT&CK technique ids associated with the event.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub attack_techniques: Vec<String>,
}

impl Event {
    /// Start building an event of the given type for a tenant.
    pub fn builder(event_type: impl Into<String>, tenant_id: impl Into<String>) -> EventBuilder {
        EventBuilder::new(event_type, tenant_id)
    }

    /// Validate every required field and cross-field invariant.
    pub fn validate(&self) -> Result<(), EventError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(EventError::BadSchemaVersion(self.schema_version.clone()));
        }
        if self.event_id.is_empty() {
            return Err(EventError::Empty("event_id"));
        }
        if self.tenant_id.is_empty() {
            return Err(EventError::Empty("tenant_id"));
        }
        if self.event_type.is_empty() {
            return Err(EventError::Empty("event_type"));
        }
        if self.source_engine.is_empty() {
            return Err(EventError::Empty("source_engine"));
        }
        if self.observed_at < self.timestamp {
            return Err(EventError::TimeTravel {
                observed_at: self.observed_at,
                timestamp: self.timestamp,
            });
        }
        if let Some(c) = self.confidence {
            if !(0.0..=1.0).contains(&c) {
                return Err(EventError::BadConfidence(c));
            }
        }
        Ok(())
    }

    /// A canonical JSON string with object keys sorted recursively — the stable byte form
    /// used for idempotency keys and fingerprints.
    pub fn canonical_json(&self) -> String {
        let value = serde_json::to_value(self).expect("event serializes");
        canonicalize(&value)
    }

    /// A content fingerprint over the canonical form, as lowercase hex.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_json().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Whether the event's provenance marks it as observed (not inferred).
    pub fn is_observed(&self) -> bool {
        self.provenance.is_observed()
    }

    /// The latency between the event happening and being observed, in milliseconds.
    pub fn ingestion_lag_ms(&self) -> i64 {
        (self.observed_at - self.timestamp).num_milliseconds()
    }
}

/// Recursively serialize a JSON value with object keys sorted.
fn canonicalize(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonicalize(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonicalize).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

/// Builds an [`Event`], enforcing required fields at `build` time.
pub struct EventBuilder {
    event_type: String,
    tenant_id: String,
    source_engine: String,
    event_id: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    observed_at: Option<DateTime<Utc>>,
    actor: Option<Actor>,
    action: IndexMap<String, String>,
    target: IndexMap<String, String>,
    outcome: Option<Outcome>,
    raw_ref: Option<String>,
    assertion: Assertion,
    trace_id: Option<String>,
    span_id: Option<String>,
    parents: Vec<String>,
    confidence: Option<f64>,
    privacy: Option<Privacy>,
    ocsf_mapping: Option<String>,
    attack_techniques: Vec<String>,
}

impl EventBuilder {
    fn new(event_type: impl Into<String>, tenant_id: impl Into<String>) -> Self {
        EventBuilder {
            event_type: event_type.into(),
            tenant_id: tenant_id.into(),
            source_engine: "platform".into(),
            event_id: None,
            timestamp: None,
            observed_at: None,
            actor: None,
            action: IndexMap::new(),
            target: IndexMap::new(),
            outcome: None,
            raw_ref: None,
            assertion: Assertion::Observed,
            trace_id: None,
            span_id: None,
            parents: Vec::new(),
            confidence: None,
            privacy: None,
            ocsf_mapping: None,
            attack_techniques: Vec::new(),
        }
    }

    /// Set the producing engine (default `platform`).
    pub fn source_engine(mut self, engine: impl Into<String>) -> Self {
        self.source_engine = engine.into();
        self
    }

    /// Set an explicit event id (otherwise one is derived from the fields).
    pub fn event_id(mut self, id: impl Into<String>) -> Self {
        self.event_id = Some(id.into());
        self
    }

    /// Set the event time (defaults to now at build).
    pub fn timestamp(mut self, t: DateTime<Utc>) -> Self {
        self.timestamp = Some(t);
        self
    }

    /// Set the ingestion time (defaults to the event time).
    pub fn observed_at(mut self, t: DateTime<Utc>) -> Self {
        self.observed_at = Some(t);
        self
    }

    /// Set the acting principal.
    pub fn actor(mut self, kind: ActorKind, id: impl Into<String>) -> Self {
        self.actor = Some(Actor::new(kind, id));
        self
    }

    /// Add an `action` field.
    pub fn action(mut self, key: &str, value: impl Into<String>) -> Self {
        self.action.insert(key.to_string(), value.into());
        self
    }

    /// Add a `target` field.
    pub fn target(mut self, key: &str, value: impl Into<String>) -> Self {
        self.target.insert(key.to_string(), value.into());
        self
    }

    /// Set the outcome.
    pub fn outcome(mut self, status: impl Into<String>, code: Option<i64>) -> Self {
        self.outcome = Some(Outcome::new(status, code));
        self
    }

    /// Set the provenance assertion (observed vs inferred).
    pub fn assertion(mut self, assertion: Assertion) -> Self {
        self.assertion = assertion;
        self
    }

    /// Set the raw-evidence reference.
    pub fn raw_ref(mut self, uri: impl Into<String>) -> Self {
        self.raw_ref = Some(uri.into());
        self
    }

    /// Attach a trace id.
    pub fn trace_id(mut self, id: impl Into<String>) -> Self {
        self.trace_id = Some(id.into());
        self
    }

    /// Attach a span id.
    pub fn span_id(mut self, id: impl Into<String>) -> Self {
        self.span_id = Some(id.into());
        self
    }

    /// Add a parent event id.
    pub fn parent(mut self, id: impl Into<String>) -> Self {
        self.parents.push(id.into());
        self
    }

    /// Set a confidence in [0.0, 1.0].
    pub fn confidence(mut self, c: f64) -> Self {
        self.confidence = Some(c);
        self
    }

    /// Set privacy flags.
    pub fn privacy(mut self, p: Privacy) -> Self {
        self.privacy = Some(p);
        self
    }

    /// Set the OCSF export mapping.
    pub fn ocsf_mapping(mut self, m: impl Into<String>) -> Self {
        self.ocsf_mapping = Some(m.into());
        self
    }

    /// Add an ATT&CK technique id.
    pub fn attack_technique(mut self, id: impl Into<String>) -> Self {
        self.attack_techniques.push(id.into());
        self
    }

    /// Finish building. Requires an actor and an outcome; fills times with `now`.
    pub fn build(self) -> Result<Event, EventError> {
        let actor = self.actor.ok_or(EventError::Missing("actor"))?;
        let outcome = self.outcome.ok_or(EventError::Missing("outcome"))?;
        let timestamp = self.timestamp.unwrap_or_else(Utc::now);
        let observed_at = self.observed_at.unwrap_or(timestamp);
        let event_id = self.event_id.unwrap_or_else(|| {
            let mut hasher = Sha256::new();
            hasher.update(self.event_type.as_bytes());
            hasher.update(self.tenant_id.as_bytes());
            hasher.update(actor.id.as_bytes());
            hasher.update(timestamp.to_rfc3339().as_bytes());
            format!("evt-{}", &hex::encode(hasher.finalize())[..16])
        });

        let event = Event {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: EventId::new(event_id),
            tenant_id: TenantId::new(self.tenant_id),
            event_type: self.event_type,
            source_engine: self.source_engine,
            timestamp,
            observed_at,
            actor,
            action: self.action,
            target: self.target,
            outcome,
            provenance: Provenance {
                collector: "platform".into(),
                raw_ref: self.raw_ref,
                assertion: self.assertion,
            },
            trace_id: self.trace_id.map(TraceId::new),
            span_id: self.span_id,
            parent_event_ids: self.parents.into_iter().map(EventId::new).collect(),
            confidence: self.confidence,
            privacy: self.privacy,
            ocsf_mapping: self.ocsf_mapping,
            attack_techniques: self.attack_techniques,
        };
        event.validate()?;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic() -> Event {
        Event::builder("agent.tool_call", "tenant-demo")
            .source_engine("agenttrace")
            .actor(ActorKind::AiAgent, "agent-1")
            .action("name", "get_order")
            .target("id", "order-42")
            .outcome("success", Some(200))
            .build()
            .unwrap()
    }

    #[test]
    fn builds_and_validates() {
        let e = basic();
        assert_eq!(e.schema_version, SCHEMA_VERSION);
        assert!(e.event_id.as_str().starts_with("evt-"));
        assert_eq!(e.source_engine, "agenttrace");
        assert_eq!(e.ingestion_lag_ms(), 0);
        assert!(e.is_observed());
    }

    #[test]
    fn missing_actor_or_outcome_fails() {
        assert_eq!(
            Event::builder("t", "x").outcome("ok", None).build().unwrap_err(),
            EventError::Missing("actor")
        );
        assert_eq!(
            Event::builder("t", "x").actor(ActorKind::Human, "u").build().unwrap_err(),
            EventError::Missing("outcome")
        );
    }

    #[test]
    fn observed_before_event_is_rejected() {
        let t = Utc::now();
        let e = Event::builder("t", "x")
            .actor(ActorKind::Human, "u")
            .outcome("ok", None)
            .timestamp(t)
            .observed_at(t - chrono::Duration::seconds(1))
            .build();
        assert!(matches!(e, Err(EventError::TimeTravel { .. })));
    }

    #[test]
    fn confidence_out_of_range_rejected() {
        let e = Event::builder("t", "x")
            .actor(ActorKind::Human, "u")
            .outcome("ok", None)
            .confidence(1.5)
            .build();
        assert_eq!(e.unwrap_err(), EventError::BadConfidence(1.5));
    }

    #[test]
    fn canonical_json_is_key_order_independent() {
        // Two events differing only in action insertion order canonicalize identically.
        let t = Utc::now();
        let a = Event::builder("t", "x")
            .actor(ActorKind::Human, "u")
            .outcome("ok", None)
            .timestamp(t)
            .event_id("evt-1")
            .action("b", "2")
            .action("a", "1")
            .build()
            .unwrap();
        let b = Event::builder("t", "x")
            .actor(ActorKind::Human, "u")
            .outcome("ok", None)
            .timestamp(t)
            .event_id("evt-1")
            .action("a", "1")
            .action("b", "2")
            .build()
            .unwrap();
        assert_eq!(a.canonical_json(), b.canonical_json());
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn optional_fields_round_trip() {
        let e = Event::builder("authz.finding", "tenant-a")
            .source_engine("authz")
            .actor(ActorKind::Scanner, "read_oracle")
            .outcome("verified", None)
            .assertion(Assertion::Inferred)
            .trace_id("trace-1")
            .parent("evt-parent")
            .confidence(0.9)
            .privacy(Privacy::pii(true))
            .ocsf_mapping("api_activity")
            .attack_technique("T1190")
            .build()
            .unwrap();
        let json = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
        assert_eq!(back.attack_techniques, vec!["T1190"]);
        assert_eq!(back.confidence, Some(0.9));
        assert!(!back.is_observed());
    }

    #[test]
    fn same_inputs_give_stable_event_id() {
        let t = Utc::now();
        let make = || {
            Event::builder("t", "x")
                .actor(ActorKind::Human, "u")
                .outcome("ok", None)
                .timestamp(t)
                .build()
                .unwrap()
                .event_id
        };
        assert_eq!(make(), make());
    }

    #[test]
    fn empty_tenant_is_rejected() {
        let e = Event::builder("t", "")
            .actor(ActorKind::Human, "u")
            .outcome("ok", None)
            .build();
        assert_eq!(e.unwrap_err(), EventError::Empty("tenant_id"));
    }
}
