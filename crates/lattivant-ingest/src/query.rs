//! Tenant-scoped event queries.
//!
//! A query always names a tenant; the store never returns events from another tenant, so a
//! query with the wrong tenant simply matches nothing. All other fields narrow within that
//! tenant.

use chrono::{DateTime, Utc};
use lattivant_event::{ActorKind, Event, TenantId, TraceId};

/// A filter over stored events, always scoped to one tenant.
#[derive(Clone, Debug)]
pub struct EventQuery {
    /// The tenant whose events to search. Required — isolation is not optional.
    pub tenant_id: TenantId,
    /// Restrict to an exact event type (e.g. `authz.finding`).
    pub event_type: Option<String>,
    /// Restrict to a source engine (e.g. `agenttrace`).
    pub source_engine: Option<String>,
    /// Restrict to an actor kind.
    pub actor_kind: Option<ActorKind>,
    /// Restrict to a trace id (correlation).
    pub trace_id: Option<TraceId>,
    /// Only events at or after this event time.
    pub since: Option<DateTime<Utc>>,
    /// Only events at or before this event time.
    pub until: Option<DateTime<Utc>>,
    /// Only observed (not inferred) events when `Some(true)`, only inferred when `Some(false)`.
    pub observed_only: Option<bool>,
    /// Cap the number of results.
    pub limit: Option<usize>,
}

impl EventQuery {
    /// A query matching everything within a tenant.
    pub fn for_tenant(tenant: impl Into<String>) -> Self {
        EventQuery {
            tenant_id: TenantId::new(tenant),
            event_type: None,
            source_engine: None,
            actor_kind: None,
            trace_id: None,
            since: None,
            until: None,
            observed_only: None,
            limit: None,
        }
    }

    /// Narrow to an event type.
    pub fn event_type(mut self, t: impl Into<String>) -> Self {
        self.event_type = Some(t.into());
        self
    }

    /// Narrow to a source engine.
    pub fn source_engine(mut self, e: impl Into<String>) -> Self {
        self.source_engine = Some(e.into());
        self
    }

    /// Narrow to an actor kind.
    pub fn actor_kind(mut self, k: ActorKind) -> Self {
        self.actor_kind = Some(k);
        self
    }

    /// Narrow to a trace id.
    pub fn trace_id(mut self, id: impl Into<String>) -> Self {
        self.trace_id = Some(TraceId::new(id));
        self
    }

    /// Only events at or after `t`.
    pub fn since(mut self, t: DateTime<Utc>) -> Self {
        self.since = Some(t);
        self
    }

    /// Only events at or before `t`.
    pub fn until(mut self, t: DateTime<Utc>) -> Self {
        self.until = Some(t);
        self
    }

    /// Only observed events.
    pub fn observed_only(mut self) -> Self {
        self.observed_only = Some(true);
        self
    }

    /// Cap results.
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Whether an event satisfies every set field of this query.
    pub fn matches(&self, event: &Event) -> bool {
        if event.tenant_id != self.tenant_id {
            return false;
        }
        if let Some(t) = &self.event_type {
            if &event.event_type != t {
                return false;
            }
        }
        if let Some(e) = &self.source_engine {
            if &event.source_engine != e {
                return false;
            }
        }
        if let Some(k) = self.actor_kind {
            if event.actor.kind != k {
                return false;
            }
        }
        if let Some(tr) = &self.trace_id {
            if event.trace_id.as_ref() != Some(tr) {
                return false;
            }
        }
        if let Some(since) = self.since {
            if event.timestamp < since {
                return false;
            }
        }
        if let Some(until) = self.until {
            if event.timestamp > until {
                return false;
            }
        }
        if let Some(obs) = self.observed_only {
            if event.is_observed() != obs {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use lattivant_event::Assertion;

    fn event(ty: &str, engine: &str, kind: ActorKind, ts: DateTime<Utc>) -> Event {
        Event::builder(ty, "alpha")
            .source_engine(engine)
            .actor(kind, "a")
            .timestamp(ts)
            .observed_at(ts)
            .outcome("success", Some(200))
            .assertion(Assertion::Observed)
            .build()
            .unwrap()
    }

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0).unwrap()
    }

    #[test]
    fn tenant_mismatch_never_matches() {
        let q = EventQuery::for_tenant("bravo");
        assert!(!q.matches(&event("x", "authz", ActorKind::Service, at(1))));
    }

    #[test]
    fn field_filters_compose() {
        let e = event("authz.finding", "authz", ActorKind::Scanner, at(5));
        assert!(EventQuery::for_tenant("alpha")
            .event_type("authz.finding")
            .source_engine("authz")
            .actor_kind(ActorKind::Scanner)
            .matches(&e));
        assert!(!EventQuery::for_tenant("alpha")
            .actor_kind(ActorKind::Human)
            .matches(&e));
    }

    #[test]
    fn time_window_is_inclusive() {
        let e = event("x", "authz", ActorKind::Service, at(10));
        assert!(EventQuery::for_tenant("alpha").since(at(10)).until(at(10)).matches(&e));
        assert!(!EventQuery::for_tenant("alpha").since(at(11)).matches(&e));
        assert!(!EventQuery::for_tenant("alpha").until(at(9)).matches(&e));
    }
}
