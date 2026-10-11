//! The canonical Lattivant event envelope.
//!
//! Every engine — AuthZ Fuzzer, AgentTrace, EastWest — emits events in this one shape so the
//! platform can normalize, store and correlate them regardless of origin. The envelope is a
//! *stable contract*: it carries a [`SCHEMA_VERSION`], separates **event time** from
//! **ingestion time**, distinguishes **observed** facts from **inferred** ones, and always
//! names its **tenant** and its **provenance**.
//!
//! This crate is pure data and validation. It performs no I/O and has no engine-specific
//! logic, so it can be depended on by producers and consumers alike without pulling in their
//! machinery.
//!
//! ```
//! use lattivant_event::{Event, ActorKind, Assertion};
//! let event = Event::builder("agent.tool_call", "tenant-demo")
//!     .source_engine("agenttrace")
//!     .actor(ActorKind::AiAgent, "agent-1")
//!     .action("type", "api_request")
//!     .action("name", "get_order")
//!     .target("type", "api_resource")
//!     .target("id", "order-42")
//!     .outcome("success", Some(200))
//!     .assertion(Assertion::Observed)
//!     .build()
//!     .unwrap();
//! assert_eq!(event.tenant_id.as_str(), "tenant-demo");
//! ```

pub mod actor;
pub mod envelope;
pub mod ids;
pub mod outcome;
pub mod privacy;
pub mod provenance;
pub mod schema;

pub use actor::{Actor, ActorKind};
pub use envelope::{Event, EventBuilder, EventError};
pub use ids::{EventId, TenantId, TraceId};
pub use outcome::Outcome;
pub use privacy::Privacy;
pub use provenance::{Assertion, Provenance};

/// The schema version this build of the envelope speaks.
///
/// Persisted events carry this so a later reader detects and migrates older records rather
/// than silently misinterpreting them.
pub const SCHEMA_VERSION: &str = "1.0";

/// The recognized source engines. The envelope accepts any string, but these are the known
/// first-party producers.
pub const KNOWN_ENGINES: [&str; 4] = ["authz", "agenttrace", "eastwest", "platform"];
