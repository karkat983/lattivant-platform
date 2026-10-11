//! Typed identifiers used in the envelope.
//!
//! Newtypes stop a tenant id being passed where an event id is expected, and give the one
//! place to enforce that ids are non-empty.

use serde::{Deserialize, Serialize};

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name(pub String);

        impl $name {
            /// Wrap a string as this id.
            pub fn new(s: impl Into<String>) -> Self {
                $name(s.into())
            }

            /// The underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Whether the id is empty.
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                $name(s.to_string())
            }
        }
    };
}

string_id!(
    /// A unique event id.
    EventId
);
string_id!(
    /// A tenant id; every customer-owned record carries one.
    TenantId
);
string_id!(
    /// A distributed-trace id linking events to a trace.
    TraceId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_distinct_types_but_share_behaviour() {
        let e = EventId::new("evt-1");
        let t = TenantId::new("tenant-a");
        assert_eq!(e.as_str(), "evt-1");
        assert_eq!(t.to_string(), "tenant-a");
        assert!(!e.is_empty());
        assert!(EventId::new("").is_empty());
    }

    #[test]
    fn serializes_as_a_bare_string() {
        assert_eq!(serde_json::to_string(&EventId::new("x")).unwrap(), "\"x\"");
        let back: TenantId = serde_json::from_str("\"y\"").unwrap();
        assert_eq!(back, TenantId::new("y"));
    }
}
