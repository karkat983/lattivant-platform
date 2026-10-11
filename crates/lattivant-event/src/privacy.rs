//! Privacy metadata on an event.
//!
//! Some events carry personal data or came from redaction. The platform records this so
//! downstream consumers (exports, the investigator's LLM channel) can treat such events with
//! the right care — for example, never sending un-redacted PII into a model context.

use serde::{Deserialize, Serialize};

/// Privacy flags for an event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Privacy {
    /// Whether the event may contain personally identifiable information.
    #[serde(default)]
    pub contains_pii: bool,
    /// Whether the event's sensitive fields have already been redacted.
    #[serde(default)]
    pub redacted: bool,
}

impl Privacy {
    /// An event with no privacy concerns.
    pub fn none() -> Self {
        Privacy::default()
    }

    /// An event that contains PII (and whether it has been redacted).
    pub fn pii(redacted: bool) -> Self {
        Privacy {
            contains_pii: true,
            redacted,
        }
    }

    /// Whether this event is safe to forward to an external model context: either it has no
    /// PII, or its PII has been redacted.
    pub fn safe_for_model(&self) -> bool {
        !self.contains_pii || self.redacted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_safety_rule() {
        assert!(Privacy::none().safe_for_model());
        assert!(!Privacy::pii(false).safe_for_model());
        assert!(Privacy::pii(true).safe_for_model());
    }
}
