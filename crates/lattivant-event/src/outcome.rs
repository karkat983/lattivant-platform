//! The outcome of an event's action.

use serde::{Deserialize, Serialize};

/// The result of the action an event describes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// A short status token, e.g. `success`, `denied`, `error`, `verified`.
    pub status: String,
    /// Optional numeric detail, e.g. an HTTP status code or an exit code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i64>,
}

impl Outcome {
    /// Construct an outcome.
    pub fn new(status: impl Into<String>, code: Option<i64>) -> Self {
        Outcome {
            status: status.into(),
            code,
        }
    }

    /// A success outcome.
    pub fn success() -> Self {
        Outcome::new("success", None)
    }

    /// A denied outcome.
    pub fn denied() -> Self {
        Outcome::new("denied", None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_omitted_when_absent() {
        let v = serde_json::to_value(Outcome::success()).unwrap();
        assert_eq!(v["status"], "success");
        assert!(v.get("code").is_none());
    }

    #[test]
    fn code_present_when_set() {
        let v = serde_json::to_value(Outcome::new("denied", Some(403))).unwrap();
        assert_eq!(v["code"], 403);
    }
}
