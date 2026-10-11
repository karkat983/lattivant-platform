//! A JSON Schema for the envelope and a lightweight structural validator.
//!
//! The schema is published so other languages (the TypeScript UI, a Python detector) can
//! validate events against the same contract. [`validate_value`] is a dependency-free
//! structural check used in tests and at ingestion to quarantine malformed events with
//! actionable messages.

use serde_json::{json, Value};

use crate::SCHEMA_VERSION;

/// The JSON Schema (draft 2020-12) describing a valid event.
pub fn json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://lattivant.dev/schemas/event-1.0.json",
        "title": "LattivantEvent",
        "type": "object",
        "required": [
            "schema_version", "event_id", "tenant_id", "event_type",
            "source_engine", "timestamp", "observed_at", "actor",
            "action", "target", "outcome", "provenance"
        ],
        "properties": {
            "schema_version": {"type": "string", "const": SCHEMA_VERSION},
            "event_id": {"type": "string", "minLength": 1},
            "tenant_id": {"type": "string", "minLength": 1},
            "event_type": {"type": "string", "minLength": 1},
            "source_engine": {"type": "string", "minLength": 1},
            "timestamp": {"type": "string", "format": "date-time"},
            "observed_at": {"type": "string", "format": "date-time"},
            "actor": {
                "type": "object",
                "required": ["type", "id"],
                "properties": {
                    "type": {"enum": ["human", "service", "ai_agent", "scanner", "network_endpoint", "unknown"]},
                    "id": {"type": "string"}
                }
            },
            "action": {"type": "object", "additionalProperties": {"type": "string"}},
            "target": {"type": "object", "additionalProperties": {"type": "string"}},
            "outcome": {
                "type": "object",
                "required": ["status"],
                "properties": {"status": {"type": "string"}, "code": {"type": "integer"}}
            },
            "provenance": {
                "type": "object",
                "required": ["collector", "assertion"],
                "properties": {
                    "collector": {"type": "string"},
                    "raw_ref": {"type": "string"},
                    "assertion": {"enum": ["observed", "inferred"]}
                }
            },
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "trace_id": {"type": "string"},
            "span_id": {"type": "string"},
            "parent_event_ids": {"type": "array", "items": {"type": "string"}},
            "attack_techniques": {"type": "array", "items": {"type": "string"}}
        }
    })
}

/// The required top-level fields.
pub const REQUIRED_FIELDS: [&str; 12] = [
    "schema_version",
    "event_id",
    "tenant_id",
    "event_type",
    "source_engine",
    "timestamp",
    "observed_at",
    "actor",
    "action",
    "target",
    "outcome",
    "provenance",
];

/// Structurally validate a JSON value as an event, returning all problems found.
///
/// This is intentionally dependency-free (no JSON Schema engine): it checks presence of the
/// required fields, the schema version, string-ness of ids, and the nested shapes of
/// `actor`, `outcome` and `provenance` — enough to quarantine garbage at ingestion.
pub fn validate_value(value: &Value) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let Some(obj) = value.as_object() else {
        return Err(vec!["event is not a JSON object".to_string()]);
    };

    for field in REQUIRED_FIELDS {
        if !obj.contains_key(field) {
            problems.push(format!("missing required field {field:?}"));
        }
    }

    match obj.get("schema_version").and_then(Value::as_str) {
        Some(v) if v == SCHEMA_VERSION => {}
        Some(v) => problems.push(format!("unsupported schema_version {v:?}")),
        None => {} // already reported as missing
    }

    for field in ["event_id", "tenant_id", "event_type", "source_engine"] {
        if let Some(v) = obj.get(field) {
            match v.as_str() {
                Some(s) if !s.is_empty() => {}
                Some(_) => problems.push(format!("{field} must not be empty")),
                None => problems.push(format!("{field} must be a string")),
            }
        }
    }

    if let Some(actor) = obj.get("actor") {
        if actor.get("type").and_then(Value::as_str).is_none() {
            problems.push("actor.type is missing or not a string".into());
        }
        if actor.get("id").is_none() {
            problems.push("actor.id is missing".into());
        }
    }

    if let Some(outcome) = obj.get("outcome") {
        if outcome.get("status").and_then(Value::as_str).is_none() {
            problems.push("outcome.status is missing or not a string".into());
        }
    }

    if let Some(prov) = obj.get("provenance") {
        match prov.get("assertion").and_then(Value::as_str) {
            Some("observed") | Some("inferred") => {}
            _ => problems.push("provenance.assertion must be 'observed' or 'inferred'".into()),
        }
    }

    if let Some(c) = obj.get("confidence") {
        match c.as_f64() {
            Some(f) if (0.0..=1.0).contains(&f) => {}
            _ => problems.push("confidence must be a number in 0.0..=1.0".into()),
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// A known-good golden event (as JSON) for compatibility tests across languages.
pub fn golden_event() -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "event_id": "evt-golden-0001",
        "tenant_id": "tenant-demo",
        "event_type": "agent.tool_call",
        "source_engine": "agenttrace",
        "timestamp": "2026-10-10T12:00:00Z",
        "observed_at": "2026-10-10T12:00:01Z",
        "actor": {"type": "ai_agent", "id": "agent-1"},
        "action": {"type": "api_request", "name": "get_order"},
        "target": {"type": "api_resource", "id": "order-42"},
        "outcome": {"status": "success", "code": 200},
        "provenance": {"collector": "agenttrace", "raw_ref": "evidence://sha256/abc", "assertion": "observed"},
        "trace_id": "trace-123"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Event;

    #[test]
    fn golden_event_is_valid_and_deserializes() {
        let g = golden_event();
        assert!(validate_value(&g).is_ok());
        let _: Event = serde_json::from_value(g).unwrap();
    }

    #[test]
    fn missing_fields_are_all_reported() {
        let bad = json!({"schema_version": SCHEMA_VERSION});
        let problems = validate_value(&bad).unwrap_err();
        // every required field except schema_version should be flagged
        assert_eq!(problems.len(), REQUIRED_FIELDS.len() - 1);
    }

    #[test]
    fn bad_assertion_is_reported() {
        let mut g = golden_event();
        g["provenance"]["assertion"] = json!("guessed");
        let problems = validate_value(&g).unwrap_err();
        assert!(problems.iter().any(|p| p.contains("assertion")));
    }

    #[test]
    fn wrong_schema_version_is_reported() {
        let mut g = golden_event();
        g["schema_version"] = json!("0.9");
        let problems = validate_value(&g).unwrap_err();
        assert!(problems.iter().any(|p| p.contains("schema_version")));
    }

    #[test]
    fn built_events_pass_the_structural_validator() {
        let e = Event::builder("x.y", "tenant-a")
            .source_engine("authz")
            .actor(crate::ActorKind::Scanner, "o")
            .outcome("verified", None)
            .build()
            .unwrap();
        let value = serde_json::to_value(&e).unwrap();
        assert!(validate_value(&value).is_ok());
    }

    #[test]
    fn schema_lists_required_fields() {
        let schema = json_schema();
        let required = schema["required"].as_array().unwrap();
        assert_eq!(required.len(), REQUIRED_FIELDS.len());
    }
}
