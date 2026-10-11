//! The actor that performed an event's action.

use serde::{Deserialize, Serialize};

/// What kind of principal performed an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// A human user.
    Human,
    /// A service account or machine identity.
    Service,
    /// An AI agent (AgentTrace).
    AiAgent,
    /// The AuthZ scanner acting as a test identity.
    Scanner,
    /// A network endpoint (EastWest).
    NetworkEndpoint,
    /// The actor could not be identified.
    Unknown,
}

/// The acting principal. The id is a non-secret identifier (a username, agent id, service
/// name, or IP), never a credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// The kind of actor.
    #[serde(rename = "type")]
    pub kind: ActorKind,
    /// A non-secret identifier for the actor.
    pub id: String,
}

impl Actor {
    /// Construct an actor.
    pub fn new(kind: ActorKind, id: impl Into<String>) -> Self {
        Actor {
            kind,
            id: id.into(),
        }
    }

    /// The unknown actor.
    pub fn unknown() -> Self {
        Actor::new(ActorKind::Unknown, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_serializes_with_type_tag() {
        let a = Actor::new(ActorKind::AiAgent, "agent-1");
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["type"], "ai_agent");
        assert_eq!(v["id"], "agent-1");
    }

    #[test]
    fn round_trips() {
        for kind in [
            ActorKind::Human,
            ActorKind::Service,
            ActorKind::AiAgent,
            ActorKind::Scanner,
            ActorKind::NetworkEndpoint,
            ActorKind::Unknown,
        ] {
            let a = Actor::new(kind, "x");
            let back: Actor = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
            assert_eq!(a, back);
        }
    }
}
