//! Core security domain types shared by AgentGate components.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// AgentGate's versioned canonical action schema.
pub const ACTION_SCHEMA_VERSION: u16 = 1;

/// A SHA-256 digest with domain-separated constructors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Hashes a domain and payload with unambiguous length framing.
    #[must_use]
    pub fn domain(domain: &[u8], payload: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"agentgate\0");
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(payload);
        Self(hasher.finalize().into())
    }

    /// Parses a lowercase or uppercase hexadecimal SHA-256 digest.
    pub fn from_hex(value: &str) -> Result<Self, CoreError> {
        let bytes = hex::decode(value).map_err(|_| CoreError::InvalidDigest)?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| CoreError::InvalidDigest)?;
        Ok(Self(array))
    }

    /// Returns the digest as lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Returns the fixed-size digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for Digest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

/// Stable identifier for one gateway session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    /// Generates a cryptographically random UUID v4 session identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Creates a session ID from a known UUID, useful for replay and tests.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for SessionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

/// Stable identity of a configured downstream server.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ServerId(String);

impl ServerId {
    /// Validates and creates a server identity.
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(CoreError::InvalidServerId);
        }
        Ok(Self(value))
    }

    /// Returns the policy-defined server identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ServerId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Stable identity of a tool under a configured server and manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolIdentity {
    /// Configured server identity.
    pub server_id: ServerId,
    /// Exact MCP tool name.
    pub name: String,
    /// Normalized tool-manifest digest.
    pub manifest_digest: Digest,
    /// Negotiated MCP protocol version.
    pub protocol_version: String,
}

/// Security-relevant consequences attached by trusted policy and heuristics.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Reads data without a filesystem-specific distinction.
    Read,
    /// Reads a local file or attachment.
    ReadFile,
    /// Writes local or remote state.
    Write,
    /// Executes code or a process.
    Execute,
    /// Makes a network request.
    Network,
    /// Sends a message or notification.
    Send,
    /// Uploads data to another system.
    Upload,
    /// Deletes data or state.
    Delete,
    /// Purchases or transfers value.
    Purchase,
    /// Reads authentication material.
    CredentialAccess,
    /// Changes a permission or access-control setting.
    PermissionChange,
    /// Controls a process or service.
    ProcessControl,
}

impl Effect {
    /// Returns whether v1 requires non-bypassable exact human approval.
    #[must_use]
    pub const fn requires_human_approval(&self) -> bool {
        matches!(
            self,
            Self::Send | Self::Upload | Self::Delete | Self::Purchase
        )
    }
}

/// Canonical JSON bytes used for action, manifest, policy, and event digests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalJson(Vec<u8>);

impl CanonicalJson {
    /// Canonicalizes a JSON value by recursively sorting object keys.
    pub fn from_value(value: &Value) -> Result<Self, CoreError> {
        let normalized = sort_value(value);
        serde_json::to_vec(&normalized)
            .map(Self)
            .map_err(CoreError::Serialize)
    }

    /// Returns the canonical UTF-8 JSON bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the canonical JSON as a value.
    pub fn to_value(&self) -> Result<Value, CoreError> {
        serde_json::from_slice(&self.0).map_err(CoreError::Serialize)
    }
}

/// Exact, versioned action used by policy, approval, and audit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalAction {
    /// Canonical action schema version.
    pub schema_version: u16,
    /// Session in which the action was requested.
    pub session_id: SessionId,
    /// Stable downstream tool identity.
    pub tool: ToolIdentity,
    /// Exact validated arguments in canonical JSON form.
    pub arguments: CanonicalJson,
    /// Trusted effect classifications.
    pub effects: BTreeSet<Effect>,
    /// Effective compiled policy digest.
    pub policy_digest: Digest,
}

impl CanonicalAction {
    /// Creates a canonical action from validated arguments.
    pub fn new(
        session_id: SessionId,
        tool: ToolIdentity,
        arguments: &Value,
        effects: BTreeSet<Effect>,
        policy_digest: Digest,
    ) -> Result<Self, CoreError> {
        Ok(Self {
            schema_version: ACTION_SCHEMA_VERSION,
            session_id,
            tool,
            arguments: CanonicalJson::from_value(arguments)?,
            effects,
            policy_digest,
        })
    }

    /// Computes the domain-separated exact action digest.
    pub fn digest(&self) -> Result<Digest, CoreError> {
        let value = serde_json::to_value(self).map_err(CoreError::Serialize)?;
        let bytes = CanonicalJson::from_value(&value)?;
        Ok(Digest::domain(b"action/v1", bytes.as_bytes()))
    }
}

/// Stable machine-readable decision code.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecisionCode(pub String);

impl DecisionCode {
    /// No allow rule matched.
    pub const NO_MATCH: &'static str = "AG-POLICY-NO-MATCH";
    /// An explicit deny rule matched.
    pub const EXPLICIT_DENY: &'static str = "AG-POLICY-EXPLICIT-DENY";
    /// Information flow was denied.
    pub const FLOW_BLOCKED: &'static str = "AG-FLOW-BLOCKED";
    /// Conservative session taint restricted an effect.
    pub const SESSION_TAINT: &'static str = "AG-SESSION-TAINT";
    /// Exact human approval is required.
    pub const APPROVAL_REQUIRED: &'static str = "AG-APPROVAL-REQUIRED";
    /// Suspicious bounded action sequence matched.
    pub const CHAIN_RISK: &'static str = "AG-CHAIN-RISK";
}

/// A deterministic security finding with bounded evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable detector identifier.
    pub id: String,
    /// Severity from `info` through `critical`.
    pub severity: String,
    /// Safe, bounded explanation.
    pub message: String,
}

/// An action that must complete before a call can be forwarded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Obligation {
    /// Exact-action approval by a human.
    HumanApproval {
        /// JSON pointers or field names rendered to the approver.
        display: Vec<String>,
        /// Maximum token validity in seconds.
        ttl_seconds: u64,
    },
    /// Offer the approver an explicit session termination action.
    OfferSessionTermination,
}

/// Final deterministic authorization result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// The call is authorized with no outstanding obligation.
    Allow {
        /// Matched policy rule IDs.
        rule_ids: Vec<String>,
    },
    /// The call may proceed only after every obligation succeeds.
    AllowWithObligations {
        /// Matched policy rule IDs.
        rule_ids: Vec<String>,
        /// Required pre-forward actions.
        obligations: Vec<Obligation>,
    },
    /// The call is denied and must never reach the downstream tool.
    Deny {
        /// Stable machine code.
        code: DecisionCode,
        /// Matched policy rule IDs.
        rule_ids: Vec<String>,
        /// Detector and evaluation findings.
        findings: Vec<Finding>,
    },
}

impl Decision {
    /// Returns whether the decision authorizes forwarding immediately.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Returns whether the decision denies forwarding.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Returns obligations, or an empty slice when none apply.
    #[must_use]
    pub fn obligations(&self) -> &[Obligation] {
        match self {
            Self::AllowWithObligations { obligations, .. } => obligations,
            Self::Allow { .. } | Self::Deny { .. } => &[],
        }
    }
}

/// Errors in core identity and canonicalization operations.
#[derive(Debug, Error)]
pub enum CoreError {
    /// A digest was not exactly 32 bytes of hexadecimal.
    #[error("invalid SHA-256 digest")]
    InvalidDigest,
    /// A policy server ID was empty, too long, or contained unsafe characters.
    #[error("invalid server identity")]
    InvalidServerId,
    /// Canonical JSON serialization failed.
    #[error("canonical JSON serialization failed: {0}")]
    Serialize(serde_json::Error),
}

fn sort_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_unstable();
            let mut sorted = Map::with_capacity(object.len());
            for key in keys {
                if let Some(value) = object.get(key) {
                    sorted.insert(key.clone(), sort_value(value));
                }
            }
            Value::Object(sorted)
        }
        scalar => scalar.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;
    use uuid::Uuid;

    use super::{
        CanonicalAction, CanonicalJson, Digest, Effect, ServerId, SessionId, ToolIdentity,
    };

    fn fixed_action(arguments: &serde_json::Value) -> CanonicalAction {
        CanonicalAction::new(
            SessionId::from_uuid(Uuid::nil()),
            ToolIdentity {
                server_id: ServerId::new("messages")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                name: "send".to_owned(),
                manifest_digest: Digest::domain(b"manifest", b"fixture"),
                protocol_version: "2025-11-25".to_owned(),
            },
            arguments,
            BTreeSet::from([Effect::Send]),
            Digest::domain(b"policy", b"fixture"),
        )
        .unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn canonical_json_sorts_nested_object_keys() {
        let left = CanonicalJson::from_value(&json!({"z": 1, "a": {"b": 2, "a": 1}}))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let right = CanonicalJson::from_value(&json!({"a": {"a": 1, "b": 2}, "z": 1}))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(left, right);
        assert_eq!(
            std::str::from_utf8(left.as_bytes()).ok(),
            Some(r#"{"a":{"a":1,"b":2},"z":1}"#)
        );
    }

    #[test]
    fn action_digest_changes_with_material_argument() {
        let first = fixed_action(&json!({"recipient": "+15555550100", "message": "hello"}));
        let changed = fixed_action(&json!({"recipient": "+15555550100", "message": "goodbye"}));
        assert_ne!(
            first
                .digest()
                .unwrap_or_else(|error| unreachable!("{error}")),
            changed
                .digest()
                .unwrap_or_else(|error| unreachable!("{error}"))
        );
    }

    #[test]
    fn server_ids_are_narrow_and_safe() {
        assert!(ServerId::new("mac-messages_1").is_ok());
        assert!(ServerId::new("../messages").is_err());
        assert!(ServerId::new("").is_err());
    }
}
