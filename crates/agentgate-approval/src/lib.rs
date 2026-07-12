//! Single-use, exact-action human approvals.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agentgate_core::{CanonicalAction, Digest, Effect, SessionId};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::Mutex;

/// Bounded material field displayed to the person approving a call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisplayField {
    /// JSON pointer requested by policy.
    pub selector: String,
    /// Escaped, bounded representation of the exact value.
    pub value: String,
}

/// Exact action presented to an approval provider.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Action digest that any approval must bind.
    pub action_digest: Digest,
    /// Session in which the action was requested.
    pub session_id: SessionId,
    /// Configured server identity.
    pub server_id: String,
    /// Exact tool name.
    pub tool: String,
    /// Security-relevant effects.
    pub effects: Vec<Effect>,
    /// Material exact fields selected by policy.
    pub fields: Vec<DisplayField>,
    /// Effective policy digest.
    pub policy_digest: Digest,
    /// Tool manifest digest.
    pub manifest_digest: Digest,
    /// UTC expiry shown to the provider.
    pub expires_at: DateTime<Utc>,
}

/// Human/provider response to an exact action prompt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalOutcome {
    /// Approve the exact action once.
    Approve,
    /// Deny the action.
    Deny,
    /// Deny and request session termination.
    TerminateSession,
}

/// Pluggable approval surface.
#[async_trait]
pub trait ApprovalProvider: Send + Sync {
    /// Presents a bounded exact action and returns an intentional outcome.
    async fn decide(&self, request: &ApprovalRequest) -> Result<ApprovalOutcome, ApprovalError>;

    /// Stable local provider identity included in evidence.
    fn identity(&self) -> &str;
}

/// Single-use approval receipt returned only after a provider allows the request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalReceipt {
    /// 128-bit random single-use token nonce.
    pub nonce: [u8; 16],
    /// Exact action digest.
    pub action_digest: Digest,
    /// Session binding.
    pub session_id: SessionId,
    /// Effective policy binding.
    pub policy_digest: Digest,
    /// Tool manifest binding.
    pub manifest_digest: Digest,
    /// Provider that made the decision.
    pub provider: String,
    /// UTC issuance evidence.
    pub issued_at: DateTime<Utc>,
    /// UTC expiry evidence.
    pub expires_at: DateTime<Utc>,
}

struct PendingApproval {
    receipt: ApprovalReceipt,
    deadline: Instant,
}

/// Broker that requests and atomically consumes exact approvals.
pub struct ApprovalBroker<P> {
    provider: Arc<P>,
    pending: Mutex<HashMap<[u8; 16], PendingApproval>>,
}

impl<P: ApprovalProvider> ApprovalBroker<P> {
    /// Creates an empty broker around one provider.
    #[must_use]
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Presents and records a short-lived single-use exact approval.
    pub async fn request(
        &self,
        action: &CanonicalAction,
        display: &[String],
        ttl_seconds: u64,
    ) -> Result<ApprovalReceipt, ApprovalError> {
        if !(1..=300).contains(&ttl_seconds) {
            return Err(ApprovalError::InvalidTtl);
        }
        let action_digest = action.digest().map_err(ApprovalError::Core)?;
        let issued_at = Utc::now();
        let expires_at = issued_at
            + chrono::Duration::seconds(
                i64::try_from(ttl_seconds).map_err(|_| ApprovalError::InvalidTtl)?,
            );
        let request = ApprovalRequest {
            action_digest,
            session_id: action.session_id,
            server_id: action.tool.server_id.to_string(),
            tool: action.tool.name.clone(),
            effects: action.effects.iter().cloned().collect(),
            fields: material_fields(action, display)?,
            policy_digest: action.policy_digest,
            manifest_digest: action.tool.manifest_digest,
            expires_at,
        };
        match self.provider.decide(&request).await? {
            ApprovalOutcome::Deny => return Err(ApprovalError::Denied),
            ApprovalOutcome::TerminateSession => return Err(ApprovalError::TerminateSession),
            ApprovalOutcome::Approve => {}
        }

        let mut nonce = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let receipt = ApprovalReceipt {
            nonce,
            action_digest,
            session_id: action.session_id,
            policy_digest: action.policy_digest,
            manifest_digest: action.tool.manifest_digest,
            provider: self.provider.identity().to_owned(),
            issued_at,
            expires_at,
        };
        self.pending.lock().await.insert(
            nonce,
            PendingApproval {
                receipt: receipt.clone(),
                deadline: Instant::now() + Duration::from_secs(ttl_seconds),
            },
        );
        Ok(receipt)
    }

    /// Atomically consumes a receipt if and only if it matches the current exact action.
    pub async fn consume(
        &self,
        receipt: &ApprovalReceipt,
        action: &CanonicalAction,
    ) -> Result<(), ApprovalError> {
        let pending = self
            .pending
            .lock()
            .await
            .remove(&receipt.nonce)
            .ok_or(ApprovalError::UnknownOrConsumed)?;
        if pending.deadline < Instant::now() || pending.receipt.expires_at < Utc::now() {
            return Err(ApprovalError::Expired);
        }
        let current = action.digest().map_err(ApprovalError::Core)?;
        let same_digest: bool = pending
            .receipt
            .action_digest
            .as_bytes()
            .ct_eq(current.as_bytes())
            .into();
        if !same_digest
            || pending.receipt.session_id != action.session_id
            || pending.receipt.policy_digest != action.policy_digest
            || pending.receipt.manifest_digest != action.tool.manifest_digest
        {
            return Err(ApprovalError::Stale);
        }
        Ok(())
    }

    /// Invalidates all outstanding receipts, used on session shutdown/reload.
    pub async fn invalidate_all(&self) {
        self.pending.lock().await.clear();
    }
}

/// Dedicated controlling-terminal approval provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct TerminalProvider;

#[async_trait]
impl ApprovalProvider for TerminalProvider {
    async fn decide(&self, request: &ApprovalRequest) -> Result<ApprovalOutcome, ApprovalError> {
        let request = request.clone();
        tokio::task::spawn_blocking(move || terminal_decision(&request))
            .await
            .map_err(|error| ApprovalError::Provider(error.to_string()))?
    }

    fn identity(&self) -> &'static str {
        "terminal/v1"
    }
}

/// Deterministic provider for unit and hermetic integration tests.
#[derive(Clone, Debug)]
pub struct FixedProvider {
    outcome: ApprovalOutcome,
}

impl FixedProvider {
    /// Creates a provider that always returns one outcome.
    #[must_use]
    pub const fn new(outcome: ApprovalOutcome) -> Self {
        Self { outcome }
    }
}

#[async_trait]
impl ApprovalProvider for FixedProvider {
    async fn decide(&self, _request: &ApprovalRequest) -> Result<ApprovalOutcome, ApprovalError> {
        Ok(self.outcome)
    }

    fn identity(&self) -> &'static str {
        "fixed-test-provider/v1"
    }
}

/// Approval/provider/canonical-binding failures.
#[derive(Debug, Error)]
pub enum ApprovalError {
    /// Provider intentionally denied the action.
    #[error("approval denied")]
    Denied,
    /// Provider intentionally denied and requested session termination.
    #[error("approval denied; terminate session")]
    TerminateSession,
    /// TTL is outside the safe 1-300 second window.
    #[error("approval ttl must be between 1 and 300 seconds")]
    InvalidTtl,
    /// Receipt is absent or already consumed.
    #[error("approval is unknown or already consumed")]
    UnknownOrConsumed,
    /// Receipt expired.
    #[error("approval expired")]
    Expired,
    /// Action, policy, manifest, or session changed after presentation.
    #[error("approval no longer matches the exact action")]
    Stale,
    /// Core canonicalization failed.
    #[error("failed to bind approval: {0}")]
    Core(agentgate_core::CoreError),
    /// Approval surface failed closed.
    #[error("approval provider failed: {0}")]
    Provider(String),
}

fn material_fields(
    action: &CanonicalAction,
    display: &[String],
) -> Result<Vec<DisplayField>, ApprovalError> {
    let arguments = action.arguments.to_value().map_err(ApprovalError::Core)?;
    let selectors: Vec<String> = if display.is_empty() {
        vec!["/arguments".to_owned()]
    } else {
        display.to_vec()
    };
    let mut fields = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let pointer = selector.strip_prefix("/arguments").unwrap_or(&selector);
        let value = if pointer.is_empty() {
            Some(&arguments)
        } else {
            arguments.pointer(pointer)
        };
        let rendered = value.map_or_else(|| "<missing>".to_owned(), render_safe);
        fields.push(DisplayField {
            selector,
            value: rendered,
        });
    }
    Ok(fields)
}

fn render_safe(value: &serde_json::Value) -> String {
    let raw = match value {
        serde_json::Value::String(value) => value.clone(),
        value => serde_json::to_string(value).unwrap_or_else(|_| "<unrenderable>".to_owned()),
    };
    let mut safe = String::with_capacity(raw.len().min(512));
    for character in raw.chars() {
        if safe.len() >= 512 {
            safe.push('…');
            break;
        }
        if character.is_control()
            || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            safe.extend(character.escape_unicode());
        } else {
            safe.push(character);
        }
    }
    safe
}

fn terminal_decision(request: &ApprovalRequest) -> Result<ApprovalOutcome, ApprovalError> {
    #[cfg(unix)]
    let path = "/dev/tty";
    #[cfg(windows)]
    let path = "CONIN$";
    let input = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| ApprovalError::Provider(error.to_string()))?;
    #[cfg(unix)]
    let output_path = "/dev/tty";
    #[cfg(windows)]
    let output_path = "CONOUT$";
    let mut output = OpenOptions::new()
        .write(true)
        .open(output_path)
        .map_err(|error| ApprovalError::Provider(error.to_string()))?;

    writeln!(
        output,
        "\nAgentGate blocked a consequential action pending approval."
    )
    .map_err(|error| ApprovalError::Provider(error.to_string()))?;
    writeln!(
        output,
        "Server/tool: {}/{}",
        request.server_id, request.tool
    )
    .map_err(|error| ApprovalError::Provider(error.to_string()))?;
    writeln!(output, "Effects: {:?}", request.effects)
        .map_err(|error| ApprovalError::Provider(error.to_string()))?;
    for field in &request.fields {
        writeln!(output, "{}: {}", field.selector, field.value)
            .map_err(|error| ApprovalError::Provider(error.to_string()))?;
    }
    writeln!(output, "Action digest: {}", request.action_digest)
        .map_err(|error| ApprovalError::Provider(error.to_string()))?;
    write!(output, "Type 'approve' to allow exactly once [deny]: ")
        .map_err(|error| ApprovalError::Provider(error.to_string()))?;
    output
        .flush()
        .map_err(|error| ApprovalError::Provider(error.to_string()))?;
    let mut answer = String::new();
    BufReader::new(input)
        .read_line(&mut answer)
        .map_err(|error| ApprovalError::Provider(error.to_string()))?;
    if answer.trim().eq_ignore_ascii_case("approve") {
        Ok(ApprovalOutcome::Approve)
    } else if answer.trim().eq_ignore_ascii_case("terminate") {
        Ok(ApprovalOutcome::TerminateSession)
    } else {
        Ok(ApprovalOutcome::Deny)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use agentgate_core::{CanonicalAction, Digest, Effect, ServerId, SessionId, ToolIdentity};
    use serde_json::json;
    use uuid::Uuid;

    use super::{ApprovalBroker, ApprovalError, ApprovalOutcome, FixedProvider, material_fields};

    fn action(message: &str) -> CanonicalAction {
        CanonicalAction::new(
            SessionId::from_uuid(Uuid::nil()),
            ToolIdentity {
                server_id: ServerId::new("messages")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                name: "tool_send_message".to_owned(),
                manifest_digest: Digest::domain(b"manifest", b"one"),
                protocol_version: "2025-11-25".to_owned(),
            },
            &json!({"recipient": "+15555550100", "message": message}),
            BTreeSet::from([Effect::Send]),
            Digest::domain(b"policy", b"one"),
        )
        .unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[tokio::test]
    async fn receipt_is_single_use_and_exact() {
        let broker = ApprovalBroker::new(FixedProvider::new(ApprovalOutcome::Approve));
        let action = action("hello");
        let receipt = broker
            .request(&action, &["/arguments/message".to_owned()], 60)
            .await
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(broker.consume(&receipt, &action).await.is_ok());
        assert!(matches!(
            broker.consume(&receipt, &action).await,
            Err(ApprovalError::UnknownOrConsumed)
        ));
    }

    #[tokio::test]
    async fn changed_action_invalidates_and_consumes_receipt() {
        let broker = ApprovalBroker::new(FixedProvider::new(ApprovalOutcome::Approve));
        let original = action("hello");
        let receipt = broker
            .request(&original, &["/arguments/message".to_owned()], 60)
            .await
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            broker.consume(&receipt, &action("changed")).await,
            Err(ApprovalError::Stale)
        ));
        assert!(matches!(
            broker.consume(&receipt, &original).await,
            Err(ApprovalError::UnknownOrConsumed)
        ));
    }

    #[test]
    fn material_display_escapes_controls_and_bidi() {
        let fields = material_fields(
            &action("hello\u{1b}[31m\u{202e}"),
            &["/arguments/message".to_owned()],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(!fields[0].value.contains('\u{1b}'));
        assert!(!fields[0].value.contains('\u{202e}'));
        assert!(fields[0].value.contains("\\u{1b}"));
    }

    #[tokio::test]
    async fn denial_fails_closed() {
        let broker = ApprovalBroker::new(FixedProvider::new(ApprovalOutcome::Deny));
        assert!(matches!(
            broker.request(&action("hello"), &[], 60).await,
            Err(ApprovalError::Denied)
        ));
    }
}
