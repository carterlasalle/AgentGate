//! AgentGate's strict declarative policy compiler and pure evaluator.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::Path;

use agentgate_core::{Decision, DecisionCode, Digest, Effect, Finding, Obligation, ServerId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Stable policy API version supported by AgentGate 1.x.
pub const POLICY_API_VERSION: &str = "agentgate.dev/v1";
/// Preview policy API accepted only by the explicit migration API.
pub const LEGACY_POLICY_API_VERSION: &str = "agentgate.dev/v1alpha1";

/// Parsed policy metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// Human-readable policy name.
    pub name: String,
    /// Monotonic author-defined policy version.
    pub version: u64,
}

/// Default policy behavior.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Decision when no capability rule matches. AgentGate 1.x requires `deny`.
    pub decision: RuleDecision,
    /// Audit capture mode. AgentGate 1.x requires privacy-preserving `metadata`.
    pub audit: String,
}

/// Top-level strict policy authoring document.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct GatewayPolicy {
    /// Policy schema identifier.
    pub api_version: String,
    /// Must be `GatewayPolicy`.
    pub kind: String,
    /// Policy identity/version.
    pub metadata: Metadata,
    /// Default fail-closed behavior.
    pub defaults: Defaults,
    /// Configured downstream servers and capabilities.
    #[serde(default)]
    pub servers: Vec<ServerPolicy>,
    /// Declared provenance labels.
    #[serde(default)]
    pub labels: Vec<LabelDefinition>,
    /// Source-to-sink flow rules.
    #[serde(default)]
    pub flows: Vec<FlowRule>,
    /// Conservative session-taint rules.
    #[serde(default)]
    pub session_taint: Vec<SessionTaintRule>,
    /// Bounded suspicious action sequences.
    #[serde(default)]
    pub chains: Vec<ChainRule>,
    /// Descriptor integrity responses.
    #[serde(default)]
    pub descriptor_integrity: DescriptorIntegrity,
}

/// One configured downstream MCP server.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerPolicy {
    /// Stable policy identity.
    pub id: String,
    /// No-shell process command.
    pub command: CommandSpec,
    /// Manifest trust policy.
    #[serde(default)]
    pub manifest: ManifestPolicy,
    /// Tool capability rules.
    #[serde(default)]
    pub rules: Vec<CapabilityRule>,
}

/// Explicit downstream process invocation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct CommandSpec {
    /// Executable name or path, never interpreted by a shell.
    pub executable: String,
    /// Exact argument vector.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variable names copied from the gateway process.
    #[serde(default)]
    pub inherit_environment: Vec<String>,
    /// Explicit environment values supplied to the child.
    #[serde(default)]
    pub environment: std::collections::BTreeMap<String, String>,
}

/// How a normalized tool manifest change is handled.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPolicy {
    /// `review_on_change`, `required`, or `observe`.
    #[serde(default = "default_manifest_mode")]
    pub mode: String,
}

/// One tool capability and its trusted classification.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRule {
    /// Stable review/audit identifier.
    pub id: String,
    /// Exact tool names.
    pub tools: Vec<String>,
    /// Trusted effects added by this rule.
    #[serde(default)]
    pub effects: Vec<Effect>,
    /// Allow or deny.
    pub decision: RuleDecision,
    /// Result fields that introduce sensitive labels.
    #[serde(default)]
    pub sources: Vec<FieldLabel>,
    /// Argument fields that are sinks.
    #[serde(default)]
    pub sinks: Vec<FieldLabel>,
    /// Pre-forward requirements.
    #[serde(default)]
    pub obligations: Vec<ObligationSpec>,
}

/// A JSON-pointer-like field and provenance label.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FieldLabel {
    /// Field selector.
    pub select: String,
    /// Hierarchical source or sink label.
    pub label: String,
}

/// Declared sensitivity and fingerprint behavior.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct LabelDefinition {
    /// Hierarchical label name.
    pub name: String,
    /// `public`, `internal`, `confidential`, `restricted`, or `external`.
    pub sensitivity: String,
    /// Explicit normalization profile.
    #[serde(default = "default_normalization")]
    pub normalization: String,
    /// Whether observing this label conservatively taints the session.
    #[serde(default)]
    pub session_taint: bool,
    /// Whether this label names a sink rather than source data.
    #[serde(default)]
    pub sink: bool,
    /// Fingerprinting configuration.
    #[serde(default)]
    pub fingerprint: FingerprintSpec,
}

/// Fingerprinting strategy for a label.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FingerprintSpec {
    /// Register exact keyed fingerprints.
    #[serde(default)]
    pub exact: bool,
    /// Register normalized keyed fingerprints.
    #[serde(default)]
    pub normalized: bool,
    /// Optional bounded chunk configuration.
    pub chunks: Option<ChunkSpec>,
}

/// Bounded chunk-fingerprint parameters.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct ChunkSpec {
    /// Minimum source bytes before chunking.
    pub min_bytes: usize,
    /// Window bytes per keyed chunk.
    pub window_bytes: usize,
}

/// Source-to-sink information-flow rule.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowRule {
    /// Stable rule identifier.
    pub id: String,
    /// Hierarchical source label/prefix.
    pub from: String,
    /// Destination selector.
    pub to: FlowTarget,
    /// Allow (declassification) or deny.
    pub decision: RuleDecision,
    /// Requirements for an allowed release.
    #[serde(default)]
    pub obligations: Vec<ObligationSpec>,
}

/// Flow destination by effect and/or exact tool.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowTarget {
    /// Any matching destination effect.
    #[serde(default)]
    pub effects: Vec<Effect>,
    /// Exact configured server identity.
    pub server: Option<String>,
    /// Exact tool name.
    pub tool: Option<String>,
    /// Material sink fields.
    #[serde(default)]
    pub fields: Vec<String>,
}

/// Session-level restriction after a sensitive label enters context.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct SessionTaintRule {
    /// Stable rule identifier.
    pub id: String,
    /// Active label/prefix that triggers the restriction.
    pub when_present: String,
    /// Exact tool exceptions that remain subject to their flow rules.
    #[serde(default)]
    pub except: Vec<ToolSelector>,
    /// Restricted effects.
    pub to_effects: Vec<Effect>,
    /// AgentGate 1.x supports deny only for conservative session taint.
    pub decision: RuleDecision,
}

/// Exact configured tool selector.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSelector {
    /// Configured server identity.
    pub server: String,
    /// Exact tool name.
    pub tool: String,
}

/// Bounded suspicious sequence rule retained for the integrity engine.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainRule {
    /// Stable rule identifier.
    pub id: String,
    /// Window such as `60s`.
    pub within: String,
    /// Ordered predicates.
    pub sequence: Vec<ChainStep>,
    /// Result when matched.
    pub decision: RuleDecision,
    /// Additional user-facing action.
    #[serde(default)]
    pub obligations: Vec<ObligationSpec>,
}

/// One bounded chain predicate.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct ChainStep {
    /// Any effect that satisfies this step.
    #[serde(default)]
    pub effects_any: Vec<Effect>,
    /// Any prior decision code that satisfies this step.
    #[serde(default)]
    pub decision_codes: Vec<String>,
    /// Required occurrences in the window.
    #[serde(default = "one")]
    pub count_at_least: usize,
}

/// Descriptor-integrity policy.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorIntegrity {
    /// Global manifest mode.
    #[serde(default = "default_manifest_mode")]
    pub manifest: String,
    /// Finding ID to response (`deny`, `quarantine`, `require_review`, `allow_with_warning`).
    #[serde(default)]
    pub findings: std::collections::BTreeMap<String, String>,
}

/// Authoring-level allow/deny value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleDecision {
    /// Permit when no stronger rule denies.
    Allow,
    /// Deny with precedence over allow.
    Deny,
}

/// Authoring form of a pre-forward obligation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObligationSpec {
    /// Exact human confirmation.
    HumanApproval {
        /// Material selectors rendered to the user.
        #[serde(default)]
        display: Vec<String>,
        /// Short duration such as `60s`.
        ttl: String,
    },
    /// Make session termination available in the prompt.
    OfferSessionTermination,
}

/// Validated, immutable policy ready for deterministic evaluation.
#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    document: GatewayPolicy,
    digest: Digest,
}

impl CompiledPolicy {
    /// Loads and compiles a policy from disk.
    pub fn from_path(path: &Path) -> Result<Self, PolicyError> {
        let source = fs::read_to_string(path).map_err(PolicyError::Io)?;
        Self::from_yaml(&source)
    }

    /// Parses, validates, and compiles a strict YAML policy.
    pub fn from_yaml(source: &str) -> Result<Self, PolicyError> {
        let document: GatewayPolicy = serde_yaml_ng::from_str(source).map_err(PolicyError::Yaml)?;
        validate(&document)?;
        let canonical = serde_json::to_value(&document).map_err(PolicyError::Json)?;
        let canonical =
            agentgate_core::CanonicalJson::from_value(&canonical).map_err(PolicyError::Core)?;
        Ok(Self {
            document,
            digest: Digest::domain(b"policy/v1", canonical.as_bytes()),
        })
    }

    /// Returns the stable compiled policy digest.
    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// Returns the policy document for configuration and introspection.
    #[must_use]
    pub const fn document(&self) -> &GatewayPolicy {
        &self.document
    }

    /// Returns one configured server by stable identity.
    #[must_use]
    pub fn server(&self, server_id: &str) -> Option<&ServerPolicy> {
        self.document
            .servers
            .iter()
            .find(|server| server.id == server_id)
    }

    /// Deterministically evaluates one tool call.
    #[must_use]
    pub fn evaluate(&self, context: &DecisionContext<'_>) -> Evaluation {
        let Some(server) = self.server(context.server_id) else {
            return Evaluation::deny(DecisionCode::NO_MATCH, Vec::new(), BTreeSet::new());
        };

        let matching: Vec<&CapabilityRule> = server
            .rules
            .iter()
            .filter(|rule| rule.tools.iter().any(|tool| tool == context.tool))
            .collect();
        if matching.is_empty() {
            return Evaluation::deny(DecisionCode::NO_MATCH, Vec::new(), BTreeSet::new());
        }

        let mut effects = builtin_effects(context.tool);
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut allow_rules = Vec::new();
        let mut deny_rules = Vec::new();
        let mut obligations = Vec::new();
        for rule in matching {
            effects.extend(rule.effects.iter().cloned());
            sources.extend(rule.sources.clone());
            sinks.extend(rule.sinks.clone());
            match rule.decision {
                RuleDecision::Allow => allow_rules.push(rule.id.clone()),
                RuleDecision::Deny => deny_rules.push(rule.id.clone()),
            }
            obligations.extend(rule.obligations.iter().filter_map(compile_obligation));
        }
        if !deny_rules.is_empty() {
            return Evaluation {
                decision: Decision::Deny {
                    code: DecisionCode(DecisionCode::EXPLICIT_DENY.to_owned()),
                    rule_ids: deny_rules,
                    findings: Vec::new(),
                },
                effects,
                sources,
                sinks,
            };
        }

        for taint_rule in &self.document.session_taint {
            let label_matches = context
                .active_labels
                .iter()
                .any(|label| label_matches(&taint_rule.when_present, label));
            let effect_matches = effects
                .iter()
                .any(|effect| taint_rule.to_effects.contains(effect));
            let excepted = taint_rule
                .except
                .iter()
                .any(|item| item.server == context.server_id && item.tool == context.tool);
            if label_matches && effect_matches && !excepted {
                return Evaluation::deny(
                    DecisionCode::SESSION_TAINT,
                    vec![taint_rule.id.clone()],
                    effects,
                );
            }
        }

        for active_label in context.active_labels {
            for flow in &self.document.flows {
                if !label_matches(&flow.from, active_label)
                    || !target_matches(&flow.to, context.server_id, context.tool, &effects)
                {
                    continue;
                }
                match flow.decision {
                    RuleDecision::Deny => {
                        return Evaluation::deny(
                            DecisionCode::FLOW_BLOCKED,
                            vec![flow.id.clone()],
                            effects,
                        );
                    }
                    RuleDecision::Allow => {
                        allow_rules.push(flow.id.clone());
                        obligations.extend(flow.obligations.iter().filter_map(compile_obligation));
                    }
                }
            }
        }

        if effects.iter().any(Effect::requires_human_approval)
            && !obligations
                .iter()
                .any(|item| matches!(item, Obligation::HumanApproval { .. }))
        {
            obligations.push(Obligation::HumanApproval {
                display: vec!["/arguments".to_owned()],
                ttl_seconds: 60,
            });
        }

        let decision = if obligations.is_empty() {
            Decision::Allow {
                rule_ids: allow_rules,
            }
        } else {
            Decision::AllowWithObligations {
                rule_ids: allow_rules,
                obligations,
            }
        };
        Evaluation {
            decision,
            effects,
            sources,
            sinks,
        }
    }
}

/// Complete deterministic input to policy evaluation.
#[derive(Clone, Debug)]
pub struct DecisionContext<'a> {
    /// Configured server identity.
    pub server_id: &'a str,
    /// Exact tool name.
    pub tool: &'a str,
    /// Validated arguments, retained for future bounded predicates.
    pub arguments: &'a Value,
    /// Labels currently present in the session or exact sink arguments.
    pub active_labels: &'a BTreeSet<String>,
}

/// Decision plus trusted classifications needed by later enforcement stages.
#[derive(Clone, Debug)]
pub struct Evaluation {
    /// Final allow/deny/obligation result.
    pub decision: Decision,
    /// Trusted effect classifications.
    pub effects: BTreeSet<Effect>,
    /// Source fields registered from the result.
    pub sources: Vec<FieldLabel>,
    /// Sink fields inspected in arguments.
    pub sinks: Vec<FieldLabel>,
}

/// Versioned data-only policy test suite.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTestSuite {
    /// Stable test schema version.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u64,
    /// Independent deterministic cases.
    pub cases: Vec<PolicyTestCase>,
}

/// One deterministic policy test case.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTestCase {
    /// Human-readable unique case name.
    pub name: String,
    /// Pre-existing session labels.
    #[serde(default, rename = "sessionLabels")]
    pub session_labels: BTreeSet<String>,
    /// Tool call presented to policy.
    pub call: PolicyTestCall,
    /// Required final outcome.
    pub expect: PolicyTestExpectation,
}

/// Data-only tool call used by policy tests.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTestCall {
    /// Configured server identity.
    pub server: String,
    /// Exact tool name.
    pub tool: String,
    /// Tool arguments.
    #[serde(default = "empty_object")]
    pub arguments: Value,
}

/// Expected deterministic policy decision.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTestExpectation {
    /// `allow`, `allow_with_obligations`, or `deny`.
    pub decision: String,
    /// Optional stable deny/escalation code.
    pub code: Option<String>,
}

/// Summary of a completely matching policy fixture suite.
#[derive(Clone, Debug, Serialize)]
pub struct PolicyTestReport {
    /// Number of matching cases.
    pub passed: usize,
    /// Ordered case names.
    pub cases: Vec<String>,
}

impl CompiledPolicy {
    /// Executes strict YAML decision fixtures without performing any tool I/O.
    pub fn test_yaml(&self, source: &str) -> Result<PolicyTestReport, PolicyError> {
        let suite: PolicyTestSuite = serde_yaml_ng::from_str(source).map_err(PolicyError::Yaml)?;
        if suite.schema_version != 1 || suite.cases.is_empty() {
            return Err(PolicyError::Validation(
                "policy test suite requires schemaVersion 1 and at least one case".to_owned(),
            ));
        }
        let mut names = HashSet::new();
        let mut passed = Vec::new();
        for case in suite.cases {
            if case.name.is_empty() || !names.insert(case.name.clone()) {
                return Err(PolicyError::Validation(format!(
                    "empty or duplicate policy test name {}",
                    case.name
                )));
            }
            let evaluated = self.evaluate(&DecisionContext {
                server_id: &case.call.server,
                tool: &case.call.tool,
                arguments: &case.call.arguments,
                active_labels: &case.session_labels,
            });
            let actual_decision = match &evaluated.decision {
                Decision::Allow { .. } => "allow",
                Decision::AllowWithObligations { .. } => "allow_with_obligations",
                Decision::Deny { .. } => "deny",
            };
            let actual_code = match &evaluated.decision {
                Decision::Deny { code, .. } => Some(code.0.as_str()),
                Decision::AllowWithObligations { .. } => Some(DecisionCode::APPROVAL_REQUIRED),
                Decision::Allow { .. } => None,
            };
            if actual_decision != case.expect.decision
                || case
                    .expect
                    .code
                    .as_deref()
                    .is_some_and(|expected| actual_code != Some(expected))
            {
                return Err(PolicyError::TestMismatch {
                    name: case.name,
                    expected: format!("{} {:?}", case.expect.decision, case.expect.code),
                    actual: format!("{actual_decision} {actual_code:?}"),
                });
            }
            passed.push(case.name);
        }
        Ok(PolicyTestReport {
            passed: passed.len(),
            cases: passed,
        })
    }

    /// Produces a deterministic, metadata-only change report between two compiled policies.
    #[must_use]
    pub fn diff(&self, next: &Self) -> PolicyDiffReport {
        let current_rules = rule_ids(&self.document);
        let next_rules = rule_ids(&next.document);
        let current_servers = self
            .document
            .servers
            .iter()
            .map(|server| server.id.clone())
            .collect::<BTreeSet<_>>();
        let next_servers = next
            .document
            .servers
            .iter()
            .map(|server| server.id.clone())
            .collect::<BTreeSet<_>>();
        PolicyDiffReport {
            from_digest: self.digest.to_hex(),
            to_digest: next.digest.to_hex(),
            added_servers: next_servers.difference(&current_servers).cloned().collect(),
            removed_servers: current_servers.difference(&next_servers).cloned().collect(),
            added_rules: next_rules.difference(&current_rules).cloned().collect(),
            removed_rules: current_rules.difference(&next_rules).cloned().collect(),
            changed: self.digest != next.digest,
        }
    }
}

/// Stable metadata-only policy change report used by review and upgrade tooling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyDiffReport {
    /// Original compiled digest.
    pub from_digest: String,
    /// Candidate compiled digest.
    pub to_digest: String,
    /// Server identities newly introduced by the candidate.
    pub added_servers: Vec<String>,
    /// Server identities removed by the candidate.
    pub removed_servers: Vec<String>,
    /// Rule identities newly introduced by the candidate.
    pub added_rules: Vec<String>,
    /// Rule identities removed by the candidate.
    pub removed_rules: Vec<String>,
    /// Whether any security-relevant canonical policy byte changed.
    pub changed: bool,
}

/// Migrates the preview `v1alpha1` policy schema to the stable `v1` schema.
///
/// Migration is deliberately explicit: the normal compiler never silently accepts a preview
/// document, so an operator can review and test the generated policy before activation.
pub fn migrate_v1alpha1_to_v1(source: &str) -> Result<String, PolicyError> {
    let mut value: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(source).map_err(PolicyError::Yaml)?;
    let mapping = value.as_mapping_mut().ok_or_else(|| {
        PolicyError::Validation("policy migration requires a YAML mapping".to_owned())
    })?;
    let version_key = serde_yaml_ng::Value::String("apiVersion".to_owned());
    let version = mapping
        .get(&version_key)
        .and_then(serde_yaml_ng::Value::as_str);
    if version != Some(LEGACY_POLICY_API_VERSION) {
        return Err(PolicyError::Validation(format!(
            "migration source apiVersion must be {LEGACY_POLICY_API_VERSION}"
        )));
    }
    mapping.insert(
        version_key,
        serde_yaml_ng::Value::String(POLICY_API_VERSION.to_owned()),
    );
    let document: GatewayPolicy = serde_yaml_ng::from_value(value).map_err(PolicyError::Yaml)?;
    validate(&document)?;
    serde_yaml_ng::to_string(&document).map_err(PolicyError::Yaml)
}

fn rule_ids(policy: &GatewayPolicy) -> BTreeSet<String> {
    policy
        .servers
        .iter()
        .flat_map(|server| server.rules.iter().map(|rule| rule.id.clone()))
        .chain(policy.flows.iter().map(|rule| rule.id.clone()))
        .chain(policy.session_taint.iter().map(|rule| rule.id.clone()))
        .chain(policy.chains.iter().map(|rule| rule.id.clone()))
        .collect()
}

impl Evaluation {
    fn deny(code: &str, rule_ids: Vec<String>, effects: BTreeSet<Effect>) -> Self {
        Self {
            decision: Decision::Deny {
                code: DecisionCode(code.to_owned()),
                rule_ids,
                findings: Vec::<Finding>::new(),
            },
            effects,
            sources: Vec::new(),
            sinks: Vec::new(),
        }
    }
}

/// Policy loading, compilation, and validation errors.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Policy file could not be read.
    #[error("failed to read policy: {0}")]
    Io(std::io::Error),
    /// Strict YAML decoding failed.
    #[error("invalid policy YAML: {0}")]
    Yaml(serde_yaml_ng::Error),
    /// Canonical serialization failed.
    #[error("failed to serialize policy: {0}")]
    Json(serde_json::Error),
    /// Core canonicalization failed.
    #[error("failed to canonicalize policy: {0}")]
    Core(agentgate_core::CoreError),
    /// Semantic policy validation failed.
    #[error("invalid policy: {0}")]
    Validation(String),
    /// A data-only policy test case did not match its expected decision.
    #[error("policy test '{name}' failed: expected {expected}, got {actual}")]
    TestMismatch {
        /// Test name.
        name: String,
        /// Expected decision/code.
        expected: String,
        /// Actual decision/code.
        actual: String,
    },
}

fn validate(policy: &GatewayPolicy) -> Result<(), PolicyError> {
    if policy.api_version != POLICY_API_VERSION {
        return Err(PolicyError::Validation(format!(
            "apiVersion must be {POLICY_API_VERSION}"
        )));
    }
    if policy.kind != "GatewayPolicy" {
        return Err(PolicyError::Validation(
            "kind must be GatewayPolicy".to_owned(),
        ));
    }
    if policy.defaults.decision != RuleDecision::Deny {
        return Err(PolicyError::Validation(
            "v1 default decision must be deny".to_owned(),
        ));
    }
    if policy.defaults.audit != "metadata" {
        return Err(PolicyError::Validation(
            "v1 audit mode must be metadata".to_owned(),
        ));
    }

    let mut server_ids = HashSet::new();
    let mut rule_ids = HashSet::new();
    let labels: HashSet<&str> = policy
        .labels
        .iter()
        .map(|label| label.name.as_str())
        .collect();
    for server in &policy.servers {
        ServerId::new(server.id.clone())
            .map_err(|error| PolicyError::Validation(error.to_string()))?;
        if !server_ids.insert(server.id.as_str()) {
            return Err(PolicyError::Validation(format!(
                "duplicate server ID {}",
                server.id
            )));
        }
        if server.command.executable.trim().is_empty() || server.command.executable.contains('\0') {
            return Err(PolicyError::Validation(format!(
                "server {} has invalid executable",
                server.id
            )));
        }
        for rule in &server.rules {
            insert_rule_id(&mut rule_ids, &rule.id)?;
            if rule.tools.is_empty() || rule.tools.iter().any(String::is_empty) {
                return Err(PolicyError::Validation(format!(
                    "rule {} requires non-empty exact tools",
                    rule.id
                )));
            }
            for field in rule.sources.iter().chain(&rule.sinks) {
                if !labels.contains(field.label.as_str()) {
                    return Err(PolicyError::Validation(format!(
                        "rule {} references unknown label {}",
                        rule.id, field.label
                    )));
                }
                validate_pointer(&field.select)?;
            }
            validate_obligations(&rule.id, &rule.obligations)?;
        }
    }

    for flow in &policy.flows {
        insert_rule_id(&mut rule_ids, &flow.id)?;
        if !label_declared_or_parent(&labels, &flow.from) {
            return Err(PolicyError::Validation(format!(
                "flow {} references unknown source label {}",
                flow.id, flow.from
            )));
        }
        if flow.to.effects.is_empty() && flow.to.server.is_none() && flow.to.tool.is_none() {
            return Err(PolicyError::Validation(format!(
                "flow {} has no destination selector",
                flow.id
            )));
        }
        if flow.decision == RuleDecision::Allow && flow.obligations.is_empty() {
            return Err(PolicyError::Validation(format!(
                "declassification flow {} requires an obligation",
                flow.id
            )));
        }
        validate_obligations(&flow.id, &flow.obligations)?;
    }

    for rule in &policy.session_taint {
        insert_rule_id(&mut rule_ids, &rule.id)?;
        if rule.decision != RuleDecision::Deny {
            return Err(PolicyError::Validation(format!(
                "session-taint rule {} must deny in v1",
                rule.id
            )));
        }
        if !label_declared_or_parent(&labels, &rule.when_present) {
            return Err(PolicyError::Validation(format!(
                "session-taint rule {} references unknown label {}",
                rule.id, rule.when_present
            )));
        }
    }

    for chain in &policy.chains {
        insert_rule_id(&mut rule_ids, &chain.id)?;
        parse_duration_seconds(&chain.within)?;
        if chain.sequence.is_empty() || chain.sequence.iter().any(|step| step.count_at_least == 0) {
            return Err(PolicyError::Validation(format!(
                "chain {} requires non-empty positive steps",
                chain.id
            )));
        }
        validate_obligations(&chain.id, &chain.obligations)?;
    }
    Ok(())
}

fn insert_rule_id<'a>(ids: &mut HashSet<&'a str>, id: &'a str) -> Result<(), PolicyError> {
    if id.is_empty() || !ids.insert(id) {
        return Err(PolicyError::Validation(format!(
            "empty or duplicate rule ID {id}"
        )));
    }
    Ok(())
}

fn validate_obligations(id: &str, obligations: &[ObligationSpec]) -> Result<(), PolicyError> {
    for obligation in obligations {
        if let ObligationSpec::HumanApproval { ttl, .. } = obligation {
            let seconds = parse_duration_seconds(ttl)?;
            if !(1..=300).contains(&seconds) {
                return Err(PolicyError::Validation(format!(
                    "rule {id} approval ttl must be 1-300 seconds"
                )));
            }
        }
    }
    Ok(())
}

fn validate_pointer(pointer: &str) -> Result<(), PolicyError> {
    if !pointer.starts_with('/') || pointer.len() > 512 {
        return Err(PolicyError::Validation(format!(
            "invalid bounded JSON pointer {pointer}"
        )));
    }
    Ok(())
}

fn parse_duration_seconds(value: &str) -> Result<u64, PolicyError> {
    let number = value.strip_suffix('s').ok_or_else(|| {
        PolicyError::Validation(format!("duration must use seconds suffix: {value}"))
    })?;
    number
        .parse::<u64>()
        .map_err(|_| PolicyError::Validation(format!("invalid duration: {value}")))
}

fn compile_obligation(spec: &ObligationSpec) -> Option<Obligation> {
    match spec {
        ObligationSpec::HumanApproval { display, ttl } => {
            parse_duration_seconds(ttl)
                .ok()
                .map(|ttl_seconds| Obligation::HumanApproval {
                    display: display.clone(),
                    ttl_seconds,
                })
        }
        ObligationSpec::OfferSessionTermination => Some(Obligation::OfferSessionTermination),
    }
}

fn builtin_effects(tool: &str) -> BTreeSet<Effect> {
    let lowered = tool.to_ascii_lowercase();
    let mut effects = BTreeSet::new();
    for (needles, effect) in [
        (&["send", "notify"][..], Effect::Send),
        (&["upload", "publish", "share"][..], Effect::Upload),
        (&["delete", "remove", "purge"][..], Effect::Delete),
        (
            &["purchase", "buy", "checkout", "pay"][..],
            Effect::Purchase,
        ),
        (
            &["http", "fetch", "request", "network", "webhook"][..],
            Effect::Network,
        ),
        (&["execute", "run", "shell", "command"][..], Effect::Execute),
    ] {
        if needles.iter().any(|needle| lowered.contains(needle)) {
            effects.insert(effect);
        }
    }
    effects
}

fn label_matches(parent: &str, value: &str) -> bool {
    value == parent
        || value
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn label_declared_or_parent(labels: &HashSet<&str>, value: &str) -> bool {
    labels.iter().any(|label| label_matches(value, label))
}

fn target_matches(
    target: &FlowTarget,
    server_id: &str,
    tool: &str,
    effects: &BTreeSet<Effect>,
) -> bool {
    let effect_match =
        target.effects.is_empty() || target.effects.iter().any(|effect| effects.contains(effect));
    let server_match = target
        .server
        .as_deref()
        .is_none_or(|value| value == server_id);
    let tool_match = target.tool.as_deref().is_none_or(|value| value == tool);
    effect_match && server_match && tool_match
}

fn default_manifest_mode() -> String {
    "review_on_change".to_owned()
}

fn default_normalization() -> String {
    "text".to_owned()
}

const fn one() -> usize {
    1
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use agentgate_core::{Decision, Effect, Obligation};
    use serde_json::json;

    use super::{CompiledPolicy, DecisionContext, migrate_v1alpha1_to_v1};

    const POLICY: &str = r#"
apiVersion: agentgate.dev/v1
kind: GatewayPolicy
metadata: { name: test, version: 1 }
defaults: { decision: deny, audit: metadata }
servers:
  - id: messages
    command: { executable: fake, args: [], inheritEnvironment: [] }
    rules:
      - id: read
        tools: [read_messages]
        effects: [read]
        decision: allow
        sources: [{ select: /content, label: personal.messages.content }]
      - id: send
        tools: [send_message]
        effects: [send]
        decision: allow
        obligations:
          - { type: human_approval, display: [/arguments/recipient, /arguments/message], ttl: 60s }
labels:
  - name: personal.messages.content
    sensitivity: restricted
    normalization: text
    sessionTaint: true
  - name: external.messages
    sensitivity: external
    sink: true
flows:
  - id: release-to-messages
    from: personal.messages.content
    to: { server: messages, tool: send_message, fields: [/arguments/message] }
    decision: allow
    obligations:
      - { type: human_approval, display: [/arguments/recipient, /arguments/message], ttl: 60s }
sessionTaint:
  - id: block-other-egress
    whenPresent: personal.messages
    except: [{ server: messages, tool: send_message }]
    toEffects: [network, upload, send]
    decision: deny
"#;

    fn policy() -> CompiledPolicy {
        CompiledPolicy::from_yaml(POLICY).unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn preview_policy_requires_explicit_reviewable_migration() {
        let legacy = POLICY.replace("agentgate.dev/v1", "agentgate.dev/v1alpha1");
        assert!(CompiledPolicy::from_yaml(&legacy).is_err());
        let migrated =
            migrate_v1alpha1_to_v1(&legacy).unwrap_or_else(|error| unreachable!("{error}"));
        let compiled =
            CompiledPolicy::from_yaml(&migrated).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(compiled.document().api_version, "agentgate.dev/v1");
    }

    #[test]
    fn policy_diff_reports_rule_identity_changes_without_payloads() {
        let current = policy();
        let candidate = CompiledPolicy::from_yaml(&POLICY.replace("id: read", "id: read-v2"))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let report = current.diff(&candidate);
        assert!(report.changed);
        assert_eq!(report.added_rules, vec!["read-v2"]);
        assert_eq!(report.removed_rules, vec!["read"]);
    }

    #[test]
    fn empty_or_unknown_capability_is_denied() {
        let policy = policy();
        let labels = BTreeSet::new();
        let evaluated = policy.evaluate(&DecisionContext {
            server_id: "messages",
            tool: "read_message",
            arguments: &json!({}),
            active_labels: &labels,
        });
        assert!(evaluated.decision.is_deny());
    }

    #[test]
    fn declared_read_is_allowed_and_labeled() {
        let policy = policy();
        let labels = BTreeSet::new();
        let evaluated = policy.evaluate(&DecisionContext {
            server_id: "messages",
            tool: "read_messages",
            arguments: &json!({}),
            active_labels: &labels,
        });
        assert!(evaluated.decision.is_allow());
        assert_eq!(evaluated.sources[0].label, "personal.messages.content");
    }

    #[test]
    fn high_impact_send_requires_exact_approval() {
        let policy = policy();
        let labels = BTreeSet::from(["personal.messages.content".to_owned()]);
        let evaluated = policy.evaluate(&DecisionContext {
            server_id: "messages",
            tool: "send_message",
            arguments: &json!({"recipient": "+15555550100", "message": "hello"}),
            active_labels: &labels,
        });
        assert!(evaluated.effects.contains(&Effect::Send));
        assert!(matches!(
            evaluated.decision,
            Decision::AllowWithObligations { ref obligations, .. }
                if obligations.iter().any(|item| matches!(item, Obligation::HumanApproval { .. }))
        ));
    }

    #[test]
    fn session_taint_blocks_unrelated_network_effect() {
        let source = POLICY.replace(
            "      - id: send\n",
            "      - id: upload\n        tools: [http_upload]\n        effects: [network, upload]\n        decision: allow\n      - id: send\n",
        );
        let policy =
            CompiledPolicy::from_yaml(&source).unwrap_or_else(|error| unreachable!("{error}"));
        let labels = BTreeSet::from(["personal.messages.content".to_owned()]);
        let evaluated = policy.evaluate(&DecisionContext {
            server_id: "messages",
            tool: "http_upload",
            arguments: &json!({"body": "summary"}),
            active_labels: &labels,
        });
        assert!(matches!(
            evaluated.decision,
            Decision::Deny { ref code, .. } if code.0 == "AG-SESSION-TAINT"
        ));
    }

    #[test]
    fn rejects_permissive_default_and_unknown_fields() {
        assert!(
            CompiledPolicy::from_yaml(&POLICY.replace("decision: deny", "decision: allow"))
                .is_err()
        );
        assert!(
            CompiledPolicy::from_yaml(
                &POLICY.replace("kind: GatewayPolicy", "kind: GatewayPolicy\nunknown: true")
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unreviewed_declassification() {
        let source = POLICY.replace(
            "    obligations:\n      - { type: human_approval, display: [/arguments/recipient, /arguments/message], ttl: 60s }\nsessionTaint:",
            "    obligations: []\nsessionTaint:",
        );
        assert!(CompiledPolicy::from_yaml(&source).is_err());
    }
}
