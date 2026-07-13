# System Specification

**Status:** Normative baseline  
**Scope:** AgentGate 1.x stable externally observable behavior and retained preview migration invariants

## 1. Terms

- **Host**: the LLM application that launches or connects to AgentGate.
- **Downstream server**: an MCP server launched by or connected through AgentGate.
- **Tool identity**: stable tuple of server identity, tool name, manifest digest, and protocol version.
- **Effect**: security-relevant consequence such as `read`, `send`, `upload`, `delete`, `purchase`, `execute`, or `network`.
- **Source label**: provenance/sensitivity class attached to data returned by a tool.
- **Sink label**: destination class attached to tool arguments or effects.
- **Session taint**: conservative record that sensitive information entered the agent context during the session.
- **Declassification**: explicit policy-authorized release of labeled information to a sink, normally with approval.
- **Obligation**: an action such as human approval that must complete before forwarding.
- **Canonical envelope**: deterministic representation of tool identity and arguments used for policy, approval, and audit digests.

## 2. Protocol mediation

| ID | Requirement |
| --- | --- |
| FR-001 | AgentGate MUST mediate MCP lifecycle, discovery, tool-call, cancellation, progress, logging, and error messages required by the supported protocol version. |
| FR-002 | AgentGate MUST preserve valid JSON-RPC request IDs and correlate responses without reuse or cross-session confusion. |
| FR-003 | AgentGate MUST NOT forward malformed, unsupported, oversized, or policy-rejected requests. |
| FR-004 | AgentGate MUST treat notifications as non-confirmable and MUST deny any notification that could cause a consequential effect. |
| FR-005 | AgentGate MUST reject or safely decompose JSON-RPC batches containing policy-mediated calls; one approval MUST NOT authorize multiple high-impact actions. |
| FR-006 | AgentGate MUST terminate or quarantine a downstream process that violates framing limits repeatedly. |
| FR-007 | AgentGate MUST expose stable implementation-defined error codes without violating JSON-RPC response rules. |
| FR-008 | AgentGate MUST negotiate only explicitly supported MCP protocol versions and fail closed on incompatible versions. |

## 3. Tool inventory and identity

| ID | Requirement |
| --- | --- |
| FR-010 | AgentGate MUST inventory tools before first invocation and validate names, schemas, annotations, and descriptions against configured limits. |
| FR-011 | The inventory MUST be normalized and hashed; the session audit header MUST include its digest. |
| FR-012 | A changed manifest MUST be evaluated before the changed tool is advertised or invoked. |
| FR-013 | A tool renamed to collide with a trusted identity MUST remain a distinct, untrusted identity. |
| FR-014 | Policy selectors MUST bind to stable server identity plus tool name and MUST optionally pin a manifest digest. |
| FR-015 | Hidden Unicode controls, excessive description size, schema ambiguity, and instruction-like metadata MUST produce findings according to policy. |

## 4. Policy decisions

| ID | Requirement |
| --- | --- |
| FR-020 | Every mediated tool call MUST receive a deterministic decision: `allow`, `deny`, or `allow_with_obligations`. |
| FR-021 | No matching allow rule MUST be equivalent to deny. |
| FR-022 | Explicit deny MUST take precedence over allow; unmet obligations MUST be equivalent to deny. |
| FR-023 | Policy evaluation MUST use the canonical envelope, principal/session context, tool identity, declared effects, provenance, and chain state. |
| FR-024 | Policy configuration MUST be schema validated and compiled before serving traffic. |
| FR-025 | Policy errors or unavailable state MUST NOT fall back to permissive behavior. |
| FR-026 | `policy check` MUST explain matched rules, precedence, obligations, and final decision without executing a tool. |
| FR-027 | `policy test` MUST evaluate version-controlled request/decision fixtures and return a non-zero status on mismatch. |

## 5. Provenance and information flow

| ID | Requirement |
| --- | --- |
| SR-001 | Policy MUST be able to label selected tool-result fields with one or more source labels. |
| SR-002 | AgentGate MUST store keyed fingerprints—not plaintext—for configured sensitive values by default. |
| SR-003 | Before a sink call, AgentGate MUST check structured lineage metadata, exact fingerprints, normalized fingerprints, substring matches above configured thresholds, and session taint. |
| SR-004 | A flow from a sensitive source to an undeclared or unrelated network/upload/send sink MUST be denied by default. |
| SR-005 | Declassification MUST name permitted source labels, destination sink, argument fields, purpose, expiry, and required approval. |
| SR-006 | Declassification approval MUST authorize only the canonical envelope presented to the user. |
| SR-007 | AgentGate MUST record confidence and detection method for each provenance match. |
| SR-008 | AgentGate MUST NOT claim that absence of a fingerprint match proves absence of sensitive derived content. |
| SR-009 | Policy MUST support conservative restrictions on external sinks while a session carries specified taint labels. |
| SR-010 | Provenance state MUST be isolated by session and bounded by configurable count, byte, and lifetime limits. |

## 6. Consequential actions and approval

| ID | Requirement |
| --- | --- |
| SR-020 | `send`, `upload`, `delete`, and `purchase` effects MUST require human approval in v1, regardless of allow rules. |
| SR-021 | Approval MUST show tool/server identity, effect, material arguments, provenance warnings, risk reasons, and expiry. |
| SR-022 | Approval MUST bind to a digest of the canonical envelope, policy digest, and session ID. |
| SR-023 | Approval tokens MUST be single-use, expire quickly, and be consumed atomically before forwarding. |
| SR-024 | Argument, tool-manifest, session, or effective-policy change MUST invalidate pending approval. |
| SR-025 | Timeouts, UI failure, malformed responses, and explicit rejection MUST deny the call. |
| SR-026 | Approval MUST NOT be inferred from conversational text supplied by the agent or a tool. |
| SR-027 | High-impact calls in a batch MUST be approved individually. |
| SR-028 | The user MUST be able to disable a server or terminate a session from the approval surface. |

## 7. Chained-action detection

| ID | Requirement |
| --- | --- |
| SR-030 | AgentGate MUST maintain a bounded session action graph containing tool identities, effects, decisions, provenance edges, and timestamps. |
| SR-031 | Policy MUST match sequences such as sensitive-read then external-send, enumerate then delete, credential-read then network, and repeated denied-action attempts. |
| SR-032 | Chain findings MAY raise risk, add obligations, or deny; model-generated risk scores MUST NOT reduce deterministic controls. |
| SR-033 | Chain state MUST be deterministic and replayable from retained audit metadata. |
| SR-034 | A session reset MUST be explicit and audited; process restart MUST NOT silently merge old chain state into a new session. |

## 8. Tool-description poisoning and integrity

| ID | Requirement |
| --- | --- |
| SR-040 | Tool descriptions, annotations, schemas, icons, and server-provided instructions MUST be treated as untrusted input. |
| SR-041 | Deterministic checks MUST cover hidden/bidirectional controls, credential solicitation, policy override language, unrelated tool instructions, cross-tool coercion, and excessive content. |
| SR-042 | A manifest digest change after trust establishment MUST generate a rug-pull finding before execution. |
| SR-043 | Policy MUST support `deny`, `quarantine`, `require_review`, and `allow_with_warning` responses to descriptor findings. |
| SR-044 | Optional model-assisted analysis MAY add findings but MUST NOT suppress deterministic findings or grant access. |
| SR-045 | Findings MUST quote only a bounded, escaped excerpt to prevent log/UI injection. |

## 9. Audit and replay

| ID | Requirement |
| --- | --- |
| SR-050 | AgentGate MUST append an audit event for session lifecycle, inventory, policy decision, approval, forwarding, response, error, and administrative action. |
| SR-051 | Events MUST form a hash chain over canonical event bytes and sequence number. |
| SR-052 | AgentGate MUST create periodic and shutdown Ed25519 signature checkpoints. |
| SR-053 | Verification MUST detect modified, inserted, deleted, duplicated, and reordered events within the covered chain. |
| SR-054 | Default events MUST retain metadata and keyed digests, not raw sensitive payloads. |
| SR-055 | Payload capture MUST be opt-in, field-limited, encrypted, retention-bounded, and visibly indicated. |
| SR-056 | Dry-run replay MUST reconstruct canonical envelopes, provenance/chain metadata, and decisions without launching or invoking downstream servers. |
| SR-057 | Replay MUST report policy drift between recorded and selected policy digests. |
| SR-058 | Audit failure before a high-impact call MUST fail the call closed. |
| SR-059 | AgentGate MUST distinguish tamper evidence from completeness: a local actor able to delete the entire log remains outside v1 guarantees unless checkpoints are externally anchored. |

## 10. Human experience

| ID | Requirement |
| --- | --- |
| UXR-001 | Prompts MUST use plain effect language such as “send this message” rather than protocol jargon alone. |
| UXR-002 | Sensitive values unrelated to the decision MUST be redacted; material arguments MUST remain reviewable. |
| UXR-003 | Denials MUST include a stable code, short explanation, matched rule/finding, and safe remediation. |
| UXR-004 | Repeated prompts MUST be rate-limited and visibly grouped as suspicious behavior. |
| UXR-005 | Approval MUST require an intentional action and MUST NOT default focus to Allow. |
| UXR-006 | Terminal output MUST remain safe against ANSI/control-sequence injection from server content. |
| UXR-007 | `doctor` MUST identify direct-server configurations that appear to bypass the gateway when detectable. |

## 11. Reference acceptance scenarios

```gherkin
Scenario: Read recent messages through the gateway
  Given mac_messages_mcp is registered with the reference policy
  When the host calls tool_get_recent_messages
  Then AgentGate forwards the request
  And labels configured result content personal.messages
  And the audit log stores no message plaintext by default

Scenario: Exact send approval cannot be reused
  Given the host requests tool_send_message for recipient A and body B
  When the user approves the displayed request
  Then AgentGate forwards exactly one matching call
  And reusing the approval token is denied
  And changing either recipient or body requires new approval

Scenario: Messages cannot flow to an unrelated upload tool
  Given a Messages result introduced personal.messages data
  When the host passes matching content to an unapproved network upload tool
  Then AgentGate does not forward the call
  And the denial identifies the source label and sink policy

Scenario: Transformed data triggers conservative session protection
  Given personal.messages taint exists in the session
  And no exact sensitive fingerprint is present in a later network request
  When policy forbids network sinks during that taint state
  Then AgentGate denies or requires explicit declassification
  And does not claim an exact content match

Scenario: Tool description rug pull
  Given a trusted tool manifest digest was recorded
  When the downstream server advertises a changed description or schema
  Then the changed tool is not invoked before manifest policy completes
  And the audit log records old and new digests

Scenario: Audit mutation is detected
  Given a signed audit checkpoint covers a completed session
  When any covered event is changed or reordered
  Then agentgate audit verify exits non-zero
  And identifies the first invalid chain position
```

## 12. Stable decision codes

| Code | Meaning |
| --- | --- |
| `AG-POLICY-NO-MATCH` | No allow rule matched |
| `AG-POLICY-EXPLICIT-DENY` | A deny rule took precedence |
| `AG-POLICY-INVALID` | Effective policy could not be validated/compiled |
| `AG-APPROVAL-REQUIRED` | Call is paused pending human approval |
| `AG-APPROVAL-DENIED` | User, timeout, or UI failure denied approval |
| `AG-APPROVAL-STALE` | Request/policy/manifest changed after prompt |
| `AG-FLOW-BLOCKED` | Source-to-sink information flow is not authorized |
| `AG-SESSION-TAINT` | Session-level restriction blocked or escalated a sink |
| `AG-MANIFEST-CHANGED` | Tool identity or metadata changed after trust |
| `AG-DESCRIPTOR-POISONING` | Descriptor integrity/content checks failed |
| `AG-CHAIN-RISK` | Suspicious action sequence matched |
| `AG-AUDIT-UNAVAILABLE` | Required audit evidence could not be committed |
| `AG-PROTOCOL-INVALID` | JSON-RPC/MCP message is invalid or unsupported |
| `AG-LIMIT-EXCEEDED` | Size, rate, depth, or resource limit exceeded |
