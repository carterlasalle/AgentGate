# Technical Design

**Status:** Baseline architecture  
**Decisions:** See [ADRs](adr/README.md)

## 1. Architecture overview

AgentGate is a protocol-aware, bidirectional MCP proxy. In v0.1, an MCP host launches AgentGate over stdio; AgentGate then launches one downstream MCP server as a child process. One gateway process serves one host connection and one downstream server, which minimizes identity ambiguity and failure coupling.

```text
                      control plane
                   +-------------------+
                   | config / policy   |
                   | trust manifests   |
                   | approval provider |
                   | signing keys      |
                   +---------+---------+
                             |
host stdin --> frame --> validate --> session/router ------------------+
                             |                                         |
                             v                                         v
                     inventory/integrity                         response labels
                             |                                         |
                             v                                         |
                    canonical action                                  |
                             |                                         |
               +-------------+-------------+                           |
               | policy + flow + chain     |                           |
               +-------------+-------------+                           |
                             | allow/deny/obligations                   |
                             v                                         |
                      approval broker                                  |
                             |                                         |
                             v                                         |
                       audit precommit                                 |
                             |                                         |
                             v                                         |
                    downstream stdio ----------------------------------+
```

The authorization path is synchronous with respect to forwarding: downstream execution cannot race ahead of the final decision and required audit precommit.

## 2. Workspace layout

Planned Rust workspace:

```text
crates/
  agentgate-cli/          CLI, config discovery, process lifecycle
  agentgate-protocol/     JSON-RPC/MCP wire types, framing, validation
  agentgate-core/         canonical types, session state, decision orchestration
  agentgate-policy/       schema, compiler, typed IR, evaluator, explain output
  agentgate-provenance/   labels, fingerprints, taint state, flow checks
  agentgate-integrity/    manifest normalization and poisoning detectors
  agentgate-approval/     provider trait, terminal provider, token lifecycle
  agentgate-audit/        event schema, hash chain, signatures, verifier/replay
  agentgate-testkit/      fake host/server, deterministic clock/RNG, assertions
fixtures/
  protocol/               JSON-RPC and MCP conformance cases
  policies/               allow/deny and lint cases
redteam/
  cases/                  attack scenario manifests and expected outcomes
  servers/                synthetic malicious MCP servers
examples/
  policies/               reference policies including mac_messages_mcp
```

Crate boundaries keep wire input untrusted until validated and prevent UI/audit modules from reaching downstream transport directly.

## 3. Core data model

```rust
// Illustrative, not final API.
struct ToolIdentity {
    server_id: ServerId,
    name: ToolName,
    manifest_digest: Digest,
    protocol_version: ProtocolVersion,
}

struct CanonicalAction {
    schema_version: u16,
    session_id: SessionId,
    tool: ToolIdentity,
    arguments: CanonicalJson,
    effects: BTreeSet<Effect>,
    policy_digest: Digest,
}

enum Decision {
    Allow { rule_ids: Vec<RuleId> },
    AllowWithObligations { rule_ids: Vec<RuleId>, obligations: Vec<Obligation> },
    Deny { code: DecisionCode, rule_ids: Vec<RuleId>, findings: Vec<Finding> },
}
```

Opaque newtypes are used for IDs, digests, labels, and canonical bytes. Raw `serde_json::Value` is confined to protocol validation and selector boundaries.

## 4. Request lifecycle

### 4.1 Lifecycle/discovery

1. Parse a length/newline-framed JSON-RPC message with resource limits.
2. Validate request structure and MCP lifecycle state.
3. Forward supported initialization messages and record negotiated capabilities.
4. Intercept `tools/list` results.
5. Validate and normalize each tool manifest.
6. Run deterministic descriptor detectors and compare trusted digest state.
7. Remove quarantined tools; annotate or expose remaining tools according to policy.
8. Record the effective inventory digest.

### 4.2 Tool call

1. Resolve the advertised tool identity; reject stale or unknown names.
2. Validate arguments against the advertised schema plus gateway limits.
3. Canonicalize the exact action.
4. Classify effects and sink fields from compiled policy; built-in high-impact heuristics can only add effects.
5. Query provenance fingerprints/session taint for sink arguments.
6. Extend the tentative action graph and evaluate chain rules.
7. Evaluate invariant denies, explicit rules, flows, and obligations.
8. If approval is required, present the canonical material action and await a bound token.
9. Append/flush `decision` and required `approval` audit events.
10. Atomically consume approval and forward the original validated arguments corresponding to the digest.
11. Correlate the downstream response, apply source selectors/labels, register fingerprints, and update chain state.
12. Append response metadata and return a protocol-valid response to the host.

The original untrusted request is never forwarded after canonicalization unless its re-derived digest equals the authorized digest.

## 5. Policy compilation and evaluation

The authoring format is strict YAML, parsed with duplicate-key rejection and validated against a checked-in JSON Schema. Compilation resolves:

- server and tool selectors;
- label/effect references;
- argument selectors and predicates;
- source-to-sink flow matrix;
- chain automata and rate windows;
- approval/display templates;
- precedence into an immutable ordered decision graph.

Evaluation is a pure function of compiled policy plus `DecisionContext`. It returns the decision and a bounded explanation tree. Policy cannot execute code, perform I/O, call a model, read environment variables, or mutate session state.

State transitions—registering provenance, consuming approval, committing an action graph node—occur only after explicit orchestration steps and audit records.

## 6. Provenance model

### 6.1 Labels

Labels are hierarchical strings such as:

- `personal.messages.content`
- `personal.messages.attachment`
- `personal.contacts`
- `secret.credential`
- `untrusted.web`

Policy may match an exact label or a documented subtree. Labels carry origin tool identity, session, selector, timestamp, and retention class.

### 6.2 Transparent-proxy detection

For configured result fields, the gateway derives keyed fingerprints for:

- exact canonical scalar bytes;
- type-specific normalization (phone, email, whitespace/text, path);
- bounded substrings/chunks for values above a minimum entropy/length threshold.

Later sink arguments are checked against these fingerprints. The keyed construction prevents offline guessing of low-entropy values from stored audit/state.

### 6.3 Session taint

Because an LLM can summarize or transform sensitive text beyond fingerprint recognition, policy may mark the session as carrying a label after a sensitive read. A session-taint rule can deny all unrelated external sinks or force explicit declassification even without an exact match.

This is intentionally conservative. The decision explanation distinguishes `exact`, `normalized`, `substring`, `authenticated_lineage`, and `session_taint` evidence.

### 6.4 Host-assisted lineage

A future host extension can attach authenticated lineage references to tool arguments. AgentGate verifies them using a per-session key negotiated out of band. Without authentication, host-provided lineage can raise risk but cannot establish safe declassification.

## 7. Approval protocol

`ApprovalProvider` receives only a bounded `ApprovalRequest`:

```text
request ID, action digest, server/tool, effects, material rendered fields,
provenance warnings, matched rules/findings, issued time, expiry
```

The provider returns `approve`, `deny`, or `terminate_session` plus the action digest and provider identity. The broker adds a random nonce, signs/MACs local IPC where applicable, stores pending/consumed state, and validates time/session/policy/manifest equality.

Terminal v0.1 uses `/dev/tty` (or platform equivalent), never protocol stdin. Default focus is deny, values are control-escaped, and values over display limits show a digest plus bounded preview. “Always allow” is prohibited for v1 high-impact effects.

## 8. Manifest integrity and poisoning detection

Normalization covers server identity, tool name, title, description, input/output schemas, annotations, and protocol version. Object keys are sorted; irrelevant presentation differences are explicitly defined before the algorithm is frozen.

Deterministic detector families:

- hidden/bidirectional/control Unicode;
- instructions to ignore policy, user, host, or prior constraints;
- requests for credentials/secrets unrelated to tool arguments;
- claims that another tool must be called or data sent elsewhere;
- descriptions that redefine other tools or imitate system messages;
- schema/description mismatches and unconstrained argument shapes;
- oversized/repetitive text intended to dominate context.

A trust store records approved digests. Any change is reviewed according to policy before advertisement or execution. A model-assisted scanner is an optional out-of-process signal and never runs in the allow path by default.

## 9. Action graph and chain rules

Each committed node contains:

```text
sequence, timestamp, tool identity, effect set, decision, source labels introduced,
sink labels targeted, finding IDs, argument digest, response digest/status
```

Edges represent temporal order, response-to-argument fingerprint match, authenticated lineage, and approval/declassification. Raw values are excluded.

Chain rules compile to bounded state machines, for example:

```text
sensitive_read -> unrelated_network within 10m => deny
credential_read -> execute within session        => require_approval
list_many -> delete repeated >= 3 within 60s     => deny + terminate_option
deny(code=X) repeated >= 3 within 30s            => quarantine_session
```

## 10. Audit format

The audit store is append-only JSONL. Event bodies use a canonical JSON profile; each event includes `previous_hash`, and `event_hash` is computed with a domain separator and schema version. Periodic checkpoint events sign the covered sequence and hash with Ed25519.

Event types include:

- `session_started`, `session_ended`;
- `policy_loaded`, `inventory_observed`, `manifest_finding`;
- `call_received`, `decision_made`, `approval_requested`, `approval_resolved`;
- `call_forwarded`, `response_observed`, `provenance_registered`;
- `limit_triggered`, `downstream_exited`, `checkpoint_signed`;
- `trust_changed`, `key_rotated`, `retention_applied`.

The default event records stable IDs, effect/label sets, rule/finding IDs, sizes, timings, and keyed digests. It excludes argument/result plaintext.

### Verification guarantees

Given the starting checkpoint/public key and retained chain, verification detects event mutation, insertion, deletion within the chain, duplication, and reordering. Local-only storage cannot prove that the entire file was not deleted. Optional external checkpoint anchoring is deferred.

### Replay

Replay reads audit events into an isolated evaluator with deterministic recorded clock/state. It never starts transports. It can verify original decisions or compare them to another compiled policy, producing a drift report.

## 11. Failure handling

| Failure | Behavior |
| --- | --- |
| Invalid host frame | JSON-RPC error when safe; audit; no forwarding |
| Downstream malformed response | Discard; correlate error to host when possible; count toward quarantine |
| Policy unavailable/invalid | Refuse startup or deny all calls |
| Approval UI unavailable/timeout | Deny pending call |
| Audit precommit fails | Deny high-impact call; configurable deny-all is recommended/default |
| Audit completion write fails after external side effect | Return cautious error/status, alert loudly, preserve recovery marker; never retry side effect automatically |
| Downstream exits | Fail outstanding requests once, audit, bounded cleanup; no automatic side-effect retry |
| Internal task panic | Cancel session and fail closed; avoid unwinding secrets into diagnostics |

## 12. Observability

- Structured stderr logs are operational and separate from signed audit evidence.
- Metrics use bounded labels: decision code, effect, detector ID, latency bucket, transport, and outcome—not tool arguments, user data, raw tool names from untrusted servers, or session IDs.
- Trace/correlation IDs are random and not approval credentials.
- Diagnostic bundles redact configuration secrets and payloads by construction.

## 13. `mac_messages_mcp` reference integration

The adapter policy classifies:

| Tool family | Effect/source |
| --- | --- |
| `tool_get_recent_messages`, `tool_fuzzy_search_messages` | `read`; source `personal.messages.content` |
| `tool_search_attachments` | `read`; source `personal.messages.attachment_metadata` |
| `tool_get_attachment` | `read_file`; source `personal.messages.attachment` |
| `tool_find_contact` and availability lookups | `read`; source `personal.contacts` |
| `tool_send_message` | `send`; sink `external.messages`; mandatory approval |

The demo pairs this server with a synthetic unrelated upload MCP server. It proves permitted reads, exact send confirmation, blocked content upload, descriptor rug-pull quarantine, and audit verification/replay.

## 14. Security-sensitive implementation notes

- Do not deserialize arbitrary values into recursive types without configured limits.
- Do not render untrusted strings before escaping controls and applying byte/grapheme limits.
- Do not compare approval or digest bytes with ordinary equality where timing matters.
- Do not retry unknown-outcome side effects.
- Do not use wall-clock alone for elapsed approval/rate decisions; combine monotonic time with recorded UTC.
- Do not let configuration interpolation read arbitrary environment variables.
- Do not trust MCP annotations such as read-only/destructive hints; policy can compare them but owns final classification.
