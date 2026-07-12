# Product Requirements Document

**Product:** AgentGate  
**Status:** Baseline  
**Target release:** v0.1 local developer preview, followed by v1.0 security-stable local gateway  
**Primary integration:** `mac_messages_mcp`

## 1. Executive summary

AI agents can combine private context with tools that send, upload, delete, purchase, or execute. Today, authorization is often reduced to a broad server install prompt or a tool description that the tool server itself supplies. That leaves users unable to express or verify rules such as “Messages may be searched locally, but message content must not be uploaded” or “show me the exact recipient and body before sending.”

AgentGate is a local, protocol-aware enforcement point between an MCP host and MCP servers. It mediates every JSON-RPC message, grants only declared capabilities, tracks sensitive result provenance, blocks unsafe cross-tool flows, detects suspicious or changed tool metadata, obtains action-specific approval, and emits signed, replayable audit evidence.

The flagship demo protects `mac_messages_mcp`: an agent may search local conversations, but it cannot send a message without exact user confirmation and cannot copy message content into an unrelated network tool without a separately authorized declassification.

## 2. Problem statement

Current agent/tool integrations have five structural weaknesses:

1. Installation trust is coarse while individual calls differ radically in consequence.
2. Tool descriptions are untrusted input yet influence model behavior.
3. Agents compose individually reasonable calls into unsafe chains.
4. Sensitive values lose visible origin as they move through model context.
5. Logs are usually incomplete, mutable, or too sensitive to retain safely.

MCP's current specification explicitly requires implementors to provide consent, access control, data protection, and caution around untrusted tool descriptions. AgentGate turns those responsibilities into a reusable local control plane.

## 3. Product goals

| ID | Goal | v1 success evidence |
| --- | --- | --- |
| PG-01 | Mediate MCP tool traffic without modifying the protected server | `mac_messages_mcp` runs behind the stdio gateway with normal read behavior |
| PG-02 | Enforce least-privilege capabilities with reviewable policy-as-code | Undeclared tools and effects fail closed; policy tests run in CI |
| PG-03 | Prevent sensitive cross-tool disclosure | Red-team cases moving Messages/file data to network sinks are blocked or explicitly approved |
| PG-04 | Put humans in control of consequential actions | Sends, uploads, deletions, and purchases always display exact-action confirmation |
| PG-05 | Detect tool and workflow manipulation | Descriptor changes, poisoning indicators, and suspicious call chains generate deterministic findings |
| PG-06 | Produce trustworthy forensic evidence | Audit verification detects mutation, deletion, insertion, and reordered events |
| PG-07 | Be credible as a security engineering portfolio project | Public threat model, ADRs, attack corpus, benchmarks, demo, and reproducible test results ship together |

## 4. Non-goals

v1 does not:

- guarantee safety for tool calls that bypass AgentGate;
- sandbox arbitrary downstream server code at the OS/kernel boundary;
- prove semantic equivalence or recover perfect lineage after arbitrary model transformation;
- replace endpoint security, secrets management, or host authentication;
- make autonomous high-impact purchases or irreversible actions safe without a person;
- provide a hosted multi-tenant control plane;
- support every agent protocol or vendor-specific function-call format;
- use an LLM as the final authorization authority.

## 5. Users and jobs

### Primary: security-conscious agent developer

Wants to connect local/private tools to an AI client while constraining what the agent can do. Needs a readable policy, deterministic denials, fixtures, and an explanation of each decision.

### Secondary: security researcher or reviewer

Wants to reproduce attacks, inspect enforcement logic, verify audit evidence, and measure bypass resistance without trusting a hosted service.

### Secondary: privacy-sensitive power user

Wants exact confirmation before external side effects and a comprehensible local history of what data and tools were involved.

## 6. Core user journeys

### J1 — protect a local MCP server

1. User points AgentGate at a downstream stdio MCP command.
2. `agentgate doctor` validates the command, policy, key store, and data directory.
3. AgentGate inventories tools and shows capability/effect classification.
4. User installs AgentGate—not the raw server command—in the MCP host.
5. Each session records the effective policy and tool-manifest digests.

### J2 — safely read Messages

1. Agent calls `tool_get_recent_messages` or a search tool.
2. Policy permits the read and labels selected result fields `personal.messages`.
3. AgentGate records provenance without storing plaintext by default.
4. The value may be used by approved local transforms, but network sinks remain restricted.

### J3 — confirm a send

1. Agent calls `tool_send_message` with recipient and body.
2. AgentGate canonicalizes arguments and pauses forwarding.
3. User sees server, tool, recipient, body preview, provenance warnings, and risk reasons.
4. Approval authorizes only that exact digest, once, before expiry.
5. Any argument change causes a new prompt; denial returns a stable MCP error.

### J4 — block cross-tool exfiltration

1. An agent reads private message content.
2. It attempts to pass that content to an unrelated HTTP/upload tool.
3. AgentGate matches structured lineage or sensitive fingerprints, considers session taint, and denies the flow by default.
4. The audit record explains source label, destination sink, matching rule, and policy decision.

### J5 — detect a poisoned tool

1. A server advertises a description containing hidden instructions, secret requests, or attempts to override policy.
2. AgentGate validates schema, normalizes content, evaluates deterministic indicators, and compares the signed/snapshotted manifest.
3. High-confidence violations quarantine the tool; lower-confidence changes require review.

### J6 — investigate and replay

1. User verifies the hash chain and signature checkpoints.
2. User filters a session by tool, decision, risk, or provenance label.
3. Dry-run replay re-evaluates recorded canonical envelopes against a selected policy without executing downstream tools.
4. Differences are reported as policy drift.

## 7. Scope by release

### v0.1 developer preview

- Transparent MCP stdio proxy and lifecycle mediation.
- Schema-validated YAML policy compiled to a typed internal representation.
- Allow/deny, capability, effect, and approval rules.
- Source/sink labels, exact and normalized sensitive-value fingerprints, and conservative session taint.
- Terminal approval UI.
- JSONL hash-chained audit log with Ed25519 checkpoints.
- Tool-manifest inventory, digest pinning, and deterministic poisoning rules.
- `mac_messages_mcp` policy pack and end-to-end demo.
- Synthetic malicious MCP servers and attack corpus.

### v0.2 hardening

- Streamable HTTP transport.
- OS-native approval helper and key storage.
- Encrypted optional payload escrow.
- Policy simulation/diff tooling and richer forensic queries.
- Signed release artifacts and SBOM.

### v1.0 security-stable

- Backward-compatibility policy for config and audit schemas.
- Published security assessment against the full corpus.
- Fault-injection, fuzzing, and performance gates enforced in CI.
- Upgrade/migration and incident-response documentation.

## 8. Product requirements

The normative behaviors live in [the system specification](SPECIFICATION.md). Product-level release invariants are:

- No downstream tool call may execute before policy returns `allow` and all required obligations complete.
- Sends, uploads, deletions, and purchases always require exact-action human approval in v1.
- Invalid or missing policy, corrupted state, audit initialization failure, or ambiguous tool identity fails closed.
- Sensitive payloads are not written to logs by default.
- Model-based classifiers can raise risk or require review but cannot turn a deterministic denial into an allow.
- Replay is dry-run by default and cannot perform side effects without a separate explicit unsafe mode that is excluded from v1.

## 9. Success metrics

### Security effectiveness

- 100% of high-impact reference actions produce an approval obligation.
- 100% of known exact/normalized sensitive-value exfiltration cases are denied.
- 100% of manifest rug-pull cases are detected before affected tool execution.
- At least 95% of the versioned malicious corpus is prevented or surfaced for confirmation; no critical corpus case silently executes.
- 100% of single-event audit mutations and chain reorderings are detected.

### Compatibility and usability

- `mac_messages_mcp` read workflows pass unchanged through AgentGate.
- Median added policy latency is under 5 ms and p99 under 20 ms, excluding approval wait and downstream execution, on the documented reference machine.
- A new user can install the reference config and complete a safe read plus confirmed send demo in under 10 minutes.
- Every denial includes a stable code, human reason, rule ID, and remediation hint that does not reveal secrets.

### Engineering quality

- Core policy, protocol, audit, and approval modules maintain at least 90% branch coverage.
- Zero known critical/high dependency vulnerabilities at release, with documented exceptions for false positives.
- Reproducible corpus and benchmark reports are attached to tagged releases.

## 10. Risks and mitigations

| Risk | Impact | Product response |
| --- | --- | --- |
| False confidence from imperfect taint propagation | Sensitive transformed data may escape | Document boundary; conservative session taint; explicit declassification; adversarial tests |
| Prompt fatigue | Users approve dangerous actions reflexively | Exact concise prompts, batching prohibited for high-impact actions, rate limits, default deny |
| Gateway bypass | Controls are ineffective | Doctor/config checks, clear deployment verification, audit heartbeat; do not claim OS-level enforcement |
| Malicious downstream server | Poisoned metadata or responses manipulate agent | Manifest pinning, schema limits, output labeling, server isolation guidance |
| Audit log becomes sensitive | Forensics creates a new data store | Metadata-first capture, redaction, local permissions, optional encryption, retention limits |
| Policy complexity causes mistakes | Legitimate work blocked or data exposed | Narrow DSL, schema validation, linting, tests, explain mode, safe examples |
| Compatibility drift | MCP changes break mediation | Pin supported protocol versions, conformance suite, explicit negotiation, upgrade ADRs |

## 11. Launch gates

v0.1 cannot be labeled a developer preview until:

1. The reference Messages read/send journeys pass on macOS.
2. All critical red-team scenarios have expected outcomes and CI coverage.
3. Audit mutation and replay tests pass.
4. Policy docs, example policy, threat model, and limitations are published.
5. A clean machine installation is reproduced from the README.
6. No known critical defect permits a denied call to reach a downstream server.

v1.0 additionally requires external review of the threat model and cryptographic design, signed artifacts, SBOM/provenance, and stable schema migration tests.

## 12. Open product decisions

- Which OS-native approval surfaces should follow the terminal UI: macOS menu bar, desktop helper, or both?
- Should v0.2 support multiple downstream servers through one gateway process or one hardened process per server?
- Which license best supports broad defensive adoption while preserving clear attribution?
- What corpus subset can be safely published without creating unnecessary exploit packaging?
