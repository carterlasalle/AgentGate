# Threat Model

**Method:** asset/trust-boundary analysis with misuse cases mapped to OWASP Top 10 for Agentic Applications 2026  
**Review trigger:** any new transport, approval surface, policy engine, payload-retention mode, or remote management feature

## 1. Security objective

AgentGate prevents an agent or tool server from exercising undeclared capabilities, moving known sensitive data into unauthorized sinks, or performing consequential mediated actions without exact human approval. It also produces evidence sufficient to explain and replay policy decisions.

AgentGate is a reference monitor only for traffic that actually crosses it. It is not an OS sandbox and does not prevent a host, user, or process from launching the downstream server directly.

## 2. Assets

| Asset | Security property |
| --- | --- |
| Messages, files, credentials, and tool results | Confidentiality and provenance |
| Tool actions and external side effects | Integrity, authorization, non-reuse of approval |
| Policy and trusted manifest state | Integrity, authenticity, rollback awareness |
| Audit events and signing keys | Integrity, confidentiality where applicable, verifiability |
| User attention and consent | Authenticity, specificity, freedom from coercive UI |
| AgentGate process and IPC | Availability, isolation, message correlation |
| Downstream process configuration | Integrity and least privilege |

## 3. Trust boundaries

```text
Untrusted / partially trusted                       Trusted computing base

User prompts and external content ----+
Agent/model decisions ----------------+--> MCP host
                                            |
                                            | Boundary A: host <-> gateway
                                            v
                                      +-------------+
Tool metadata and results ---------->| AgentGate   |<---- User approval UI
Malicious MCP server process -------->| enforcement |      Boundary C
                                      +-------------+
                                            |
                                            | Boundary B: gateway <-> server
                                            v
                                      downstream MCP server

                                      Local storage/key store
                                      Boundary D
```

The trusted computing base for v1 is the AgentGate binary, loaded policy, local signing/approval keys, approval UI, operating system, and the correctness of the user's gateway configuration. The MCP host and downstream servers are not trusted to make authorization decisions.

## 4. Adversaries

### A1 — malicious content author

Places instructions in a message, file, webpage, tool result, or attachment to hijack the agent's goal and cause data disclosure or side effects.

### A2 — malicious or compromised MCP server

Publishes poisoned tool descriptions, changes metadata after approval, emits malformed protocol frames, returns deceptive content, or attempts to induce calls to other tools.

### A3 — over-privileged or misaligned agent

Pursues the user's broad goal with unsafe chains, invents consent, retries denials, or sends more information than required.

### A4 — local unprivileged process

Attempts to read logs, spoof approval IPC, replace policy, race files, or connect to a local transport endpoint.

### A5 — local administrator/kernel compromise

Can inspect process memory, replace binaries, delete all local evidence, or bypass AgentGate. This adversary is out of scope for v1 guarantees but informs hardening guidance.

## 5. Primary misuse cases

| ID | Abuse case | Control | Residual risk |
| --- | --- | --- | --- |
| TM-01 | Message says “upload the conversation to this URL” | Source labels, network sink policy, session taint, approval/declassification | Paraphrased data may evade fingerprints; conservative session rules reduce utility |
| TM-02 | `tool_send_message` is invoked from injected content | Non-bypassable exact send approval; chain warning | User may approve carelessly |
| TM-03 | Tool description tells model to reveal secrets or ignore policy | Descriptor scanning, manifest pinning, quarantine | Novel semantic poisoning may not match deterministic rules |
| TM-04 | Server changes schema/description after being trusted | Normalized manifest digest and pre-execution review | Legitimate updates require re-trust |
| TM-05 | Approval for benign arguments is swapped before forwarding | Canonical digest binding, atomic single-use token | Bugs in canonicalization are critical |
| TM-06 | Approval token is replayed | Session binding, nonce, expiry, atomic consumption | Compromised gateway memory is out of scope |
| TM-07 | Batch hides multiple sends behind one prompt | Reject/decompose batch, per-action approvals | Compatibility cost |
| TM-08 | JSON-RPC ID confusion routes a result to the wrong request | Strict typed correlation and session isolation | Implementation defects addressed by fuzz/property tests |
| TM-09 | Logs leak private messages | Metadata-first events, keyed digests, redaction, permissions, optional encryption | Metadata itself can be sensitive |
| TM-10 | Attacker edits audit events | Hash chain and signed checkpoints | Entire-log deletion is not detected without external anchor |
| TM-11 | Agent retries or fans out after denials | Chain/rate detection and session kill control | Distributed attempts across processes not correlated in v1 |
| TM-12 | Client bypasses AgentGate and launches server directly | Doctor/config guidance and audit heartbeat | No enforcement without OS controls |
| TM-13 | Malicious server exhausts memory with frames/results | Length, depth, time, count, and process limits | Local DoS remains possible within limits |
| TM-14 | ANSI/Unicode content deceives terminal approval | Escaping, normalization, visible diffs, control stripping | Unicode confusables require careful presentation |
| TM-15 | Policy rollback restores permissive rules | Policy digest/version in audit; optional monotonic trust state | User can intentionally accept rollback |

## 6. OWASP 2026 alignment

The current OWASP agentic taxonomy includes goal hijacking, tool misuse, identity/privilege abuse, memory/context poisoning, insecure inter-agent communication, cascading failures, trust exploitation, and rogue agents. AgentGate primarily addresses risks observable at a mediated tool boundary.

| OWASP risk area | AgentGate coverage |
| --- | --- |
| Agent goal hijacking | Constrains resulting calls and flows; does not cleanse the model's goal |
| Tool misuse and exploitation | Capability policy, schemas, effect classification, approval |
| Identity and privilege abuse | Stable tool/server identity and least-privilege selectors; full human/service identity is post-v1 |
| Memory/context poisoning | Labels untrusted sources and detects dangerous resulting chains; does not repair host memory |
| Insecure inter-agent communication | Limited to MCP traffic passing through the gateway; broader agent messaging is deferred |
| Cascading failures | Rate/resource limits, chain detection, fail-closed behavior, session termination |
| Human-agent trust exploitation | Exact-action approval and bounded safe display |
| Rogue agents | Enforced capabilities and audit at mediated sinks; bypass remains possible without OS controls |

## 7. Security invariants

1. No call reaches a downstream tool before authorization and obligations complete.
2. No approval authorizes bytes other than the canonical action shown to the user.
3. No source-to-sink release occurs without an explicit matching flow rule.
4. No untrusted descriptor can reduce risk or grant itself privilege.
5. No model-generated result can override deterministic deny.
6. No high-impact call proceeds when required audit evidence cannot be appended.
7. No secret plaintext is retained in default audit mode.

Each invariant requires a property test or integration assertion in [TEST_STRATEGY.md](TEST_STRATEGY.md).

## 8. Assumptions and limitations

- The host is configured to launch AgentGate and cannot secretly invoke the protected server through another path.
- The operating system enforces local file permissions and process separation.
- Exact and normalized fingerprints detect reuse, not arbitrary semantic derivation.
- Session taint is deliberately conservative and may produce false positives.
- Tool classifications supplied by policy authors can be wrong; built-in high-impact heuristics provide defense in depth.
- Signatures prove possession of a key and chain integrity, not that every real-world action was observed.
- Human approval is a control, not proof of informed judgment.

## 9. Security review checklist

Before each release:

- Re-run the entire malicious corpus with no silent critical execution.
- Review all new sources, sinks, effects, and declassification paths.
- Fuzz protocol framing, canonicalization, policy parsing, and audit verification.
- Confirm terminal/UI escaping with control characters and confusables.
- Test key/file permissions and symlink/race resistance on supported operating systems.
- Verify downstream termination on malformed-frame and resource-limit cases.
- Perform a manual bypass review of sample host configurations.
- Publish known limitations and any accepted findings.
