# Technical Requirements

**Status:** Normative baseline  
**Target:** v1.0; historical preview/bridge annotations remain for compatibility context

## 1. Compatibility baseline

| ID | Requirement | Verification |
| --- | --- | --- |
| TR-001 | AgentGate MUST implement JSON-RPC 2.0 request, notification, response, error, and batch semantics without changing valid request IDs. | Conformance fixtures and differential proxy tests |
| TR-002 | v0.1 MUST support MCP protocol version `2025-11-25` over stdio and MUST explicitly negotiate supported versions. | Official-schema fixtures and reference server integration |
| TR-003 | Unsupported MCP versions or capabilities MUST fail with a bounded diagnostic before tool execution. | Negative negotiation tests |
| TR-004 | v0.1 MUST mediate `initialize`, initialized notification, ping, tool listing/change notifications, tool calls, cancellation, progress, and logging needed by the reference integration. | Lifecycle integration suite |
| TR-005 | v0.2 SHOULD support MCP Streamable HTTP without changing policy semantics or canonical action identity. | Transport contract suite reused across stdio/HTTP |
| TR-006 | AgentGate MUST preserve downstream stdout exclusively for protocol frames; diagnostics MUST use stderr or structured audit output. | Process integration test |

## 2. Implementation platform

| ID | Requirement | Verification |
| --- | --- | --- |
| TR-010 | The enforcement core MUST be implemented in stable Rust using the repository-pinned toolchain. | CI toolchain and build manifest |
| TR-011 | Core types MUST distinguish untrusted wire messages, validated protocol messages, canonical envelopes, policy decisions, approvals, and forwarded messages. | Compile-time API review and unit tests |
| TR-012 | Async tasks MUST have explicit ownership, cancellation, and bounded channels; unbounded queues are prohibited in the mediation path. | Architecture tests and load tests |
| TR-013 | Production code MUST forbid unsafe Rust unless an accepted ADR documents the exact block and safety invariant. | `cargo geiger`/lint gate and review |
| TR-014 | Serialization used for digests/signatures MUST be canonical and versioned; ordinary map serialization MUST NOT be assumed stable. | Golden vectors across builds/platforms |
| TR-015 | All persistent schemas MUST contain a schema version and have forward-error/backward-migration behavior. | Migration fixtures |

## 3. Process and transport controls

| ID | Requirement | Default/target |
| --- | --- | --- |
| TR-020 | Downstream commands MUST be executed without a shell and with an explicit executable plus argument array. | Required |
| TR-021 | Environment inheritance MUST be allowlisted; secret-bearing variables MUST NOT be inherited by default. | Minimal `PATH`, locale, configured values |
| TR-022 | Frames MUST have configurable byte, nesting-depth, string-length, and collection-count limits before full materialization where possible. | 4 MiB frame, depth 64 initial defaults |
| TR-023 | Each request MUST have a deadline; cancellation MUST propagate to downstream work where protocol semantics allow. | Configurable, 60 s tool default |
| TR-024 | Request IDs MUST be unique within outstanding requests per session; duplicates MUST be rejected or safely serialized. | Property tests |
| TR-025 | Gateway shutdown MUST stop accepting calls, resolve/deny pending approvals, attempt bounded downstream termination, append final audit checkpoint, and exit. | Fault-injection tests |
| TR-026 | Repeated malformed frames or limit violations MUST trip a configurable server quarantine threshold. | Default 3 violations/60 s |

## 4. Policy engine

| ID | Requirement | Verification |
| --- | --- | --- |
| TR-030 | Policies MUST be YAML authoring documents validated against a versioned JSON Schema and compiled to a typed immutable IR before use. | Parser/schema/golden tests |
| TR-031 | The evaluator MUST be deterministic, side-effect free, total over validated input, and independent of network/model availability. | Property and replay tests |
| TR-032 | Conflict order MUST be: invariant deny, explicit deny, flow deny, obligations, explicit allow, default deny. | Decision-table tests |
| TR-033 | Policy MUST support server/tool selectors, effects, argument predicates, source/sink labels, chain predicates, rate predicates, and obligations. | Policy conformance suite |
| TR-034 | Regexes MUST use a linear-time engine and have pattern/subject limits. | Dependency selection and adversarial tests |
| TR-035 | Policy loading MUST reject duplicate rule IDs, unknown fields, invalid label references, unreachable rules, and unsafe unconditional declassification. | Linter fixtures |
| TR-036 | Effective policy and compiled IR MUST have stable SHA-256 digests recorded in session/audit state. | Golden vectors |
| TR-037 | Hot reload MAY be supported only at an atomic session boundary in v0.1; in-flight calls MUST retain their original effective policy. | Concurrency tests |

## 5. Canonicalization and approval

| ID | Requirement | Verification |
| --- | --- | --- |
| TR-040 | Canonical action bytes MUST include schema version, session, server identity, tool name, manifest digest, MCP protocol version, normalized arguments, effects, and policy digest. | Published golden vectors |
| TR-041 | JSON canonicalization MUST define UTF-8 handling, numeric normalization, object-key ordering, duplicate-key rejection, and absent-versus-null behavior. | Cross-language/golden tests |
| TR-042 | Approval tokens MUST contain a cryptographically random nonce with at least 128 bits of entropy, action digest, session, policy/manifest digests, issued/expiry times, and UI identity. | Unit/property tests |
| TR-043 | Approval consumption MUST be atomic and durable enough to prevent reuse after concurrent requests or process recovery. | Race and crash-injection tests |
| TR-044 | Terminal approval MUST read from a controlling terminal or dedicated IPC, never from the protocol stdin stream. | Integration test |
| TR-045 | Approval display MUST escape C0/C1 controls, ANSI escapes, bidirectional controls, and unbounded values. | Snapshot/adversarial UI tests |

## 6. Provenance engine

| ID | Requirement | Verification |
| --- | --- | --- |
| TR-050 | Source extraction MUST use policy-declared JSON Pointer/JSONPath-like selectors with deterministic behavior and bounded expansion. | Selector tests |
| TR-051 | Sensitive fingerprints MUST use a per-installation keyed construction; raw SHA-256 of low-entropy values is prohibited. | Cryptographic unit tests |
| TR-052 | Normalization profiles MUST be explicit by label/type and MUST retain detection-method metadata. | Golden normalization cases |
| TR-053 | Fingerprint state MUST be bounded and evicted by documented TTL/LRU rules without crossing session boundaries. | Load/property tests |
| TR-054 | Structured lineage metadata MUST be authenticated when accepted from a host extension; unauthenticated lineage is advisory only. | Forgery tests |
| TR-055 | Session taint transitions MUST be deterministic, audited, and replayable. | State-machine tests |
| TR-056 | The engine MUST never label a no-match result as proof that content is non-sensitive. | API/type and message snapshot tests |

## 7. Descriptor and chain analysis

| ID | Requirement | Verification |
| --- | --- | --- |
| TR-060 | Tool manifests MUST be normalized with a versioned algorithm before hashing. | Golden manifests |
| TR-061 | Descriptor analysis MUST execute before untrusted descriptions are exposed to the host. | Proxy ordering integration test |
| TR-062 | Deterministic detectors MUST be individually attributable by stable finding ID, severity, evidence span, and remediation. | Detector fixtures |
| TR-063 | Unicode normalization MUST preserve a safe original digest and produce an escaped review rendering. | Confusable/control tests |
| TR-064 | The action graph MUST be bounded by event count and time window and MUST not retain raw sensitive argument values. | Memory/load and privacy tests |
| TR-065 | Chain rules MUST operate only on recorded facts and policy classifications; optional semantic signals are additive. | Replay equivalence tests |

## 8. Audit and cryptography

| ID | Requirement | Verification |
| --- | --- | --- |
| TR-070 | Audit events MUST be canonical JSON Lines with monotonic sequence, UTC timestamp, previous hash, event hash, session, event type, and schema version. | Schema and golden-vector tests |
| TR-071 | Event hash MUST cover the canonical event body plus previous hash and domain separator. | Mutation tests |
| TR-072 | Signature checkpoints MUST use Ed25519 via a maintained cryptographic library and include key ID, covered sequence/hash, policy digest, and timestamp. | Known-answer and tamper tests |
| TR-073 | Private keys MUST be created with OS-restrictive permissions; OS keychain integration is a v0.2 SHOULD. | Permission integration tests |
| TR-074 | Key rotation MUST create a signed transition event when the old key is available and preserve verification metadata for prior logs. | Rotation fixtures |
| TR-075 | Audit writes for high-impact actions MUST be flushed before forwarding the action and completion appended afterward. | Crash/fault injection |
| TR-076 | Default records MUST use allowlisted metadata. Raw request/result payload capture MUST require explicit encrypted configuration. | Privacy snapshots |
| TR-077 | Verification MUST work offline with public keys and MUST return machine-readable findings plus non-zero status on failure. | CLI tests |
| TR-078 | Replay MUST not invoke tools, spawn downstream processes, resolve DNS, or make network connections. | Sandbox/network-deny integration test |

## 9. Storage and local security

| ID | Requirement | Verification |
| --- | --- | --- |
| TR-080 | State paths MUST follow platform conventions and reject unsafe ownership/permissions unless an explicit development override is set. | Platform tests |
| TR-081 | Writes MUST use safe create/rename patterns, avoid following attacker-controlled symlinks, and fsync security-critical state where required. | Filesystem race tests |
| TR-082 | Policy, trust, key, approval, and audit state MUST be logically separated and independently permissioned. | Installation test |
| TR-083 | Retention MUST be configurable by age and size; deletion actions MUST be audited without pretending deleted logs remain verifiable. | Retention tests |
| TR-084 | Secrets in memory SHOULD use zeroizing containers where practical and MUST never be included in panic/debug output. | Review and panic snapshots |

## 10. Non-functional requirements

| ID | Requirement | Target |
| --- | --- | --- |
| NFR-001 | Added authorization latency excluding human/downstream time | median <5 ms, p99 <20 ms at 1 MiB or smaller |
| NFR-002 | Idle memory for one stdio server/session | <40 MiB on reference release build |
| NFR-003 | Sustained mediated calls without approval | >=1,000 calls/s for small synthetic payloads on reference machine; benchmark, not universal SLA |
| NFR-004 | Startup to completed downstream initialize | <500 ms excluding downstream startup, measured separately |
| NFR-005 | Test coverage | >=90% branch coverage for protocol/policy/audit/approval core |
| NFR-006 | Fuzz stability | 24-hour nightly corpus campaign with zero crash, hang, or invariant violation before v1 |
| NFR-007 | Reproducibility | Locked dependencies; tagged builds publish checksums, SBOM, provenance, and corpus report |
| NFR-008 | Supported platforms | v0.1 macOS arm64/x86_64 and Linux x86_64; Windows deferred |
| NFR-009 | Observability | Structured local logs/metrics with bounded cardinality and no sensitive payloads by default |
| NFR-010 | Accessibility | Approval content usable without color and keyboard-only; future GUI meets WCAG 2.2 AA |

## 11. Supply-chain and release requirements

| ID | Requirement | Verification |
| --- | --- | --- |
| TR-090 | CI MUST run format, lints with warnings denied, unit/integration/conformance tests, policy fixtures, secret scan, dependency audit, and documentation checks. | Required checks |
| TR-091 | Release builds MUST be produced by pinned workflows with least-privilege tokens and artifact attestations. | Workflow review |
| TR-092 | Dependencies MUST be minimized and reviewed for policy, parser, cryptography, IPC, and transport criticality. | Dependency inventory |
| TR-093 | The repository MUST publish a vulnerability-reporting policy and supported-version matrix before v0.1. | Release gate |
| TR-094 | The malicious corpus MUST contain only synthetic data and isolated mock servers; CI MUST never target real user data or external services. | Corpus review/network isolation |

## 12. Error behavior

- Protocol errors use valid JSON-RPC error objects with implementation codes in the server-error range and stable AgentGate codes inside `error.data`.
- User-facing messages are concise and redacted; detailed local diagnostics use correlation IDs.
- Internal panic, task cancellation, downstream exit, audit I/O failure, and approval UI loss all have explicit fail-closed mappings.
- A response that cannot be safely associated with exactly one outstanding request is discarded, audited, and may quarantine the server.
