# Test Strategy

**Objective:** demonstrate that AgentGate enforces its stated boundary, fails closed under faults, remains protocol-compatible, and does not overclaim protection outside observable evidence.

## 1. Test principles

- Assert negative space: a denied action was not observed by downstream.
- Test outcomes and audit evidence together.
- Use deterministic time, randomness, keys, and process fixtures where security logic depends on them.
- Separate compatibility, prevention, detection, and human-confirmation outcomes.
- Keep all CI attacks synthetic, hermetic, and network-disabled.
- Preserve discovered bypasses as regression or expected-limitation cases.
- Fuzz parsers and state machines; do not rely only on example tests.

## 2. Test layers

| ID | Layer | Purpose | Runs |
| --- | --- | --- | --- |
| T-01 | Unit | Pure parser, canonicalizer, evaluator, detector, crypto wrapper behavior | Every change |
| T-02 | Property/state machine | Invariants across generated inputs, orderings, races, failures | Every change/extended scheduled |
| T-03 | Protocol conformance | JSON-RPC/MCP lifecycle and transport compatibility | Every change |
| T-04 | Component integration | Real crates with in-memory boundaries and deterministic dependencies | Every change |
| T-05 | Process integration | Host↔gateway↔fake/real stdio server, lifecycle and OS behavior | Every change on primary OS; matrix scheduled |
| T-06 | Policy fixtures | Authoring validation, decision/explanation outcomes | Every change |
| T-07 | Adversarial corpus | Multi-step attacks and malicious servers | Critical subset every change; full scheduled/release |
| T-08 | Fuzzing | Hostile bytes, JSON, schemas, policy, canonicalization, event verification | Smoke every change; extended scheduled/release |
| T-09 | Fault injection | I/O errors, crashes, timeouts, partial writes, cancellation, unknown outcomes | Scheduled/release |
| T-10 | Performance/resource | Latency, throughput, memory, bounds, regression | Scheduled/release |
| T-11 | Flagship acceptance | `mac_messages_mcp` read/send/exfiltration/integrity/audit story | Release and macOS changes |
| T-12 | Supply chain/release | Dependencies, SBOM, provenance, signatures, clean install | Every change subset; full release |

## 3. Security-invariant tests

| Invariant | Required tests |
| --- | --- |
| No forwarding before allow/obligations | Fake server call count at every failure/cancellation point; randomized state transitions |
| Approval binds exact action | Changed field/tool/policy/manifest/session, expiry, concurrent replay, token forgery |
| Flow requires explicit rule | Exact/normalized/chunk evidence, missing flow, wrong destination/field/purpose, forged lineage, taint no-match |
| Descriptor cannot self-authorize | Poisoned annotations/descriptions/schemas, finding suppression attempts, identity collision, rug pull |
| Model cannot override deterministic deny | Absent/error/allow-suggesting model signal yields same deny |
| High-impact call needs audit | Disk full/permission/partial write before forward; completion failure after known side effect |
| Default logs contain no plaintext | Snapshot and token scan across all event types/error paths/panics |

## 4. Protocol matrix

JSON-RPC cases:

- request/response with string, integer, and edge-case valid IDs;
- notifications with no responses;
- standard and implementation errors;
- valid mixed batch, all-notification batch, empty/invalid batch;
- duplicate/unknown IDs, late responses, cancellation races;
- malformed UTF-8/JSON, duplicate keys, depth/size/count limits;
- child stdout contamination and stderr separation.

MCP cases:

- supported/unsupported version negotiation;
- initialize ordering and capability mismatch;
- `tools/list`, pagination if supported, list-changed notifications;
- tool calls/results/errors and cancellation/progress;
- stale inventory and manifest change;
- server exit/restart and session isolation.

Differential tests compare an allow-all safe read fixture through AgentGate with direct fake/reference server behavior, excluding expected gateway annotations/errors.

## 5. Policy test matrix

Every rule needs:

- intended positive match;
- near-miss tool/server identity;
- boundary values for each argument predicate;
- explicit-deny conflict and file-order permutation;
- missing/unknown/malformed fields;
- explanation tree and stable decision code;
- audit rule IDs and effective policy digest;
- compile/lint failure where an unsafe configuration is possible.

Mutation testing targets precedence and predicate code. A surviving mutation in default deny, explicit-deny precedence, obligation creation, or declassification is release-blocking.

## 6. Provenance cases

### Expected deterministic matches

- exact message/contact/path copy;
- case/whitespace/Unicode normalization defined by profile;
- E.164/contact normalization;
- bounded substring/chunk reuse above thresholds;
- nested objects/arrays selected from tool results;
- authenticated lineage references.

### Expected uncertainty

- paraphrase, summary, translation, arithmetic/aggregation, encryption/encoding outside configured normalization;
- very short/low-entropy values;
- data introduced outside mediated sources.

These cases must not be marked safe. Policy/session-taint outcomes are asserted separately from fingerprint outcomes.

### Privacy/resource tests

- fingerprints differ across installation keys;
- raw low-entropy SHA lookup is impossible from retained state;
- TTL/LRU/count/byte bounds hold under adversarial results;
- state never crosses sessions;
- panic/debug/audit output contains no source plaintext.

## 7. Approval cases

- allow, deny, timeout, provider loss, malformed provider response, terminate session;
- exact recipient/body/path/amount rendering with redaction of unrelated data;
- empty, huge, multiline, ANSI, bidi, zero-width, homoglyph, and invalid-control content;
- default focus/keyboard behavior and no-color rendering;
- nonce entropy interface, expiry boundary, monotonic/wall-clock changes;
- simultaneous identical approvals, consume crash points, stale reload;
- five rapid requests produce fatigue/chain warning without batch authorization;
- downstream unknown outcome is not retried.

## 8. Descriptor/integrity cases

Detector fixtures include positive and legitimate near-miss examples for:

- hidden/bidirectional controls;
- “ignore previous/system/policy” instructions;
- credential/secret solicitation;
- cross-tool calls or uploads unrelated to the described operation;
- imitation of host/system messages;
- schema/description mismatch and unconstrained shapes;
- context-flood/repetition;
- changed description, schema, annotations, and tool name after trust;
- same display name from a different server identity.

Evidence excerpts are snapshot-tested for escaping and bounds.

## 9. Audit verification matrix

Starting from a valid signed fixture, independently:

- flip one byte in every field class;
- insert, remove, duplicate, and reorder events;
- truncate before/after checkpoint;
- replace previous/event hash;
- forge key ID/signature/checkpoint coverage;
- rotate keys correctly and incorrectly;
- concatenate sessions/logs;
- use future/unknown schema and invalid canonical bytes;
- delete the whole log and confirm documentation/CLI does not claim detection.

Replay tests freeze clock and state, deny process spawn/network syscalls where practical, reproduce recorded decisions, and explain drift under modified policy.

## 10. Fault-injection matrix

Inject before and after every security-critical transition:

| Fault | Assertions |
| --- | --- |
| Host disconnect | Pending calls cancel/deny; no unauthorized forward; session end evidence |
| Downstream exit/hang | Outstanding calls resolve once; no side-effect retry; bounded termination |
| Approval provider exit | Deny and audit; protocol stream unaffected |
| Audit disk full/permission/partial write | Pre-forward high-impact deny; integrity of last committed event |
| Policy/trust file replaced mid-session | Immutable snapshot for in-flight call; safe next-session/reload behavior |
| Clock jump | Expiry uses monotonic elapsed logic; UTC remains evidence only |
| Task panic/channel closure | Session fail closed and bounded cleanup |
| SIGTERM/interrupt | Stop intake, deny pending approval, checkpoint if possible, terminate child |

## 11. Red-team corpus schema and outcomes

Each case names requirements and threat IDs, fixture versions, ordered steps, and expected:

- policy decision/code/rules;
- whether human confirmation appears;
- downstream call count and exact safe digest where applicable;
- detector/provenance evidence method;
- audit event subsequence;
- final session/quarantine state;
- known limitation.

Allowed outcome vocabulary:

- `prevented`: unsafe action did not reach downstream;
- `confirmed`: action reached downstream only after valid exact human approval;
- `detected`: finding/evidence emitted, but prevention was not in scope;
- `not_detected`: expected limitation/bypass requiring explicit rationale;
- `not_applicable`: threat is outside the mediated boundary.

A critical case with unexpected downstream execution blocks release.

## 12. Performance methodology

Publish hardware, OS, build profile, policy/corpus version, payload distribution, concurrency, warm-up, sample count, and confidence/percentile method. Measure:

- direct fake server baseline versus gateway allow/deny paths;
- canonicalization, policy, provenance lookup, audit append separately;
- p50/p95/p99/max latency and throughput;
- idle/peak resident memory and bounded-state growth;
- tool inventory/manifest processing for large schemas;
- audit verification and replay rate.

Approval wait and downstream execution are excluded from policy latency but reported end-to-end separately. Benchmarks never contain real Messages.

## 13. Coverage gates

- Core protocol/policy/approval/audit/provenance branch coverage >=90%.
- Every normative `FR`, `SR`, and `TR` group has automated evidence; security-critical individual requirements have direct tests.
- Every threat-model misuse case has a prevention/detection/limitation corpus entry.
- Every accepted ADR's validation section maps to at least one suite.
- No skipped/ignored security test in release configuration without a linked time-bounded issue and explicit release decision.

Coverage is a floor, not proof. Mutation, property, fuzz, fault, and corpus evidence are required alongside line/branch metrics.

## 14. Release evidence bundle

Tagged releases publish:

- exact commit/toolchain/dependency lock and supported protocol version;
- unit/integration/conformance summary;
- corpus report with outcome definitions and limitations;
- fuzz duration/corpus/crash summary;
- fault-injection matrix result;
- benchmark report;
- SBOM, artifact checksums/signatures, and build provenance;
- known issues, supported versions/platforms, and security contact.
