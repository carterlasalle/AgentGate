# Implementation Plan

**Purpose:** delivery roadmap, milestones, dependencies, and exit gates  
**Planning style:** security-first vertical slices; estimates are relative engineering weeks, not promises  
**Release sequence:** v0.1 developer preview → v0.2 hardening → v1.0 security-stable

## 1. Delivery principles

1. Build a minimal end-to-end reference monitor before adding detector breadth.
2. Write the failing test/corpus case before each enforcement behavior.
3. Never merge a new allow path without a deny-path test and audit assertion.
4. Keep commits reviewable: specification/test, implementation, hardening/docs.
5. Treat canonicalization, approval consumption, audit precommit, and protocol correlation as security-critical review areas.
6. Publish limitations with the same prominence as pass rates.
7. Do not postpone the real `mac_messages_mcp` demo or red-team corpus until after “core” development; they drive the core.

## 2. Milestone overview

| Milestone | Outcome | Relative effort | Depends on |
| --- | --- | --- | --- |
| M0 | Repository and engineering guardrails | 0.5 week | Documentation baseline |
| M1 | Transparent stdio MCP proxy | 1.5 weeks | M0 |
| M2 | Typed policy engine and capability enforcement | 1.5 weeks | M1 |
| M3 | Exact-action approval | 1 week | M2 |
| M4 | Provenance and information-flow enforcement | 2 weeks | M2, M3 |
| M5 | Manifest integrity and chain detection | 1.5 weeks | M2, M4 state model |
| M6 | Signed audit, verification, and dry replay | 1.5 weeks | M2–M5 event contracts |
| M7 | Red-team lab and Messages flagship demo | 1.5 weeks | M1–M6 |
| M8 | v0.1 hardening and release | 1 week | M7 |
| M9 | v0.2 transport/UX/storage hardening | 3–5 weeks | v0.1 evidence |
| M10 | v1.0 stability and review | evidence-driven | v0.2 |

With one experienced engineer, v0.1 is roughly 11–13 focused engineering weeks. Scope is cut by deferring features, never by weakening fail-closed invariants.

## 3. M0 — repository and guardrails

### Deliverables

- Rust workspace and pinned toolchain/MSRV policy.
- Crate skeleton from the technical design.
- CI: format, clippy with denied warnings, unit/doc tests, dependency/license audit, secret scan, docs check.
- `SECURITY.md`, `CONTRIBUTING.md`, code of conduct, supported-version statement.
- Dependabot/Renovate policy, lockfile policy, release profile, deny configuration.
- Deterministic clock/RNG and fake host/server primitives in `agentgate-testkit`.
- Initial JSON-RPC/MCP fixtures licensed/attributed appropriately.

### Test-first slices

1. CI fails on formatting/lint/test errors.
2. A fake host can exchange one request/response with a fake server entirely in memory.
3. Testkit can freeze time and supply deterministic nonces without those hooks entering production configuration.

### Exit criteria

- Clean checkout passes all local/CI commands.
- Release build contains no accidental unsafe blocks.
- Dependency tree and license choice are reviewed.
- Architecture docs and crate ownership match the workspace.

## 4. M1 — transparent stdio MCP proxy

### Deliverables

- Bounded JSON-RPC framing and parsing.
- Typed request/response/notification/error correlation.
- MCP initialize lifecycle and capability negotiation for `2025-11-25`.
- Tool discovery interception with pass-through behavior.
- Downstream child launch without shell, allowlisted environment, stderr separation.
- Cancellation, deadlines, graceful shutdown, and malformed-server quarantine.
- `agentgate run` and `agentgate doctor` minimum commands.

### Test-first slices

1. Valid JSON-RPC request ID returns the matching response.
2. Malformed/oversized frame never reaches the fake server.
3. Consequential notification is rejected before any generic pass-through is enabled.
4. Lifecycle calls for the reference server pass unchanged.
5. Child exit resolves every pending request exactly once.

### Exit criteria

- Unmodified `mac_messages_mcp` initializes and supports a synthetic read through the gateway.
- Protocol conformance suite covers requests, notifications, errors, batches, cancellation, and invalid IDs.
- Fuzzer finds no crash/hang in parser and lifecycle state machine during the configured CI budget.
- No diagnostics are written to protocol stdout.

## 5. M2 — typed policy and capability enforcement

### Deliverables

- `v1alpha1` JSON Schema, duplicate-key-safe loader, linter, compiler, immutable IR.
- Stable server/tool identities and normalized manifest digests.
- Effect classification, argument predicates, explicit deny/allow/default deny.
- Canonical JSON/action profile with golden vectors.
- Pure decision evaluator and bounded explanation tree.
- `agentgate policy check` and `agentgate policy test`.
- Reference Messages capability policy without provenance behavior yet.

### Test-first slices

1. Empty policy denies every tool.
2. Exact allow permits one declared read and not a similarly named tool.
3. Explicit deny wins regardless of file order.
4. Unknown field, duplicate rule ID/key, bad selector, and unknown label fail compilation.
5. Equivalent JSON objects produce one action digest; ambiguous duplicate keys are rejected.
6. Policy reload cannot change an in-flight call's digest.

### Exit criteria

- No unclassified or undeclared call reaches the fake server.
- Every example policy has positive/negative fixtures.
- Canonicalization vectors are checked on macOS and Linux.
- Core policy branch coverage is at least 90%.

## 6. M3 — exact-action approval

### Deliverables

- Approval provider trait and dedicated-terminal provider.
- Safe material-argument rendering and redaction.
- Pending token store with nonce, expiry, session/policy/manifest binding, atomic consumption.
- Mandatory invariant effects: send, upload, delete, purchase.
- Timeout, denial, UI loss, session termination, rate/fatigue warnings.
- Fake deterministic approval provider for tests.

### Test-first slices

1. Send is paused and never observed downstream before approval.
2. Changed recipient/body fails digest validation.
3. One token cannot satisfy two concurrent identical requests.
4. Policy/manifest reload invalidates pending approval.
5. ANSI, bidi, and oversized values render safely.
6. Unknown downstream outcome is never automatically retried.

### Exit criteria

- `tool_send_message` demo displays recipient/body and forwards once after approval.
- All mandatory effects require approval even under an allow-all test policy.
- Concurrency and crash-injection tests show no token reuse.
- Approval path has keyboard-only, deny-default behavior.

## 7. M4 — provenance and information-flow enforcement

### Deliverables

- Hierarchical labels, bounded result selectors, source/sink classifications.
- Per-installation keyed fingerprints and explicit normalization profiles.
- Bounded exact/normalized/chunk lookup state.
- Deterministic session-taint state machine.
- Flow/declassification rules and provenance explanations.
- Optional authenticated-lineage interface contract, with implementation allowed to remain experimental.

### Test-first slices

1. Synthetic Messages result creates a label without plaintext audit retention.
2. Exact content copy to fake upload is denied.
3. Whitespace/case/contact normalization still matches.
4. Short low-entropy values are not chunk-fingerprinted unsafely.
5. Paraphrased no-match remains restricted by session taint.
6. Forged lineage cannot authorize a flow.
7. Exact approved declassification cannot be reused for another sink/field.
8. TTL/LRU eviction stays within memory bounds and is visible in conservative decisions.

### Exit criteria

- All `SR-001`–`SR-010` acceptance tests pass.
- Reference policy blocks Messages/file-to-unrelated-network corpus cases.
- Documentation and CLI distinguish detection evidence from proof.
- Fingerprint state passes privacy and bounded-resource review.

## 8. M5 — descriptor integrity and suspicious chains

### Deliverables

- Versioned manifest normalization and trust store.
- Deterministic descriptor detector registry with stable finding IDs.
- Safe excerpts/diffs and quarantine/review states.
- Bounded action graph and compiled chain automata.
- Rules for sensitive-read→external-sink, enumerate→delete, credential→execute/network, repeated denial probing, and high-rate sends.
- Synthetic malicious MCP servers: poisoned description, manifest rug pull, malformed frames, coercive outputs, schema bomb.

### Test-first slices

1. Hidden/bidi control quarantines before host advertisement.
2. Manifest changes after trust prevent invocation until review.
3. Renamed collision does not inherit trust.
4. Read→upload chain denies even when individual tools are allowed.
5. Graph eviction is deterministic and raw values are absent.
6. Optional semantic detector cannot suppress deterministic finding.

### Exit criteria

- Critical descriptor and rug-pull corpus cases never execute.
- Detector false-positive fixtures cover legitimate security text and complex schemas.
- Chain state is reconstructible from audit metadata.
- Resource-exhaustion cases remain bounded.

## 9. M6 — signed audit and replay

### Deliverables

- Versioned canonical audit event schema and JSONL writer.
- Hash chain, Ed25519 key generation/checkpoints, key IDs and rotation events.
- Security-critical precommit/flush semantics.
- Offline `audit verify` with machine-readable and human output.
- Dry-run `audit replay` against recorded or alternate policy.
- Retention and permission checks; metadata-first privacy snapshots.

### Test-first slices

1. Golden event/checkpoint vectors verify across platforms.
2. Modify/insert/delete/duplicate/reorder each fail at a known position.
3. Audit failure prevents a high-impact call.
4. Crash after forward but before completion records/reports unknown outcome without retry.
5. Replay performs no process/network action.
6. Policy change produces an explainable drift report.
7. Rotation preserves old verification and links keys when possible.

### Exit criteria

- `SR-050`–`SR-059` pass, including explicit whole-log-deletion limitation.
- Default audit snapshots contain no synthetic message plaintext.
- Key/state files have safe ownership and permissions on supported platforms.
- Independent verifier module does not depend on gateway runtime state.

## 10. M7 — red-team lab and flagship demo

### Deliverables

- Versioned corpus schema: threat, setup, steps, expected decision/evidence, requirement links.
- Hermetic fake sink and malicious MCP servers.
- Categories: prompt/content injection, tool poisoning, rug pull, cross-tool exfiltration, approval swap/replay, chain misuse, malformed protocol, exhaustion, audit tamper.
- Synthetic Messages dataset/setup plus optional real local integration instructions.
- Demo script/storyboard and machine-generated report.
- Coverage map to OWASP Agentic Top 10 2026 and AgentGate threat cases.

### Flagship demonstration

1. Start AgentGate protecting `mac_messages_mcp` and a separate synthetic upload server in isolated demo sessions/configuration.
2. Read/search synthetic Messages successfully.
3. Attempt injected upload and show deterministic block.
4. Request a legitimate send, inspect exact prompt, approve, and show one execution.
5. Change the send body after prompt and show invalidation.
6. Change a malicious server description and show quarantine.
7. Verify the signed audit chain and replay against a stricter policy.

### Exit criteria

- Every critical scenario has a deterministic expected outcome and requirement link.
- CI has network disabled and uses only synthetic data/targets.
- No critical case silently executes; expected limitations are explicitly reported.
- The demo is reproducible from a clean macOS checkout.

## 11. M8 — v0.1 hardening and release

### Deliverables

- Parser/canonicalizer/policy/audit fuzz targets and seed corpora.
- Fault injection around I/O, downstream exit, approval, audit, and shutdown.
- Benchmarks with reference hardware/methodology.
- Dependency, license, secret, SBOM, and provenance checks.
- Installation, configuration, troubleshooting, limitations, security disclosure, and demo documentation.
- Signed release artifacts and checksums for supported targets.

### Exit criteria

- All PRD v0.1 launch gates pass.
- No open critical/high issue violates a security invariant.
- Performance meets NFR targets or variance is documented and accepted before release.
- Clean-machine install/read/confirm/block/verify journey completes under 10 minutes.
- Release report includes corpus pass matrix, benchmark, known limitations, and reproducible commands.

## 12. M9 — v0.2 hardening

Prioritize from v0.1 evidence, not feature enthusiasm:

- Streamable HTTP with a dedicated authentication/origin/TLS ADR and transport conformance reuse.
- OS-native approval helper and authenticated IPC.
- macOS Keychain/Linux secret-service key storage.
- Explicit encrypted payload escrow.
- Policy diff/simulation and derived local query index.
- Optional OS sandbox profiles for downstream processes.
- External checkpoint anchoring experiment.

Each item is independently shippable and must not alter v1 security invariants silently.

## 13. M10 — v1.0 security stability

- Freeze supported policy/audit schemas and migration guarantees.
- Commission external threat-model/cryptographic review and resolve findings.
- Run extended fuzz, fault, corpus, compatibility, and performance campaigns.
- Publish supported-version/deprecation policy and incident response runbook.
- Verify artifact signing, SBOM, provenance, reproducibility, and upgrade/rollback behavior.
- Require two-person review for changes touching canonicalization, policy precedence, approval binding, audit hashing/signing, and invariant effects.

## 14. Scope-control rules

If schedule pressure appears, defer in this order:

1. GUI and hosted experiences.
2. Streamable HTTP and multi-server process.
3. Optional model-assisted detectors.
4. Payload escrow and derived audit query UI.
5. Authenticated host-lineage implementation (retain interface/research plan).

Do not cut default deny, exact-action approval, Messages flow controls, deterministic manifest integrity, audit tamper evidence, red-team corpus, or published limitations.

## 15. Definition of done for every security feature

- Requirement and threat/corpus IDs linked.
- Failing test/corpus case exists before implementation.
- Positive, negative, boundary, concurrency/failure, and audit assertions pass.
- User-facing explanation and safe remediation exist.
- No new sensitive logging/state is introduced without privacy review.
- Performance/resource bounds are measured.
- Docs/example policy updated.
- Security-critical review checklist completed.
