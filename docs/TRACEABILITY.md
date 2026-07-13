# Traceability Matrix

This matrix connects product promises to normative behavior, engineering constraints, architecture decisions, delivery milestones, and evidence. It is maintained with requirement changes and checked before releases.

## 1. Product-goal traceability

| Goal | Functional/security requirements | Technical requirements | ADRs | Milestones | Evidence |
| --- | --- | --- | --- | --- | --- |
| PG-01 Mediate unmodified MCP servers | FR-001–008, FR-010–015 | TR-001–026 | ADR-0001, 0002, 0008 | M1, M7 | T-03, T-05, T-11 |
| PG-02 Least-privilege policy-as-code | FR-020–027 | TR-030–037, TR-090 | ADR-0003, 0007 | M2 | T-01, T-02, T-06 |
| PG-03 Prevent cross-tool disclosure | SR-001–010, SR-030–034 | TR-050–056, TR-064–065 | ADR-0004, 0007 | M4, M5, M7 | T-02, T-06, T-07, T-11 |
| PG-04 Human control of consequences | SR-020–028, UXR-001–007 | TR-040–045 | ADR-0005 | M3, M7 | T-02, T-04, T-05, T-07, T-11 |
| PG-05 Detect manipulation/chains | FR-010–015, SR-030–045 | TR-060–065 | ADR-0007, 0009 | M5, M7 | T-01, T-02, T-07, T-08 |
| PG-06 Trustworthy forensic evidence | SR-050–059 | TR-070–084 | ADR-0006 | M6, M8 | T-01, T-02, T-09, T-12 |
| PG-07 Portfolio-grade reproducibility | all plus UXR | TR-090–094, NFR-001–010 | ADR-0009, 0010, 0012 | M0, M7, M8, M10, M11 | T-07–T-12 and release bundle |

## 2. Threat traceability

| Threat | Primary controls | Required evidence |
| --- | --- | --- |
| TM-01 content-driven exfiltration | SR-001–010, session taint, exact flows | direct/normalized/paraphrased upload corpus; zero unsafe fake-sink calls |
| TM-02 injected send | SR-020–028 | approval prompt/digest/one-call integration |
| TM-03 descriptor poisoning | SR-040–045 | positive and near-miss detector corpus; quarantine before advertisement |
| TM-04 rug pull | FR-011–014, SR-042–043 | changed manifest fake server and trust-state tests |
| TM-05 approval substitution | SR-021–024, TR-040–043 | canonical golden vectors and changed-argument races |
| TM-06 approval replay | SR-023, TR-042–043 | concurrent/expired/restart consumption tests |
| TM-07 batch approval abuse | FR-004–005, SR-027 | mixed/all-notification/high-impact batch fixtures |
| TM-08 ID confusion | FR-002, TR-024 | generated duplicate/late/cancel correlation tests |
| TM-09 audit privacy leak | SR-054–055, TR-076, TR-084 | event/panic snapshots scanned for synthetic plaintext |
| TM-10 audit mutation | SR-051–053, TR-070–074 | full tamper matrix and known-answer signatures |
| TM-11 repeated probing | SR-030–034, UXR-004 | chain/rate corpus and termination option |
| TM-12 bypass | PRD non-goals, UXR-007 | doctor fixture and prominently documented limitation |
| TM-13 resource exhaustion | FR-003, FR-006, TR-022–026 | fuzz/load/schema-bomb/malformed-server tests |
| TM-14 UI injection | SR-045, UXR-002/005/006, TR-045 | ANSI/bidi/control/oversize snapshots |
| TM-15 policy rollback | SR-022/024, TR-036/040 | digest/reload/rollback audit and approval invalidation tests |

## 3. Normative requirement coverage by suite

| Requirement group | Test suites | Release gate |
| --- | --- | --- |
| FR-001–008 protocol mediation | T-01, T-02, T-03, T-05, T-08, T-09 | M1 |
| FR-010–015 identity/inventory | T-01, T-03, T-05, T-07 | M2/M5 |
| FR-020–027 policy decisions | T-01, T-02, T-04, T-06 | M2 |
| SR-001–010 provenance/flow | T-01, T-02, T-04, T-06, T-07, T-10 | M4 |
| SR-020–028 approval | T-01, T-02, T-04, T-05, T-07, T-09 | M3 |
| SR-030–034 chains | T-01, T-02, T-07, T-10 | M5 |
| SR-040–045 descriptors | T-01, T-07, T-08, T-10 | M5 |
| SR-050–059 audit/replay | T-01, T-02, T-04, T-09, T-12 | M6 |
| UXR-001–007 human safety | T-01 snapshots, T-05, T-07, T-11 | M3/M8 |
| TR-001–026 protocol/platform | T-01–T-05, T-08–T-10 | M1/M8 |
| TR-030–065 policy/provenance/integrity | T-01, T-02, T-06–T-10 | M2–M5 |
| TR-070–084 audit/storage | T-01, T-02, T-09, T-12 | M6/M8 |
| TR-090–094 release/supply chain | T-07, T-08, T-10, T-12 | M0/M8 |
| NFR-001–010 quality | T-08, T-10, T-11, T-12 | M8/M10 |

## 4. ADR validation traceability

| ADR | Validation suites |
| --- | --- |
| ADR-0001 local proxy | T-03, T-05, T-11, bypass doctor fixture |
| ADR-0002 Rust core | compile/lint/unsafe gate, T-02, T-08, T-10 |
| ADR-0003 typed policy | T-01, T-02, T-06, replay equivalence |
| ADR-0004 conservative flow | T-02, T-06, T-07 provenance category, T-10 bounds |
| ADR-0005 exact approval | T-02, T-04, T-05, T-07 approval category, T-09 |
| ADR-0006 signed audit | T-01 known answers, T-09 mutation/crash, T-12 evidence |
| ADR-0007 deterministic decisions | T-02 replay, network/model-disabled tests, T-07 poisoning |
| ADR-0008 stdio first | T-03, T-05, T-11 |
| ADR-0009 corpus as product | T-07, T-11, T-12 release bundle |
| ADR-0010 stable v1 policy | migration/overwrite tests, policy digest and diff fixtures |
| ADR-0011 authenticated lineage | binding, forgery, expiry, session/tool/argument swap tests |
| ADR-0012 detached anchors | public-key CLI round trip and anchor mutation/coverage tests |

## 5. Flagship acceptance trace

| Demo step | Requirements | Threats | Evidence |
| --- | --- | --- | --- |
| Initialize unmodified `mac_messages_mcp` | FR-001/002/008, TR-001–006 | compatibility/bypass boundary | protocol trace and inventory digest |
| Read synthetic messages | FR-020–027, SR-001–003 | TM-01, TM-09 | labeled response, no plaintext audit |
| Block unrelated upload | SR-003–010, SR-030–033 | TM-01, TM-11 | `AG-FLOW-BLOCKED`, fake sink count 0 |
| Confirm legitimate send | SR-020–028, UXR-001–006 | TM-02, TM-05–07, TM-14 | displayed digest-bound prompt, one downstream call |
| Reject modified send | SR-022–024 | TM-05, TM-06 | `AG-APPROVAL-STALE`, no extra call |
| Quarantine changed malicious tool | FR-010–015, SR-040–045 | TM-03, TM-04 | manifest finding before invocation |
| Verify and replay | SR-050–059 | TM-09, TM-10, TM-15 | valid checkpoint; policy drift report; no I/O |

## 6. Change-control rules

- Adding or changing a normative requirement updates at least one row here and one planned/implemented test.
- Removing a requirement requires a superseding ADR when it changes a security or compatibility promise.
- A release report references exact requirement/corpus versions, not only a commit-level “tests passed” statement.
- Any `expected_limitation` corpus result links to the threat/non-goal and cannot be relabeled as prevented.
- Missing traceability for a critical/high security change blocks release.
