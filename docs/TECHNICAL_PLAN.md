# Technical Plan

**Purpose:** concrete engineering sequence for implementing the architecture  
**Companion:** [Implementation Plan](IMPLEMENTATION_PLAN.md) owns milestone outcomes; this document owns module tasks, dependency order, interfaces, and test-first slices.

## 1. Critical dependency path

```text
wire limits/types
      ↓
MCP lifecycle + request correlation
      ↓
tool identity + manifest normalization
      ↓
canonical action ───────────────┐
      ↓                         │
typed policy IR/evaluator       │
      ↓                         │
approval binding ◄──────────────┘
      ↓
provenance + action graph
      ↓
audit event contract + replay
      ↓
red-team orchestration + release evidence
```

Audit event types should be sketched early, but cryptographic persistence is implemented after event-producing modules stabilize. The fake host/server and deterministic time/RNG are built first because every stage depends on reliable tests.

## 2. Workspace contracts

### `agentgate-protocol`

Owns:

- bounded byte framing and JSON parsing;
- JSON-RPC validation/correlation types;
- supported MCP lifecycle/tool wire types;
- transport-neutral validated message interface;
- conversion to/from wire errors.

Must not depend on policy, approval, audit storage, CLI, or downstream process implementation.

Initial API seams:

```rust
trait Transport {
    async fn receive(&mut self) -> Result<UntrustedFrame, TransportError>;
    async fn send(&mut self, frame: ValidatedFrame) -> Result<(), TransportError>;
    async fn close(&mut self) -> Result<(), TransportError>;
}

fn validate_frame(frame: UntrustedFrame, limits: &Limits) -> Result<ProtocolMessage, ProtocolError>;
```

Test order: framing limits → JSON-RPC shape → IDs/correlation → lifecycle transitions → cancellation/batches → stdio process adapter.

### `agentgate-core`

Owns:

- session state machine and orchestration;
- stable server/tool identity;
- canonical action construction;
- strict ordering of inventory, decision, obligation, precommit, forward, response labeling, completion;
- fail-closed mapping and shutdown.

Must not implement detector/policy semantics internally. It consumes traits and typed outputs.

Critical API:

```rust
trait Authorizer {
    fn decide(&self, context: &DecisionContext) -> Decision;
}

trait AuditSink {
    async fn append(&self, event: AuditEvent, durability: Durability) -> Result<Receipt, AuditError>;
}

trait ApprovalBroker {
    async fn satisfy(&self, action: &CanonicalAction, obligations: &[Obligation])
        -> Result<ApprovalReceipt, ApprovalError>;
}
```

Test order: deny before forward → obligation before forward → audit precommit before side effect → response state commit → cancellation/shutdown races.

### `agentgate-policy`

Owns:

- authoring structs and schema generation/check-in;
- secure YAML loading and lint diagnostics;
- compilation to typed IR;
- pure evaluation and explanation trees;
- policy fixture runner.

Must not perform I/O during evaluation. Loading and compilation happen outside the hot path.

Test order: reject unsafe syntax → selector/predicate primitives → rule conflicts → flows → obligations → chain compilation → explain/golden cases → mutation tests.

### `agentgate-provenance`

Owns:

- labels/origin records and selector extraction;
- keyed exact/normalized/chunk fingerprints;
- normalization profiles;
- bounded per-session state and authenticated lineage validation;
- flow evidence and session-taint transitions.

Does not decide final authorization; produces deterministic evidence for policy.

Test order: label hierarchy → keyed fingerprints → normalization → bounded chunks → sink matching → taint transitions → eviction → forged lineage.

### `agentgate-integrity`

Owns:

- manifest normalization/digest;
- trusted manifest state and change classification;
- deterministic descriptor detectors;
- safe excerpts/diffs;
- bounded action graph facts and chain runtime.

The policy crate compiles chain definitions; integrity executes the bounded automata against facts.

Test order: normalization vectors → Unicode safety → each detector → manifest change/collision → graph bounds → chain sequence/rate → replay reconstruction.

### `agentgate-approval`

Owns:

- approval request/receipt/token types;
- pending state, cryptographic nonce, time/session/digest binding, atomic consumption;
- provider trait, terminal provider, deterministic test provider;
- safe display model independent of terminal rendering.

Must not receive raw unrestricted protocol objects. It receives material bounded fields selected by policy plus action digest.

Test order: token fields → expiry → atomic reuse race → stale action/policy/manifest → safe rendering → `/dev/tty` isolation → provider failure.

### `agentgate-audit`

Owns:

- canonical event schema/encoding;
- append/hash/flush/checkpoint storage;
- Ed25519 key/public verification and rotation metadata;
- offline verifier and dry replay reader;
- retention primitives and privacy allowlist.

Must expose a narrow append interface; callers cannot author arbitrary map fields that leak data.

Test order: canonical bytes → hash vector → append/reopen → checkpoint vector → tamper matrix → crash points → rotation → dry replay/no-network → retention.

### `agentgate-cli`

Owns:

- config/path resolution;
- subcommands and exit codes;
- downstream process wiring;
- operational logs and diagnostics;
- `doctor`, policy, audit, run, version commands.

CLI is composition, not a second implementation of policy or verification.

### `agentgate-testkit`

Owns:

- in-memory and stdio fake hosts/servers;
- deterministic clock, nonce/key fixtures, fault injection;
- frame/action/audit assertions;
- hermetic process/network guards;
- corpus runner primitives.

It must make unsafe outcomes observable: every fake server records calls so tests can assert a denied action never arrived.

## 3. Vertical slice sequence

Each slice should land as a small commit series: failing contract test, implementation, hardening/docs. Avoid long-lived “all architecture” branches.

### Slice A — ping through a bounded proxy

- Parse one request and response.
- Preserve ID and isolate stderr.
- Reject malformed/oversized input.
- Append an in-memory event only.

Demonstrates the mediation seam without authorization claims.

### Slice B — default-deny one tool call

- Intercept `tools/list` and create identity.
- Canonicalize one tool call.
- Empty compiled policy returns `AG-POLICY-NO-MATCH`.
- Fake server call count remains zero.

This is the first reference-monitor invariant.

### Slice C — allow one Messages read

- Compile exact tool allow.
- Forward synthetic `tool_get_recent_messages`.
- Record metadata receipt and return unchanged valid result.
- Deny similarly named/unknown tools.

### Slice D — exact send approval

- Classify `tool_send_message` as send.
- Require terminal/test provider receipt.
- Bind/consume exact digest once.
- Exercise changed recipient/body and concurrent replay.

### Slice E — label and block direct exfiltration

- Label synthetic message content.
- Register keyed fingerprint.
- Deny matching fake upload argument.
- Explain source, sink, evidence method, and flow rule.

### Slice F — conservative transformed-data control

- Mark session taint after Messages read.
- Attempt paraphrased/no-match upload.
- Deny due to session taint with distinct explanation.
- Permit only exact approved declassification to the Messages send tool.

### Slice G — manifest rug pull

- Trust first normalized fake manifest.
- Change description/schema.
- Quarantine before advertisement/invocation.
- Safely render diff and emit digest-only evidence.

### Slice H — suspicious chain

- Allow individual synthetic enumerate and delete tools.
- Match bounded enumerate→repeated-delete rule.
- Deny the threshold action and offer session termination.
- Replay action facts to the same decision.

### Slice I — durable signed evidence

- Replace in-memory sink with canonical JSONL.
- Precommit before send; completion after response.
- Sign/verify checkpoint.
- Mutate and replay against alternate policy.

### Slice J — integrated corpus report

- Run all prior slices through common scenario manifests.
- Add poisoned prompt/server cases and resource failures.
- Emit machine JSON and human Markdown release reports.
- Map outcomes to requirements/threats.

## 4. Canonicalization work package

Canonicalization is independently reviewed before approval or signatures rely on it.

Decide and freeze in a dedicated versioned module:

- UTF-8 only; reject invalid encoding before JSON parse.
- Reject duplicate object keys at parse time.
- Lexicographically sort object member names by defined Unicode/UTF-8 ordering.
- Preserve array order.
- Specify integer/float domain; preferably reject non-integer numbers in security-sensitive action fields unless schema requires them.
- Distinguish absent from explicit null.
- Normalize no general user strings for action identity; normalization is only for provenance evidence. The displayed/forwarded action uses exact validated values.
- Domain-separate action, event, manifest, fingerprint, and policy digests.
- Include schema/profile version in every digest input.

Publish golden inputs/bytes/digests covering Unicode, escapes, empty values, large integers, negative zero/float policy, nested maps, and equivalent key order.

## 5. State and concurrency plan

Per session:

- one lifecycle owner task;
- bounded host-reader and downstream-reader tasks;
- pending request map keyed by typed JSON-RPC ID;
- immutable policy/inventory snapshot generation;
- mutex/actor-owned approval pending/consumed state;
- bounded provenance store and action graph;
- ordered audit appender.

Security-sensitive operations use an orchestrated state machine rather than callbacks:

```text
Received → Validated → Canonicalized → Decided
  → AwaitingApproval → AuditPrecommitted → Forwarded
  → ResponseObserved → StateCommitted → Completed

Any pre-forward failure → Denied/Cancelled (never Forwarded)
Any post-forward ambiguity → UnknownOutcome (never auto-retried)
```

Property tests generate cancellation/failure at each transition and assert at-most-once forwarding, at-most-once approval consumption, and monotonic audit sequence.

## 6. Data/storage plan

Initial local layout:

```text
config/agentgate/config.yaml
config/agentgate/policies/*.yaml
data/agentgate/trust/manifests.json
data/agentgate/keys/<key-id>.key
data/agentgate/audit/<date>-<session>.jsonl
state/agentgate/approvals/     # only if crash-safe pending state requires it
```

Exact paths follow platform directories. Files are created owner-only, checked for safe ownership/type, and written without following untrusted symlinks. Audit is the source of truth; any query database is disposable/derived.

Persist only what a security property requires:

- provenance fingerprints: in-memory per session v0.1;
- action graph: in-memory plus metadata audit facts;
- approval tokens: memory by default; consumed/precommit ordering prevents reuse within process; crash model validated before deciding if durable pending state is needed;
- manifest trust and keys: durable local state;
- audit: durable append-only evidence.

## 7. Configuration plan

One top-level config references one or more named downstream profiles and policy paths, but `run` selects exactly one downstream in v0.1. Configuration precedence is explicit:

```text
compiled safe defaults < config file < explicit CLI flags
```

No implicit environment interpolation. Secrets reference a provider/path, not inline expansion. `doctor` prints effective non-secret configuration, binary/policy/manifest digests, paths/permissions, protocol version, and bypass warnings.

## 8. Red-team corpus implementation

Scenario manifest fields:

```text
id, title, category, severity, requirement_ids, threat_ids,
policy, server fixtures, host steps, expected decisions,
expected downstream call counts, expected audit events, limitations
```

Fake server behaviors are composable flags, not arbitrary shell scripts: poison descriptor, change manifest after N lists, malformed frame, delay, exit, oversized result, coercive result, record calls. Any custom fixture executable is built from repository source and run with network disabled.

Corpus taxonomy:

- direct/indirect prompt injection;
- descriptor poisoning, cross-tool coercion, shadowing, rug pull;
- exact/normalized/chunk/transformed exfiltration;
- approval substitution, replay, expiry, fatigue, UI control injection;
- unauthorized capability, identity collision, stale inventory;
- suspicious sequences and retry probing;
- JSON-RPC confusion, batch/notification abuse, limits and lifecycle races;
- audit tamper, key rotation, crash ambiguity, policy drift.

Reports show `prevented`, `confirmed`, `detected`, `not_detected`, `not_applicable`, or `expected_limitation`; they never collapse all outcomes into a misleading pass percentage.

## 9. CI pipeline order

Fast pull-request path:

1. format and generated-schema drift;
2. clippy/forbidden unsafe;
3. unit and doc tests;
4. policy/docs/link/fixture validation;
5. protocol/integration tests with fake processes;
6. hermetic critical corpus;
7. dependency/license/secret checks.

Scheduled/release path adds:

- fuzzers and property-test expansion;
- fault-injection matrix;
- full corpus;
- benchmarks and regression thresholds;
- cross-platform build/integration;
- SBOM, provenance, signing, reproducibility comparison.

## 10. Review ownership

Require explicit security review for changes to:

- protocol framing, JSON parsing, request correlation;
- canonicalization and any digest input;
- policy precedence, default behavior, invariant effects;
- approval rendering/binding/consumption;
- provenance normalization/fingerprint construction/declassification;
- manifest normalization and detector suppression;
- audit canonicalization/hash/signature/key lifecycle;
- any new external I/O, transport, model dependency, or payload retention.

Review uses a checklist tied to security invariants and asks “can a rejected action reach downstream?” before style/performance concerns.

## 11. Initial engineering backlog

| Order | Issue-sized task | Primary evidence |
| --- | --- | --- |
| 1 | Scaffold workspace, CI, testkit clock/RNG | clean CI |
| 2 | Bounded frame reader and duplicate-key JSON parser | fuzz/unit |
| 3 | JSON-RPC ID/correlation state machine | property tests |
| 4 | MCP initialize/tools lifecycle | conformance integration |
| 5 | No-shell stdio child transport | process tests |
| 6 | Manifest normalizer and stable identities | golden vectors |
| 7 | Canonical JSON/action profile | published vectors |
| 8 | Policy schema/secure loader/compiler | invalid fixture suite |
| 9 | Capability evaluator/explain/default deny | decision tables |
| 10 | Core deny/allow orchestration | downstream call-count assertions |
| 11 | Terminal approval safe display | snapshots |
| 12 | Approval token state machine | race/crash properties |
| 13 | Mandatory effect invariants | bypass policy tests |
| 14 | Labels/selectors/keyed fingerprint state | privacy/unit/load |
| 15 | Flow/session-taint/declassification evaluator | corpus cases |
| 16 | Descriptor detector registry/trust store | malicious server cases |
| 17 | Action graph/chain automata | sequence/replay tests |
| 18 | Canonical audit appender/hash chain | mutation matrix |
| 19 | Ed25519 key/checkpoints/verifier | known-answer tests |
| 20 | Dry replay/policy drift | no-I/O tests |
| 21 | Messages adapter/demo and fake upload server | flagship run |
| 22 | Corpus runner/report/OWASP mapping | release evidence |
| 23 | Fuzz/fault/performance/release hardening | v0.1 gates |

## 12. Technical exit checklist for v0.1

- All required MCP/JSON-RPC fixtures pass and invalid frames are bounded.
- Every tool call follows one audited state machine; denied calls have zero downstream observations.
- Canonicalization and cryptographic golden vectors match supported platforms.
- Policy is default-deny, deterministic, linted, and fully fixture-tested.
- Mandatory effects cannot be configured around.
- Direct/normalized Messages exfiltration is blocked; transformed-data limitation is controlled and documented via session taint.
- Manifest rug pulls and critical poisoning fixtures quarantine before execution.
- Audit mutation matrix passes; replay makes no external calls.
- Critical corpus has no silent execution and every expected limitation is public.
- Clean macOS flagship demo and Linux synthetic suite are reproducible.
