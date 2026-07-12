# ADR-0006: Metadata-first signed audit

- Status: Accepted
- Date: 2026-07-12
- Owners: project maintainers

## Context

Forensic replay needs an ordered record of identities, decisions, provenance, and side effects. Plain logs can be edited and raw payload capture would duplicate the private data AgentGate is supposed to protect. Signing each event is expensive and still does not prove completeness if all local files disappear.

## Decision

Write canonical append-only JSONL events linked by hashes. Sign periodic and shutdown checkpoints with Ed25519. Default events store allowlisted metadata, classifications, rule/finding IDs, sizes/timings, and keyed digests—not raw tool arguments or results.

Optional payload escrow is deferred to v0.2 and, when implemented, must be explicit, field-limited, encrypted, and retention-bounded. Offline verification detects mutations within a retained covered chain. The product clearly states that local-only checkpoints cannot prove the entire log was not deleted.

## Security properties

- Modification, insertion, deletion within a retained chain, duplication, and reordering are detectable.
- Verification does not require a running service or private key.
- Default logging avoids a second plaintext archive of Messages/files.
- Policy drift can be evaluated from canonical metadata and digests.

## Consequences

- Canonical event encoding and key lifecycle are security-critical.
- Metadata and digests still require local permissions and retention controls.
- Full semantic replay of raw tool behavior is impossible in metadata-only mode; policy decision replay remains possible.
- Strong completeness requires a future external anchor or append-only platform service.

## Alternatives considered

- **Ordinary structured logs:** insufficient tamper evidence.
- **Raw full-payload event sourcing:** unacceptable default privacy cost.
- **Database audit table:** useful querying but adds mutable engine complexity; may be a derived index, not source of truth.
- **Sign every event:** possible but unnecessary; hash chain plus checkpoints gives efficient verification.

## Validation

Known-answer cryptographic vectors, cross-build canonicalization fixtures, mutation/insertion/deletion/reorder tests, key rotation tests, permission tests, crash points around precommit/forward/completion, and explicit whole-log-deletion limitation documentation.
