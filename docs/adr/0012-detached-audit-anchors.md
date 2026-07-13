# ADR-0012: Export Public Verifiers and Detached Audit Anchors

- Status: Accepted
- Date: 2026-07-12

## Context

Preview verification asked for the raw signing-key file, which unnecessarily exposed secret material. Embedded checkpoints detect retained-chain mutation but a local actor can delete the complete log.

## Decision

Version 1 verification accepts a raw public Ed25519 key. A separate command exports public bytes from the owner-only signing key. Operators may create a detached JSON anchor after verifying a completed log. The signed anchor binds schema, event count, final chain hash, key identity/public key, and creation time. Verification authenticates the anchor, the full log, the expected public key, and exact coverage.

Anchor creation refuses overwrite. Publication is deliberately separate from signing so operators can send the non-sensitive anchor to an independent append-only, transparency, or retention-locked system.

## Consequences

Independent retention can establish evidence of whole-log deletion or substitution relative to the published checkpoint. An anchor left beside the log offers portability but no stronger deletion guarantee. AgentGate does not claim that local detached files are external anchors.

