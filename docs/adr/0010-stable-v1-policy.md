# ADR-0010: Freeze the v1 Policy Contract

- Status: Accepted
- Date: 2026-07-12

## Context

The preview policy identifier allowed incompatible change and could not support a security-stable release. Silently accepting preview input would make upgrade review and rollback ambiguous.

## Decision

AgentGate 1.x accepts only `agentgate.dev/v1`. Unknown fields remain errors, deny precedence and mandatory high-impact approval are frozen, and the policy digest uses the `policy/v1` domain. A separate migration command accepts exactly `v1alpha1`, writes a new file with create-new semantics, validates all stable invariants, and never activates or overwrites policy. A canonical metadata-only diff reports digest and identity changes.

## Consequences

Preview users must perform an explicit migration. Security-semantic changes require a new API version and ADR. Tightening invalid-input rejection and additive deny-only findings remain compatible patch behavior.

