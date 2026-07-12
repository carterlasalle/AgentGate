# ADR-0005: Exact-action human approval

- Status: Accepted
- Date: 2026-07-12
- Owners: project maintainers

## Context

Broad installation consent and conversational statements are not sufficient authorization for sends, uploads, deletions, or purchases. A common time-of-check/time-of-use failure is presenting benign arguments and executing changed ones. Reusable approvals also turn one decision into ambient privilege.

## Decision

Human approval is an obligation bound to one canonical action digest, session ID, effective policy digest, tool-manifest digest, random nonce, provider identity, and short expiry. Approval tokens are single-use and atomically consumed immediately before forwarding.

In v1, `send`, `upload`, `delete`, and `purchase` always require human approval. Policy cannot remove this invariant. Argument, manifest, session, or policy changes invalidate the prompt. Conversation/tool content cannot count as consent.

## Security properties

- The bytes authorized correspond to the material action displayed.
- Approval cannot be reused for another call or session.
- Rug pulls and policy reloads invalidate stale consent.
- UI loss, timeout, ambiguity, and errors fail closed.

## Consequences

- Some workflows have unavoidable human latency.
- Canonicalization and rendering become critical security code with published golden vectors.
- Approval fatigue must be managed with concise display and rate/chain warnings, not blanket approval.
- Terminal v0.1 needs a dedicated controlling terminal because MCP owns stdin/stdout.

## Alternatives considered

- **Approve server installation once:** too coarse for changing effects/arguments.
- **Approve tool name for session:** vulnerable to argument changes and repeated side effects.
- **Trust agent-generated confirmation text:** untrusted and susceptible to injection.
- **Risk-score auto-approval:** nondeterministic and unsafe for mandatory effects.

## Validation

Race tests for concurrent consumption, clock-expiry tests, canonicalization vectors, stale policy/manifest tests, terminal injection snapshots, changed-argument tests, and no-automatic-retry tests for unknown outcomes.
