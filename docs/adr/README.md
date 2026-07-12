# Architecture Decision Records

ADRs capture decisions that materially affect AgentGate's security claims, compatibility, or long-term structure. Accepted ADRs are normative; changing one requires a superseding ADR rather than silently editing history.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-local-protocol-aware-proxy.md) | Use a local protocol-aware reference monitor with one downstream server per process | Accepted |
| [0002](0002-rust-enforcement-core.md) | Implement the enforcement core in Rust | Accepted |
| [0003](0003-typed-declarative-policy.md) | Use a narrow declarative YAML policy compiled to typed IR | Accepted |
| [0004](0004-conservative-information-flow.md) | Combine fingerprints, authenticated lineage, and conservative session taint | Accepted |
| [0005](0005-exact-action-human-approval.md) | Bind human approval to one canonical action | Accepted |
| [0006](0006-metadata-first-signed-audit.md) | Use metadata-first hash-chained audit logs with Ed25519 checkpoints | Accepted |
| [0007](0007-deterministic-security-decisions.md) | Keep model analysis additive and outside authorization authority | Accepted |
| [0008](0008-stdio-first-transport.md) | Ship stdio first, then add Streamable HTTP behind a common transport contract | Accepted |
| [0009](0009-red-team-corpus-as-product.md) | Treat the adversarial corpus and reference demo as versioned release artifacts | Accepted |

## Template

New ADRs use:

```markdown
# ADR-NNNN: Title

- Status: Proposed | Accepted | Superseded by ADR-NNNN
- Date: YYYY-MM-DD
- Owners: project maintainers

## Context
## Decision
## Security properties
## Consequences
## Alternatives considered
## Validation
```
