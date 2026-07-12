# AgentGate documentation

This directory is the normative design record for AgentGate. The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are interpreted as in [BCP 14](https://www.rfc-editor.org/info/bcp14) when capitalized.

## Document authority

When documents disagree, use this precedence:

1. Accepted ADRs for architectural choices.
2. `TECHNICAL_REQUIREMENTS.md` for measurable engineering constraints.
3. `SPECIFICATION.md` for externally observable behavior.
4. `PRD.md` for product intent and scope.
5. Plans for sequencing only; plans do not override requirements.

Changing an accepted security invariant requires a new superseding ADR and updates to the traceability matrix.

## Requirement identifiers

| Prefix | Source | Meaning |
| --- | --- | --- |
| `PG` | PRD | Product goal |
| `FR` | Specification | Functional requirement |
| `SR` | Specification | Security behavior requirement |
| `UXR` | Specification | Human interaction requirement |
| `TR` | Technical requirements | Protocol/implementation requirement |
| `NFR` | Technical requirements | Non-functional requirement |
| `ADR` | ADR directory | Architecture decision |
| `M` | Implementation plan | Delivery milestone |
| `T` | Test strategy | Verification family |

The [traceability matrix](TRACEABILITY.md) is the index connecting these identifiers.

## Status vocabulary

- **Proposed**: under review; implementation may spike but must not depend on it for release.
- **Accepted**: part of the current build contract.
- **Superseded**: retained for history and linked to its replacement.
- **Deferred**: explicitly outside the current release target.
