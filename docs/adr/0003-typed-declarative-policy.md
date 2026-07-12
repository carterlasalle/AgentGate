# ADR-0003: Typed declarative policy

- Status: Accepted
- Date: 2026-07-12
- Owners: project maintainers

## Context

AgentGate needs policy for capabilities, argument predicates, information flow, approvals, descriptor findings, and short action chains. General-purpose languages increase expressiveness but also allow I/O, nontermination, hidden dependencies, or review complexity. Adopting a large policy runtime before semantics stabilize would make the prototype harder to reason about.

## Decision

Use a strict, versioned YAML authoring format validated by JSON Schema and compiled to an immutable typed intermediate representation. The evaluator is a total, deterministic, side-effect-free function. The DSL exposes only bounded selectors, predicates, flow rules, chain automata, and obligations specified in `POLICY_MODEL.md`.

Unknown fields, duplicate keys/IDs, invalid references, unsafe unconditional declassification, and ambiguous constructs are compilation errors. No-match is deny.

## Security properties

- Reviewers can reason about the entire policy without executing it.
- Replay produces the same decision from the same IR and context.
- Regex, selectors, and chains have explicit resource bounds.
- Policy cannot call a model/network, read secrets, or mutate gateway state.

## Consequences

- AgentGate must maintain a schema, compiler, linter, migrations, and test runner.
- Some advanced enterprise policies will not fit v0.1 and require deliberate language evolution.
- YAML is only an authoring syntax; security semantics live in the typed IR and decision algorithm.
- Future Cedar/Rego adapters may compile into the same IR or act as an additional deny-only signal, subject to an ADR.

## Alternatives considered

- **Rego/OPA:** powerful and mature, but broad semantics/runtime increase the initial trusted and operational surface.
- **Cedar:** strong authorization model, but AgentGate's flows, taint, obligations, and sequences need substantial surrounding semantics.
- **TOML/JSON only:** stricter syntactically, but less approachable for nontrivial policy; JSON Schema validation still governs YAML.
- **Embedded scripting:** rejected because arbitrary code is incompatible with deterministic safe policy review.

## Validation

Golden compilation vectors, semantic decision tables, property tests for order independence and explicit-deny precedence, mutation testing, lint fixtures, and replay equivalence.
