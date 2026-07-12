# ADR-0002: Rust enforcement core

- Status: Accepted
- Date: 2026-07-12
- Owners: project maintainers

## Context

The gateway parses hostile input, manages concurrent request correlation, holds approval and signing secrets, launches child processes, and sits on a latency-sensitive path. Memory-safety defects, accidental shared mutation, or ambiguous wire/domain types could directly violate the reference-monitor guarantee.

## Decision

Implement the enforcement core and CLI as a Rust workspace on a pinned stable toolchain. Use strong domain types between wire validation, policy, approval, forwarding, and audit boundaries. Forbid unsafe Rust in production unless a future ADR documents the exact need and proof obligation.

## Security properties

- Memory and thread safety by default for hostile protocol handling.
- Exhaustive enums for decisions and state machines.
- Explicit ownership around pending requests, approval consumption, and shutdown.
- Single-binary local deployment with a small runtime surface.

Rust reduces classes of defects; it does not make protocol, policy, cryptographic, or logic errors impossible.

## Consequences

- Contributors need Rust proficiency and compile times are higher than scripting-language prototypes.
- Core libraries are split into narrow crates to preserve type boundaries.
- Fuzzing, sanitizers where supported, clippy, and dependency auditing become standard CI gates.
- Python/TypeScript may be used for isolated corpus fixtures or demo servers but not authorization decisions.

## Alternatives considered

- **Python:** excellent MCP ecosystem and iteration speed, but weaker compile-time state/ownership guarantees for the enforcement core.
- **TypeScript:** good SDK compatibility, but runtime validation and single-binary local packaging are less attractive here.
- **Go:** strong deployment/concurrency story, but Rust's enums, ownership, and control over allocation are preferred for the security-critical parser/state machine.

## Validation

Compile-time boundary tests, denied warnings, property tests for state machines, fuzz targets for all hostile parsers/canonicalizers, and release benchmarks on supported platforms.
