# ADR-0008: Stdio-first transport

- Status: Accepted
- Date: 2026-07-12
- Owners: project maintainers

## Context

The flagship `mac_messages_mcp` integration is launched locally over stdio. Supporting stdio and Streamable HTTP simultaneously would expand lifecycle, authentication, session, origin, and network attack surfaces before the core authorization model is validated.

## Decision

Ship MCP stdio in v0.1. Define an internal transport contract around framed validated messages, peer identity, lifecycle, cancellation, and shutdown so Streamable HTTP can be added in v0.2 without changing canonical action or policy semantics.

Transport-specific identity and authorization are established before messages enter the common policy path. Tests for policy, provenance, approval, and audit are transport-independent.

## Security properties

- First release covers the real local Messages use case with the smallest network surface.
- Child-process identity/configuration can be bound directly to policy.
- Later HTTP support cannot silently redefine action identity or bypass shared authorization.

## Consequences

- Remote MCP servers are not supported in v0.1.
- Stdio framing, diagnostic stream separation, and child lifecycle need excellent tests.
- HTTP needs a separate ADR for authentication, DNS/rebinding, redirects, TLS, origin, and session resumption before release.

## Alternatives considered

- **HTTP first:** does not best serve the flagship local integration and adds network threats.
- **Both immediately:** dilutes hardening and doubles early conformance work.
- **Use a generic byte proxy:** cannot enforce MCP method, identity, argument, or flow semantics.

## Validation

Official-protocol fixtures, fake host/server lifecycle tests, unmodified `mac_messages_mcp` integration, malformed framing/resource-limit tests, and a transport-contract test suite designed for reuse by v0.2 HTTP.
