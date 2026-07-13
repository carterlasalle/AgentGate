# ADR-0011: Authenticate Host Lineage Out of Band

- Status: Accepted
- Date: 2026-07-12

## Context

Fingerprints cannot prove lineage after arbitrary transformation. Unauthenticated host annotations can raise risk but must not establish trusted provenance.

## Decision

A dedicated 32-byte key shared with a trusted host adapter authenticates bounded lineage claims. Initialization advertises the exact session identifier. Claims travel in MCP request `_meta`, are not forwarded as tool arguments, and bind schema, session, server, tool, canonical argument digest, label, issue/expiry time, and nonce. HMAC-SHA-256 uses a v1 domain separator and canonical claim bytes. Missing configuration, malformed envelopes, forgery, expiry, and binding mismatch fail closed.

Authenticated lineage adds provenance evidence. It cannot override deterministic denial or remove exact approval. A claim lifetime cannot exceed five minutes and a call accepts at most 32 assertions.

## Consequences

The adapter and lineage key join the trusted computing base when enabled. Operators should use a distinct key and restrictive file permissions. Semantic truth still depends on adapter correctness; cryptography proves origin and binding, not that the adapter classified content correctly.

