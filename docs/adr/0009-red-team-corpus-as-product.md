# ADR-0009: Red-team corpus as a product artifact

- Status: Accepted
- Date: 2026-07-12
- Owners: project maintainers

## Context

Security claims are difficult to evaluate from architecture prose alone. A private or ad hoc test suite would not demonstrate which attacks AgentGate handles, where it fails, or whether a change regressed protection. The portfolio value also depends on reproducible evidence, not feature count.

## Decision

Treat the synthetic malicious prompt/tool corpus, fake MCP servers, expected decision manifests, and release evaluation report as versioned first-class artifacts. Every critical security requirement maps to at least one positive and negative corpus case. CI runs the safe hermetic subset; extended fuzz/performance campaigns publish summaries for tagged releases.

The `mac_messages_mcp` demo is an executable acceptance system: a real local server plus synthetic unrelated sinks and malicious servers, using synthetic Messages fixtures wherever real user data is not required.

## Security properties

- Claims are tied to repeatable inputs and expected outcomes.
- Regressions become visible during review.
- Known bypasses can be preserved as failing/expected-limitation cases rather than forgotten.
- Corpus data cannot contact real services or contain real secrets.

## Consequences

- Corpus schema, isolation, versioning, and triage require ongoing maintenance.
- Publishing attack fixtures needs responsible review to avoid unnecessary weaponization.
- A high pass rate is not proof against unknown attacks; the report must state coverage and limitations.
- Release work includes generating an evidence report, not only binaries.

## Alternatives considered

- **Unit tests only:** insufficient multi-step/protocol realism.
- **Private corpus:** weak external credibility and reproducibility.
- **One-time penetration test:** valuable but not regression protection.
- **Live third-party targets:** rejected as unsafe, flaky, and potentially unauthorized.

## Validation

Hermetic network-deny CI, schema validation for every case, unique requirement mapping, deterministic expected decisions, synthetic-data scanning, and signed release report/checksums.
