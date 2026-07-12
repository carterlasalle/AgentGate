# ADR-0004: Conservative information-flow tracking

- Status: Accepted
- Date: 2026-07-12
- Owners: project maintainers

## Context

A transparent MCP proxy sees sensitive tool results and later tool arguments, but the host/model sits between them. Exact values may be copied, normalized, summarized, encoded, or transformed. Claiming complete dynamic taint tracking without host/model instrumentation would be false; exact matching alone would miss transformed disclosure.

## Decision

Use layered provenance evidence:

1. policy-declared structured source/sink selectors;
2. per-installation keyed exact and type-normalized fingerprints;
3. bounded keyed chunk fingerprints for suitable high-entropy/long values;
4. authenticated structured lineage from cooperating host extensions;
5. conservative session taint that can restrict unrelated external sinks after sensitive reads.

Evidence is attributed by method/confidence. Absence of a match never means data is proven safe. Declassification is explicit, destination/field/purpose bounded, short-lived, and normally requires human approval.

## Security properties

- Direct and normalized copy exfiltration is deterministically detectable.
- Stored fingerprints resist simple offline guessing better than raw hashes.
- Transformed-data risk remains constrained through session-level policy.
- Untrusted host lineage cannot create an allow.

## Consequences

- Session taint can block legitimate external actions and needs good explanations.
- Fingerprint state requires strict memory/TTL limits and privacy review.
- Normalization profiles become security-sensitive versioned code.
- Perfect semantic lineage remains an explicit non-goal.

## Alternatives considered

- **Exact matching only:** rejected as an inadequate flagship claim.
- **LLM classifier for sensitive similarity:** nondeterministic and vulnerable to evasion; may add risk only later.
- **Modify every host/model runtime for taint:** stronger but incompatible with transparent deployment; supported later through authenticated lineage.
- **Block all network tools permanently:** secure but unusably coarse.

## Validation

Corpus cases cover exact copy, whitespace/case/phone normalization, substrings, encoding/transformation misses, forged lineage, session-taint restrictions, declassification binding, and bounded-state eviction.
