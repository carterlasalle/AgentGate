# ADR-0007: Deterministic security decisions

- Status: Accepted
- Date: 2026-07-12
- Owners: project maintainers

## Context

Semantic models can notice novel poisoning language or suspicious intent, but their decisions are nondeterministic, prompt-injectable, difficult to replay, and may be unavailable. Putting an LLM in the allow path would make the gateway dependent on the same class of component it is constraining.

## Decision

Authorization, mandatory effects, manifest integrity, provenance matches, and core chain rules are deterministic. Optional model-assisted analysis runs as an isolated additive sensor: it may add findings, increase risk, require review, or deny, but it cannot suppress deterministic findings or turn a deny into allow.

The default v0.1 path has no model or network dependency.

## Security properties

- Same validated context and policy produce the same decision.
- An injected descriptor cannot persuade a security model to grant privilege.
- Offline replay and CI expectations remain stable.
- Loss of model/network availability cannot create permissive fallback.

## Consequences

- Novel semantic attacks may be missed until a deterministic detector/corpus case is added.
- Detector evidence must be explainable and versioned.
- Model-assisted experiments require redaction, isolation, and separate threat modeling.
- Marketing must describe “detection” precisely, not imply complete semantic understanding.

## Alternatives considered

- **LLM as primary policy engine:** rejected for nondeterminism and circular trust.
- **LLM tie-breaker on ambiguous calls:** rejected because ambiguity should fail closed or go to a human.
- **No semantic signal ever:** too restrictive for research; additive deny/review signals preserve the security boundary.

## Validation

Replay equivalence with network disabled, fixtures proving optional model absence cannot change allows, adversarial prompt tests, and tests proving model output cannot suppress deterministic denies.
