# AgentGate 1.0 Release Evidence

**Version:** 1.0.0  
**Policy API:** `agentgate.dev/v1`  
**Audit schema:** 1  
**MCP:** `2025-11-25`

## Milestone closure

| Milestone | Evidence in tree | Status |
| --- | --- | --- |
| M0 guardrails | pinned Rust, strict lints, CI, supply-chain policy, security/contribution docs | Complete |
| M1 protocol proxy | bounded JSON-RPC parser, correlation, lifecycle, no-shell stdio transport | Complete |
| M2 policy | strict stable schema, typed IR, fixtures, default deny, canonical digest | Complete |
| M3 approval | exact-action binding, one-use/expiry/session/policy/manifest checks, safe UI | Complete |
| M4 provenance | keyed exact/normalized/chunk evidence, session taint, authenticated lineage | Complete |
| M5 integrity | manifest pinning, descriptor poisoning, schema checks, bounded chains | Complete |
| M6 audit | canonical hash chain, Ed25519 checkpoints, rotation, public verification, dry replay | Complete |
| M7 flagship lab | synthetic Messages policy, fake MCP server, adversarial corpus | Complete |
| M8 preview hardening | fuzz targets, benchmark, retention, release workflows, operational docs | Complete |
| M9 v1 bridge | policy diff/migration, native macOS approval, detached anchoring experiment | Complete for selected v1 scope |
| M10 stability | stable schemas, compatibility policy, upgrade/rollback and incident runbooks | Complete internally |
| M11 operational assurance | public-key verifier, detached-anchor workflow, CLI contract tests, push/release gates | Complete internally |

## Security evidence commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo deny check advisories bans licenses sources
cargo test -p agentgate --test redteam_corpus -- --nocapture
cargo bench -p agentgate-core --bench canonical_action
python3 scripts/check_docs.py
```

Release artifacts are built for Linux x86_64 and macOS arm64/x86_64, checksummed, supplied with CycloneDX SBOMs, and submitted to GitHub artifact attestation. CI runs the release build matrix on direct `main` pushes as well as pull requests.

## Compatibility and schema guarantees

The runtime accepts stable policy v1 only. `policy migrate` converts a complete preview document to a new reviewed file and refuses overwrite. `policy diff` exposes canonical digest and added/removed stable identities. Audit schema 1 remains readable; verification consumes a public key, while private keys are limited to signing, rotation, and explicit detached-anchor creation.

## Assurance status

All implementation-controlled M0–M11 gates are represented in code, tests, automation, or runbooks. The PRD also calls for independent external threat-model and cryptographic review. No repository author or AI implementation session can truthfully self-certify that external gate. The review packet is the PRD, threat model, ADRs 0004–0007 and 0010–0012, canonicalization code/vectors, approval state machine, audit implementation/vectors, corpus, and this evidence file. A 1.0 release should record reviewer identity, scope, report hash, findings, and resolutions here before claiming independent assessment.

This limitation does not weaken the runtime fail-closed behavior; it limits the assurance claim. AgentGate does not claim an OS sandbox, bypass prevention outside configured MCP traffic, perfect semantic provenance, or whole-log deletion proof without an independently retained anchor.

