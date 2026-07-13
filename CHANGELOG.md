# Changelog

All notable changes are documented here. AgentGate follows semantic versioning after the v1 policy/audit schemas stabilize.

## [Unreleased]

## [1.0.0] - 2026-07-12

### Added

- Rust workspace with isolated protocol, core, policy, approval, provenance, integrity, audit, testkit, and CLI crates.
- Bounded strict JSON-RPC 2.0 and MCP `2025-11-25` stdio reference monitor.
- Strict policy compiler, fixture runner, canonical action digests, and default-deny enforcement.
- Mandatory exact human approval for send, upload, delete, and purchase effects.
- Native macOS approval dialogs and dedicated-terminal fallback for other platforms.
- Keyed exact/normalized/chunk provenance and conservative session taint.
- Tool-description poisoning detectors, manifest pinning, rug-pull revocation, and bounded chain containment.
- Metadata-first hash-chained JSONL audit events, Ed25519 checkpoints, public-key verification, detached anchors, and dry replay.
- Synthetic MCP server, 11-case adversarial corpus, Messages reference policy, complete planning/design record, and operational guides.
- Stable `agentgate.dev/v1` policy schema with explicit non-overwriting preview migration and canonical policy diff.
- Authenticated lineage envelopes bound to session, destination, exact arguments, nonce, and a five-minute maximum validity window.
- Supported-version, upgrade/rollback, incident-response, v1 evidence, and independent-review packet documentation.
- Direct-main release-smoke builds for every supported target and CycloneDX SBOMs in tagged releases.
