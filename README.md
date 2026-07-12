# AgentGate

[![CI](https://github.com/carterlasalle/AgentGate/actions/workflows/ci.yml/badge.svg)](https://github.com/carterlasalle/AgentGate/actions/workflows/ci.yml)
[![Rust 1.97](https://img.shields.io/badge/rust-1.97%2B-orange.svg)](rust-toolchain.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2025--11--25-6f42c1.svg)](https://modelcontextprotocol.io/specification/2025-11-25)

AgentGate is a local security firewall for AI agents. It runs between an MCP host and its tool server, validates and authorizes every JSON-RPC call, tracks sensitive-data provenance, requires exact human approval for consequential actions, quarantines poisoned tool descriptors, detects dangerous action chains, and writes signed replayable audit evidence.

The flagship policy protects [`mac_messages_mcp`](https://github.com/carterlasalle/mac_messages_mcp): local message reads are labeled sensitive; sends always require confirmation; and Messages data cannot flow into unrelated network or upload tools.

> **Status:** working v0.1 security preview. The stdio gateway, policy compiler, approvals, provenance controls, manifest integrity, action-chain containment, signed audit verifier/replay, fake MCP lab, and adversarial corpus are implemented and tested. Review the [security boundary](docs/THREAT_MODEL.md#8-assumptions-and-limitations) before relying on it.

## What is implemented

- Strict newline-delimited JSON-RPC 2.0 parsing with duplicate-key, size, depth, collection, ID, batch, and notification controls.
- MCP `2025-11-25` stdio mediation with lifecycle negotiation, request correlation, tool inventory interception, child-process isolation, and clean shutdown.
- Strict YAML policy-as-code compiled into deterministic typed rules; no match means deny and unknown fields fail compilation.
- Trusted effect classification and non-bypassable human approval for sends, uploads, deletions, and purchases.
- One-time approval receipts bound to canonical arguments, session, policy digest, manifest digest, nonce, and short expiry.
- Native macOS approval dialogs for GUI-launched clients and dedicated-terminal approval elsewhere.
- Per-session HMAC-SHA-256 exact, normalized, and bounded-chunk fingerprints plus conservative session taint.
- Deterministic descriptor-poisoning detectors, normalized manifest pinning, rug-pull quarantine, and safe evidence excerpts.
- Bounded action graph with repeated denial/high-impact action containment.
- Metadata-first JSONL audit chains with domain-separated hashes, Ed25519 checkpoints, trusted-key verification, and no-tool dry replay.
- Eleven hermetic red-team scenarios and synthetic malicious MCP server modes.

## Architecture

```text
MCP host / AI agent
        |
        | JSON-RPC 2.0 over stdio
        v
+-------------------------------------------------+
| AgentGate                                       |
| bounded parse -> inventory/identity -> policy   |
| -> provenance/chain -> exact approval -> audit  |
+-------------------------------------------------+
        |
        | only after allow + completed obligations
        v
downstream MCP server (for example mac_messages_mcp)
```

No denied action is forwarded. Audit precommit failure, policy errors, unavailable approval UI, malformed protocol state, stale manifests, and ambiguous identity all fail closed.

## Quick start

### Build and test

```bash
git clone https://github.com/carterlasalle/AgentGate.git
cd AgentGate
cargo build --release -p agentgate
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Install the CLI locally:

```bash
cargo install --path crates/agentgate-cli
```

### Validate the Messages policy

```bash
agentgate policy check --policy examples/policies/mac_messages_mcp.yaml
agentgate policy test \
  --policy examples/policies/mac_messages_mcp.yaml \
  --cases examples/policies/mac_messages_mcp.tests.yaml
agentgate doctor --policy examples/policies/mac_messages_mcp.yaml
```

### Configure an MCP host

Replace a direct `uvx mac-messages-mcp` entry with AgentGate:

```json
{
  "mcpServers": {
    "messages-protected": {
      "command": "/absolute/path/to/agentgate",
      "args": [
        "run",
        "--policy",
        "/absolute/path/to/AgentGate/examples/policies/mac_messages_mcp.yaml",
        "--state-dir",
        "/absolute/path/to/agentgate-state"
      ]
    }
  }
}
```

The host must launch AgentGate—not `mac-messages-mcp` directly. On macOS, consequential actions open a native approval dialog showing the exact material fields. Deny is the default.

### Run the hermetic security lab

```bash
cargo build -p agentgate-testkit --bin agentgate-fake-mcp
cargo test -p agentgate --test redteam_corpus -- --nocapture
```

The lab uses synthetic data and makes no network calls. See the [demo walkthrough](docs/DEMO.md) for a complete read→blocked upload→confirmed action→audit verification story.

## Audit verification

Every run creates a session log and installation key under the selected state directory:

```bash
agentgate audit verify agentgate-state/audit/<session>.jsonl \
  --key agentgate-state/keys/audit-ed25519.key

agentgate audit replay agentgate-state/audit/<session>.jsonl \
  --key agentgate-state/keys/audit-ed25519.key
```

Verification detects modification, insertion, removal inside the retained chain, duplication, reordering, truncation relative to a trusted checkpoint, and unexpected signing keys. Local-only evidence cannot prove that an attacker with sufficient filesystem control did not delete the entire log.

## Commands

```text
agentgate run --policy <policy.yaml> [--server <id>] [--state-dir <path>]
agentgate policy check --policy <policy.yaml>
agentgate policy test --policy <policy.yaml> --cases <cases.yaml>
agentgate audit verify <audit.jsonl> [--key <signing.key>]
agentgate audit replay <audit.jsonl> [--key <signing.key>]
agentgate audit rotate-key <signing.key>
agentgate doctor --policy <policy.yaml> [--state-dir <path>]
agentgate version
```

## Documentation

| Document | Purpose |
| --- | --- |
| [User guide](docs/USER_GUIDE.md) | Installation, host configuration, policy operation, approvals, audit, troubleshooting |
| [Demonstration](docs/DEMO.md) | Reproducible fake-server and `mac_messages_mcp` walkthroughs |
| [Product requirements](docs/PRD.md) | Users, outcomes, scope, success measures, and release gates |
| [System specification](docs/SPECIFICATION.md) | Normative externally observable behavior |
| [Threat model](docs/THREAT_MODEL.md) | Assets, trust boundaries, adversaries, abuse cases, and residual risk |
| [Technical requirements](docs/TECHNICAL_REQUIREMENTS.md) | Protocol, security, performance, reliability, and operations |
| [Technical design](docs/TECHNICAL_DESIGN.md) | Components, data flows, state, storage, and failure behavior |
| [Policy model](docs/POLICY_MODEL.md) | Capability, flow, taint, approval, and integrity semantics |
| [Test strategy](docs/TEST_STRATEGY.md) | Unit, property, conformance, integration, adversarial, fuzz, fault, and performance evidence |
| [Traceability](docs/TRACEABILITY.md) | Product goals through requirements, decisions, milestones, and tests |
| [Architecture decisions](docs/adr/README.md) | Nine accepted ADRs and tradeoffs |
| [Red-team corpus](redteam/README.md) | Versioned attacks, fake servers, expected outcomes, and safe execution |

Machine-readable schemas are under [`schemas/`](schemas/).

## Security boundary

AgentGate controls only traffic that passes through it. It does not prevent a client or user from launching a tool server through another path, provide an OS kernel sandbox, or perfectly reconstruct provenance after arbitrary model transformation. Conservative session taint exists specifically because absence of a fingerprint match is not proof that transformed content is safe.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Governing references

- [Model Context Protocol specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Practical Guide for Secure MCP Server Development](https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/)

## License

Apache-2.0. See [LICENSE](LICENSE).
