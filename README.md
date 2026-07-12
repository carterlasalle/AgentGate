# AgentGate

AgentGate is a local security gateway for AI agents. It sits between an MCP host and its tool servers, inspects JSON-RPC traffic, applies policy-as-code, requests human approval for consequential actions, tracks sensitive-data provenance, and writes tamper-evident audit evidence.

The first reference integration protects [`mac_messages_mcp`](https://github.com/carterlasalle/mac_messages_mcp): reading messages is treated as a sensitive source, while sending messages is a consequential action that always requires confirmation. Cross-tool flows from Messages into unrelated network or upload tools are denied unless the user explicitly authorizes the exact flow.

> Status: architecture and delivery specification. Implementation has not started. The documents below are the build contract and use normative requirement IDs that will map directly to tests.

## Why AgentGate

MCP intentionally enables arbitrary data access and tool execution. Its specification places consent, privacy, and tool safety responsibilities on implementors. AgentGate makes those controls explicit and enforceable at the protocol boundary.

```text
MCP host / agent
       |
       | JSON-RPC 2.0 over stdio (v1)
       v
+-----------------------+
| AgentGate             |
| parse -> label ->      |
| policy -> approve ->   |
| forward -> audit       |
+-----------------------+
       |
       v
MCP tool server(s)
```

## Documentation map

| Document | Purpose |
| --- | --- |
| [Product requirements](docs/PRD.md) | Users, outcomes, scope, success measures, and release gates |
| [System specification](docs/SPECIFICATION.md) | Normative product behavior and acceptance scenarios |
| [Threat model](docs/THREAT_MODEL.md) | Assets, trust boundaries, adversaries, abuse cases, and residual risks |
| [Technical requirements](docs/TECHNICAL_REQUIREMENTS.md) | Protocol, security, performance, reliability, and operability requirements |
| [Technical design](docs/TECHNICAL_DESIGN.md) | Architecture, components, data flows, storage, and interfaces |
| [Policy model](docs/POLICY_MODEL.md) | Capability, information-flow, approval, and descriptor-integrity policy semantics |
| [Implementation plan](docs/IMPLEMENTATION_PLAN.md) | Phased roadmap and milestone exit criteria |
| [Technical plan](docs/TECHNICAL_PLAN.md) | Engineering work breakdown, dependency order, and test-first slices |
| [Test strategy](docs/TEST_STRATEGY.md) | Unit, conformance, integration, adversarial, and performance validation |
| [Traceability matrix](docs/TRACEABILITY.md) | Product goals through requirements, decisions, milestones, and tests |
| [Architecture decisions](docs/adr/README.md) | Accepted and proposed ADRs |

## Governing references

- [Model Context Protocol specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25) — current MCP protocol and trust-and-safety requirements at planning time.
- [JSON-RPC 2.0 specification](https://www.jsonrpc.org/specification) — message, correlation, error, notification, and batch semantics.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — agentic threat taxonomy.
- [OWASP Practical Guide for Secure MCP Server Development](https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/) — secure authorization, validation, isolation, and deployment guidance.

## Design principles

1. **Fail closed.** Missing, invalid, or ambiguous policy never grants a capability.
2. **Bind consent to an exact action.** Approval is short-lived, single-use, and cryptographically bound to canonical tool arguments.
3. **Keep enforcement deterministic.** A model may add risk signals but can never be the only reason an action is allowed.
4. **Minimize retained data.** Audit metadata and digests are the default; sensitive payload capture is opt-in and encrypted.
5. **Make security claims testable.** Every normative requirement has an identifier, acceptance evidence, and planned automated test.
6. **Be honest about boundaries.** AgentGate reduces risk at the mediated tool boundary; it cannot secure calls that bypass it or perfectly reconstruct transformed data lineage.

## Planned v1 command surface

```text
agentgate run --config agentgate.yaml
agentgate policy check --policy policy.yaml
agentgate policy test --cases tests/policy
agentgate audit verify ~/.local/share/agentgate/audit.jsonl
agentgate audit replay --session <id> --dry-run
agentgate doctor
```

## License

Licensing is intentionally deferred until implementation begins; see the open decision in the implementation plan.
