# ADR-0001: Local protocol-aware proxy

- Status: Accepted
- Date: 2026-07-12
- Owners: project maintainers

## Context

AgentGate needs to observe and authorize individual MCP actions while preserving compatibility with existing hosts and servers. An SDK library would require each host to integrate correctly. A network-only gateway would not cover local stdio servers such as `mac_messages_mcp`. An OS sandbox can restrict processes but cannot explain tool semantics, source-to-sink flows, or exact user consent by itself.

## Decision

AgentGate will be a local, protocol-aware bidirectional proxy. In v0.1, the host launches AgentGate as its MCP server and AgentGate launches exactly one downstream server as a child process. The gateway terminates and re-originates the MCP/JSON-RPC connection while preserving valid protocol semantics.

One host connection plus one downstream server per process is the v0.1 isolation unit. Multi-server orchestration can be added only after stable server identity and cross-server failure semantics are specified.

## Security properties

- A single synchronous enforcement point exists before downstream execution.
- Downstream identity cannot be confused with another server in the same process.
- Local stdio tools are covered without modifying their source.
- Process lifecycle, environment, framing, and audit can be bounded together.

This does not prevent a host or user from launching the downstream server directly.

## Consequences

- Hosts must be configured to invoke AgentGate instead of the raw server.
- AgentGate must correctly implement both client- and server-side MCP lifecycle behavior.
- A process is required per protected downstream server, increasing small fixed overhead but simplifying isolation.
- OS sandboxing remains complementary future hardening, not the primary policy mechanism.

## Alternatives considered

- **Host SDK:** rejected as the only enforcement point because adoption and correctness depend on every host.
- **Server wrapper library:** rejected because malicious/unmodified servers remain outside control.
- **Network reverse proxy only:** rejected for stdio-first local integrations.
- **Kernel/endpoint enforcement:** valuable defense in depth but cannot express MCP semantics alone.

## Validation

Run unmodified `mac_messages_mcp` behind the proxy; prove no denied test call reaches the fake downstream server; document and test detectable bypass configurations in `agentgate doctor`.
