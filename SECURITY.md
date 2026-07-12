# Security policy

AgentGate is pre-1.0 security software. Please do not rely on it as the sole control for production secrets or irreversible actions until the relevant release is marked security-stable.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do not open a public issue containing exploit details, private data, credentials, or a working bypass against real systems.

Include the affected commit/version, platform, policy, minimal synthetic reproduction, expected behavior, observed behavior, and whether a denied action reached a downstream server. Reports involving exact-action approval reuse, default-deny bypass, audit forgery, or unauthorized source-to-sink flow are treated as critical.

## Supported versions

Until v1.0, only the latest tagged release receives security fixes. Security guarantees and known limitations are documented in the release evidence bundle and [threat model](docs/THREAT_MODEL.md).

## Safe research

Use synthetic data and the repository's fake MCP servers. Do not test against systems or accounts you do not own or have explicit permission to assess.
