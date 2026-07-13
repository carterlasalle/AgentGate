# Supported Versions and Compatibility

| Line | Status | Security fixes | Policy API | Audit schema |
| --- | --- | --- | --- | --- |
| 1.x | Supported | Yes | `agentgate.dev/v1` | 1 |
| 0.1 preview | Unsupported after 1.0 | No | `agentgate.dev/v1alpha1` | 1 |

AgentGate 1.x follows semantic versioning. Patch releases may tighten deterministic detection, reject previously ambiguous invalid input, and add deny-only signals. New allow behavior, policy precedence changes, canonical action changes, approval binding changes, or audit hash/signature changes require a new documented schema/profile and migration path.

The stable policy loader rejects preview documents and unknown fields. The explicit migration command is maintained for the 1.x line. Audit schema 1 remains readable throughout 1.x. Removing a stable field or decision code requires a major release.

MCP `2025-11-25`, macOS arm64/x86_64, and Linux x86_64 are the 1.0 compatibility baseline. Windows and remote MCP transports are not claimed as supported by 1.0.

Security reports follow [SECURITY.md](../SECURITY.md). Critical fixes target the current 1.x release. The project does not promise fixes for preview builds.

