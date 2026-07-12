# AgentGate adversarial corpus

This corpus is a hermetic executable security contract. It uses only synthetic messages, fake tools, local files, and a network-free MCP server. Every case maps to normative requirements and threat-model IDs and asserts both the gateway outcome and whether a tool remained callable downstream.

Run the complete corpus:

```bash
cargo test -p agentgate --test redteam_corpus -- --nocapture
```

Build the interactive fake server used by the end-to-end demo:

```bash
cargo build -p agentgate-testkit --bin agentgate-fake-mcp
```

Modes are `safe`, `poisoned`, `rug-pull`, and `malformed-after-response`. The server never opens a network connection. With `--record <path>`, it appends tool names only so a demonstration can prove that a blocked action never arrived.

Outcome vocabulary follows the test strategy:

- `prevented`: no unsafe downstream execution;
- `confirmed`: exactly one action after bound approval;
- `detected`: finding emitted and tool quarantined;
- `expected_limitation`: explicitly documented behavior outside the guarantee.

The corpus pass count is evidence against these versioned cases, not proof against unknown attacks.
