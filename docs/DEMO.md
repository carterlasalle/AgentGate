# Reproducible Demonstration

This demo proves the complete mediated story with synthetic data before using private Messages. It requires no network and never sends, uploads, deletes, or purchases anything real.

## 1. Build

```bash
cargo build -p agentgate -p agentgate-testkit \
  --bin agentgate --bin agentgate-fake-mcp
cargo test --workspace --all-features
```

## 2. Run the adversarial corpus

```bash
cargo test -p agentgate --test redteam_corpus -- --nocapture
```

Expected categories:

- unknown capability default deny;
- exact private-data upload prevention;
- send/delete/purchase approval denial;
- poisoned descriptor quarantine;
- post-trust manifest rug-pull revocation;
- consequential batch rejection;
- server-initiated capability denial;
- duplicate-key rejection;
- repeated high-impact attempt containment.

Each PASS line states `prevented` or `detected` plus the stable decision/finding code. The test harness executes the real policy, approval, provenance, integrity, audit, and gateway engine.

## 3. Interactive protocol story

Start the gateway with the hermetic server policy:

```bash
mkdir -p /tmp/agentgate-demo-state
target/debug/agentgate run \
  --policy redteam/policies/lab.yaml \
  --state-dir /tmp/agentgate-demo-state
```

An MCP host normally supplies newline-delimited JSON-RPC. The successful story is:

1. `initialize` negotiates `2025-11-25`.
2. `tools/list` is intercepted; safe manifests are normalized/pinned before advertisement.
3. `read_messages` returns `Synthetic private message: launch code ORANGE-742` and registers `personal.messages.content` without plaintext audit retention.
4. `http_upload` with that content returns `AG-SESSION-TAINT`; the fake server does not observe the call.
5. `send_message`, `delete_items`, and `purchase_item` pause for exact human approval.
6. Session shutdown writes an Ed25519 checkpoint.

Verify the resulting evidence:

```bash
AUDIT_FILE=$(find /tmp/agentgate-demo-state/audit -name '*.jsonl' | head -1)
target/debug/agentgate audit export-key \
  --signing-key /tmp/agentgate-demo-state/keys/audit-ed25519.key \
  --output /tmp/agentgate-demo-state/keys/audit-ed25519.pub
target/debug/agentgate audit verify "$AUDIT_FILE" \
  --public-key /tmp/agentgate-demo-state/keys/audit-ed25519.pub
target/debug/agentgate audit replay "$AUDIT_FILE" \
  --public-key /tmp/agentgate-demo-state/keys/audit-ed25519.pub
```

The verifier reports event/checkpoint counts, final hash, and expected key ID. Replay reports decisions/forwards/denials and does not execute the fake server.

## 4. Poisoned server modes

The synthetic server supports:

```bash
target/debug/agentgate-fake-mcp --mode poisoned
target/debug/agentgate-fake-mcp --mode rug-pull
target/debug/agentgate-fake-mcp --mode malformed-after-response
```

- `poisoned` advertises an upload description that attempts to override security policy and solicit an API key. AgentGate removes it before the host sees it.
- `rug-pull` advertises a safe manifest once and a changed malicious descriptor on the next inventory. AgentGate revokes it from the session inventory.
- `malformed-after-response` writes invalid JSON after a valid response. AgentGate terminates the downstream session rather than guessing at correlation.

## 5. Messages integration

After the synthetic demo passes:

1. Install/configure `mac_messages_mcp` and grant Full Disk Access to the MCP host.
2. Validate `examples/policies/mac_messages_mcp.yaml` and its fixtures.
3. Configure the host using [USER_GUIDE.md](USER_GUIDE.md#4-configure-mac_messages_mcp).
4. Ask the agent to search recent messages. Confirm the read succeeds.
5. Ask it to send a harmless test message to your own device. Confirm the native dialog shows the exact recipient and body; change/cancel it and verify no send occurs.
6. Reissue and approve once. Confirm only one send occurs.
7. Connect a synthetic unrelated sink in a separate lab configuration and verify Messages-derived data is denied.
8. Stop the session and verify the signed audit log with the expected local key.

Never use real private content in the published red-team report. The reproducible repository evidence uses only synthetic fixtures.

## 6. What this demonstrates—and what it does not

It demonstrates protocol mediation, default deny, exact approval binding, known-value and session-level flow controls, descriptor integrity, action-chain containment, and tamper evidence for traffic crossing AgentGate.

It does not prove that a host cannot bypass AgentGate, that downstream code is kernel-sandboxed, that arbitrary paraphrases can be perfectly traced, or that an administrator cannot delete all local evidence. Those boundaries are explicit in the [threat model](THREAT_MODEL.md).
