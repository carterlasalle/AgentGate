# User Guide

## 1. Prerequisites

- macOS or Linux with Rust 1.97+ for source installation.
- An MCP host that supports stdio servers and MCP `2025-11-25`.
- The downstream server executable and dependencies.
- For the Messages integration: macOS, `uv`/`uvx`, Full Disk Access for the launching host, and `mac_messages_mcp` prerequisites.

AgentGate is local. It does not require an account, hosted service, model API, or network connection of its own.

## 2. Installation

```bash
cargo install --git https://github.com/carterlasalle/AgentGate \
  --package agentgate
```

From a checkout:

```bash
cargo install --path crates/agentgate-cli
agentgate version
```

Release builds use thin LTO, one codegen unit, overflow checks, stripped symbols, and abort-on-panic.

## 3. Start with policy validation

Never discover policy errors while a host is starting:

```bash
agentgate policy check --policy examples/policies/mac_messages_mcp.yaml
agentgate policy test \
  --policy examples/policies/mac_messages_mcp.yaml \
  --cases examples/policies/mac_messages_mcp.tests.yaml
agentgate doctor --policy examples/policies/mac_messages_mcp.yaml \
  --state-dir "$HOME/Library/Application Support/AgentGate"
```

`check` rejects unknown fields, permissive defaults, invalid identities/selectors/durations, unknown labels, duplicate IDs, empty tool sets, and unreviewed declassification. It prints the canonical policy digest used by approval and audit binding.

## 4. Configure `mac_messages_mcp`

The included policy launches:

```text
uvx mac-messages-mcp
```

It inherits only `PATH`, `HOME`, and `TMPDIR`. Add a variable to `inheritEnvironment` only when the downstream executable needs it. Prefer explicit non-secret `environment` values. AgentGate clears the child environment first and never invokes a shell.

Configure the MCP host to launch AgentGate:

```json
{
  "mcpServers": {
    "messages-protected": {
      "command": "/Users/you/.cargo/bin/agentgate",
      "args": [
        "run",
        "--policy",
        "/Users/you/src/AgentGate/examples/policies/mac_messages_mcp.yaml",
        "--server",
        "mac-messages",
        "--state-dir",
        "/Users/you/Library/Application Support/AgentGate"
      ]
    }
  }
}
```

Remove or disable the direct unprotected Messages server entry. If both exist, the host can bypass AgentGate.

Full Disk Access belongs to the application that launches the process chain. Restart the host after changing macOS privacy permissions.

## 5. Approval experience

AgentGate requires exact human approval for trusted effects `send`, `upload`, `delete`, and `purchase`, even if a policy author writes an allow rule without an obligation.

On macOS, a native modal dialog displays:

- configured server and exact tool;
- trusted effects;
- policy-selected material fields such as recipient, message, path, IDs, or amount;
- exact action digest.

On other platforms, the same bounded content appears on the dedicated controlling terminal. Protocol stdin is never used for approval.

Approval rules:

- The user must type/click Approve intentionally; Deny is the default.
- The receipt is valid once, for 1–300 seconds as configured.
- Any argument, session, policy, or manifest change makes it stale.
- Concurrent identical calls cannot reuse a receipt.
- UI error, closure, timeout, malformed response, or denial fails closed.
- Agent/tool conversational text is never consent.

## 6. Information-flow behavior

When a configured source returns sensitive fields, AgentGate:

1. adds hierarchical source labels to session state;
2. registers keyed exact and configured normalized fingerprints;
3. optionally registers bounded keyed chunks for long values;
4. stores no source plaintext in default audit events;
5. restricts destination effects using flow and session-taint rules.

Exact and normalized matches explain the detected source label and method. Session taint is intentionally conservative: after Messages content enters the model context, unrelated network/upload/send effects can remain denied even when a later argument no longer contains an exact copy.

End the MCP session to clear session taint. v0.1 deliberately has no casual “clear taint” action.

## 7. Tool integrity

Before advertising `tools/list` results, AgentGate validates and hashes each descriptor. Safe first observations establish local trust. A tool is removed from the advertised inventory when:

- its trusted manifest changes;
- it contains hidden/bidirectional control characters;
- it attempts to override policy or privileged instructions;
- it solicits credentials/secrets;
- it coerces unrelated cross-tool calls;
- it exceeds descriptor bounds.

Trust state is stored at `STATE_DIR/trust/manifests.json`. Delete or edit it only as an intentional trust reset; the change affects future sessions and is not proof that the new descriptor is safe.

## 8. State and permissions

```text
STATE_DIR/
  audit/<timestamp>-<session>.jsonl
  keys/audit-ed25519.key
  trust/manifests.json
```

Audit and key files are created owner-only on Unix. Keep the signing key separate when validating copied evidence. Anyone with the signing key can create a different valid chain; `--key` ensures the checkpoint was signed by the expected installation key.

By default, startup removes audit JSONL files older than 30 days and keeps aggregate retained audit data under 512 MiB. Configure `agentgate run` with `--audit-retention-days` and `--audit-maximum-bytes`. The new session records the retention summary; non-audit files are never removed.

Default audit records contain IDs, digests, effects, labels, findings, byte counts, decisions, and timings—not raw tool arguments or results.

## 9. Audit verification and replay

```bash
agentgate audit verify STATE_DIR/audit/SESSION.jsonl \
  --key STATE_DIR/keys/audit-ed25519.key
```

A non-zero exit means the log is malformed, the chain is broken, a checkpoint signature is invalid, or the signer is unexpected.

```bash
agentgate audit replay STATE_DIR/audit/SESSION.jsonl \
  --key STATE_DIR/keys/audit-ed25519.key
```

Replay first performs complete verification, then reports recorded decisions, forwards, denials, and policy digests. It does not launch a downstream server, execute a tool, resolve DNS, or make a network request.

Rotate the installation signing key intentionally:

```bash
agentgate audit rotate-key STATE_DIR/keys/audit-ed25519.key
```

Rotation archives the old owner-only key for prior-log verification, installs a new key atomically, and writes a JSON transition record signed by the retired key. Preserve the transition record and retired key according to your evidence-retention policy.

## 10. Common failures

### `unsupported MCP protocol version`

The host did not request `2025-11-25`. AgentGate fails before tool execution. Upgrade/configure the host or use a compatible version of AgentGate; do not edit the constant to bypass negotiation.

### `tool is not present in the trusted session inventory`

The tool was never advertised, was quarantined, changed after trust, or the host used a stale inventory. Inspect audit `inventory_observed` and `manifest_finding` events and restart only after reviewing the descriptor.

### Approval always denies

On macOS, confirm `/usr/bin/osascript` can present dialogs in the host session. On other systems, launch the MCP host from a controlling terminal. Provider failure is intentionally a denial.

### `uvx` cannot be found

Run `agentgate doctor`, verify `PATH` is inherited in the selected server policy, and use an absolute executable path if the host has an unusual GUI environment.

### Audit creation fails

Choose an owner-writable state directory that does not already contain the generated session filename. AgentGate refuses high-impact execution when audit precommit fails.

### The client can still call an unprotected Messages server

Remove the direct `mac-messages-mcp` configuration. AgentGate cannot control a path that does not cross its process boundary.

## 11. Operational verification checklist

- Policy check and fixtures pass.
- Host config points to AgentGate only.
- `doctor` shows the expected executable, argument count, digest, and state directory.
- `tools/list` contains expected tools and no quarantined descriptor.
- A read works and produces provenance/audit metadata.
- A send shows exact recipient/body and executes only once after approval.
- A synthetic unrelated upload is denied.
- Audit verifies using the expected key.
- Red-team corpus passes on the release commit.
