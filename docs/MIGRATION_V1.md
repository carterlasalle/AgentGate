# AgentGate 1.0 Migration Guide

AgentGate 1.0 freezes the policy API as `agentgate.dev/v1`, keeps audit schema 1 readable, and changes verification so operators can distribute a public key instead of exposing the installation signing key.

## 1. Safe upgrade sequence

1. Stop the MCP host so no session is in flight.
2. Back up the policy, state directory, binary, and last trusted public key.
3. Migrate each preview policy to a new path; migration refuses to overwrite files.
4. Review the generated diff, run policy fixtures, and run `doctor`.
5. Export the audit public key and verify retained logs before replacing the binary.
6. Install AgentGate 1.0, update host arguments, then execute the synthetic read/block/confirm journey.
7. Retain the previous binary and policy until the first 1.0 session and detached anchor verify.

```bash
agentgate policy migrate --policy policy-v1alpha1.yaml --output policy-v1.yaml
agentgate policy check --policy policy-v1.yaml
agentgate policy test --policy policy-v1.yaml --cases policy.tests.yaml
agentgate policy diff --current policy-v1.yaml --candidate policy-v1.yaml
agentgate doctor --policy policy-v1.yaml --state-dir ~/.local/state/agentgate
```

Migration only changes the schema identifier. It parses the entire preview document with strict unknown-field rejection, validates stable-v1 invariants, and serializes a complete reviewed destination. The runtime never silently upgrades preview policy.

## 2. Audit verifier migration

Preview commands accepted a raw private signing-key path through `--key`. Version 1.0 deliberately replaces that interface with a public verifier:

```bash
agentgate audit export-key \
  --signing-key ~/.local/state/agentgate/keys/audit-ed25519.key \
  --output ~/.local/state/agentgate/keys/audit-ed25519.pub

agentgate audit verify SESSION.jsonl \
  --public-key ~/.local/state/agentgate/keys/audit-ed25519.pub
```

Copy the `.pub` file—not the signing key—to auditors. Publish a detached anchor to storage outside the protected workstation when whole-log deletion evidence matters:

```bash
agentgate audit anchor SESSION.jsonl \
  --signing-key ~/.local/state/agentgate/keys/audit-ed25519.key \
  --output SESSION.anchor.json
agentgate audit verify-anchor SESSION.jsonl \
  --anchor SESSION.anchor.json \
  --public-key ~/.local/state/agentgate/keys/audit-ed25519.pub
```

An anchor held on the same filesystem remains tamper evidence, not deletion proof. The operator must copy it to an independent append-only or retention-locked system.

## 3. Authenticated lineage

Lineage is off unless `run --lineage-key <32-byte-file>` is configured. Initialization then advertises `_meta.agentgate.sessionId` and `authenticatedLineage: true`. A trusted host adapter may attach up to 32 signed assertions in `params._meta.agentgateLineage`. Each assertion is bound to:

- schema, session, configured server, and exact tool;
- canonical digest of the exact arguments;
- issue and expiry timestamps, with a maximum five-minute lifetime;
- a bounded adapter nonce and provenance label.

Invalid, forged, stale, cross-session, cross-tool, or argument-swapped claims fail closed. Lineage adds risk evidence; it does not bypass a deny or the mandatory approval invariant.

## 4. Rollback

Stop the host, restore the prior binary and matching preview policy, and verify the last v1 audit log before resuming. Never feed the stable policy to the preview binary. Audit schema 1 remains readable in both releases; detached anchors are an additive v1 artifact. Record the rollback reason and preserved log hashes in the incident record.

