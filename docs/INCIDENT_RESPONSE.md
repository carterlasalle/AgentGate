# Incident Response Runbook

## Trigger conditions

Treat unexpected forwarding, signature failure, manifest change, repeated approval mismatch, policy rollback, state-permission drift, or evidence deletion as a security incident. A denied or quarantined attack with intact evidence is an alert to investigate, not proof of compromise.

## 1. Contain

1. Stop the MCP host and AgentGate process. Do not approve pending actions.
2. Disable direct MCP server entries that bypass AgentGate.
3. Isolate the workstation from unneeded networks if execution or credential access is suspected.
4. Preserve the active binary, policy, state directory, host configuration, and process metadata. Do not run retention or key rotation yet.

## 2. Preserve and verify

Work on copies. Export the current public verifier, hash the binary/policy/configuration, and run offline audit verification. Compare any detached anchor held outside the workstation. A failed chain identifies the first invalid retained event; a missing whole log requires external anchors or platform evidence to establish deletion.

```bash
agentgate audit verify SESSION.jsonl --public-key TRUSTED.pub
agentgate audit verify-anchor SESSION.jsonl --anchor TRUSTED.anchor.json --public-key TRUSTED.pub
agentgate audit replay SESSION.jsonl --public-key TRUSTED.pub
agentgate policy check --policy ACTIVE.yaml
agentgate doctor --policy ACTIVE.yaml --state-dir STATE_DIR
```

Never upload raw Messages content, private signing keys, approval state, or unredacted state directories to a public issue.

## 3. Scope

Determine the first affected session, server/tool identity, policy and manifest digests, action digests, decision codes, approvals, forwarded count, and unknown outcomes. Check host configuration for bypass paths. Compare the installed binary checksum with the release artifact and provenance. Review manifest trust changes and recently changed inherited environment variables.

## 4. Eradicate and recover

Patch the root cause before resuming. Revoke exposed downstream credentials. Replace compromised policy/configuration from a reviewed source. Rotate the AgentGate audit key only after preserving the old key for prior-log verification and recording the signed transition. Clear manifest trust only after independently reviewing new tool descriptors. Restore service with a synthetic deny/read/confirm test, then anchor the first recovered session externally.

## 5. Communicate and learn

Use the private reporting channel in `SECURITY.md` for suspected product vulnerabilities. Record impact, affected versions, timeline, evidence confidence, containment, root cause, and corrective tests. Add a minimized non-sensitive regression case to the corpus and update the threat model/ADR when the trust boundary changed.

