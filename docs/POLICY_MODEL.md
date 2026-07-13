# Policy Model

**Status:** Stable authoring contract for AgentGate 1.x
**Format:** Strict YAML, schema `agentgate.dev/v1`

## 1. Goals

The AgentGate policy language is deliberately narrower than a general-purpose policy engine. It must be reviewable in a code review, deterministic offline, safe to evaluate on hostile input, and expressive enough for capabilities, information flow, approval obligations, descriptor integrity, and bounded action chains.

Policy files cannot execute code, interpolate shell commands, call services/models, or grant permissions through unknown fields.

## 2. Document shape

```yaml
apiVersion: agentgate.dev/v1
kind: GatewayPolicy
metadata:
  name: messages-local
  version: 1
defaults:
  decision: deny
  audit: metadata
servers: []
labels: []
flows: []
chains: []
invariants: []
```

The compiler rejects duplicate keys and rule IDs, aliases/anchors if the selected parser cannot bound expansion, unknown top-level keys, invalid selectors, cyclic label definitions, unsafe unconditional declassification, and references to undeclared labels/effects.

## 3. Stable identity

A server selector includes a local policy ID and executable identity. Version 1 supports command path plus configured package/version or executable digest. Display name alone is never an identity.

A tool selector is scoped under a server and matches an exact tool name by default. Regex selectors require an explicit `match: regex` and use a linear-time engine. Manifest pinning may be `required`, `review_on_change`, or `observe`.

## 4. Effects

Built-in effects:

- `read`, `read_file`, `write`, `execute`, `network`;
- `send`, `upload`, `delete`, `purchase`;
- `credential_access`, `permission_change`, `process_control`.

Policy classifications may add effects. Built-in heuristics and trusted adapters may also add effects; no server-supplied annotation can remove one. The v1 invariant layer always adds human approval to `send`, `upload`, `delete`, and `purchase`.

## 5. Labels and selectors

Labels declare sensitivity and normalization:

```yaml
labels:
  - name: personal.messages.content
    sensitivity: restricted
    normalization: text
    sessionTaint: true
    fingerprint:
      exact: true
      normalized: true
      chunks:
        minBytes: 24
        windowBytes: 48
```

Source rules attach labels to downstream result fields using bounded selectors. Sink rules identify fields leaving a trust boundary. Missing fields do not silently match; selector errors create findings and follow the rule's `onError`, defaulting to deny when security-relevant.

## 6. Capability rules

```yaml
rules:
  - id: allow-message-search
    match:
      server: mac-messages
      tools:
        - tool_get_recent_messages
        - tool_fuzzy_search_messages
    effects: [read]
    decision: allow
    sources:
      - select: /content
        label: personal.messages.content
```

Rules may constrain arguments by presence, type, equality, bounded set membership, numeric range, anchored regex, path prefix after safe normalization, and collection size. General expression evaluation is excluded.

## 7. Flow rules

```yaml
flows:
  - id: deny-messages-to-network
    from: personal.messages
    to:
      effects: [network, upload]
    decision: deny

  - id: confirm-message-send
    from: personal.messages.content
    to:
      server: mac-messages
      tool: tool_send_message
      fields: [/message]
    decision: allow
    obligations:
      - type: human_approval
        display: [recipient, message]
        ttl: 60s
```

An allow flow is not itself a tool capability; both the tool rule and flow must allow. Declassification must be destination- and field-specific, time bounded, and approved when releasing restricted labels.

## 8. Session-taint rules

```yaml
sessionTaint:
  - id: restrict-network-after-private-read
    whenPresent: personal.messages
    except:
      - server: mac-messages
        tool: tool_send_message
    toEffects: [network, upload, send]
    decision: deny
```

This covers transformed content that fingerprints cannot recognize. Exact flow rules can create a narrower approved exception. Taint clearing is not automatic; version 1 ends it only with session termination or an explicit audited policy-defined transition.

## 9. Chain rules

```yaml
chains:
  - id: enumerate-then-delete
    within: 60s
    sequence:
      - effectsAny: [read]
        countAtLeast: 1
      - effectsAny: [delete]
        countAtLeast: 3
    decision: deny

  - id: denial-probing
    within: 30s
    sequence:
      - decisionCodes: [AG-FLOW-BLOCKED, AG-POLICY-EXPLICIT-DENY]
        countAtLeast: 3
    decision: deny
    obligations:
      - type: offer_session_termination
```

The compiler converts chain rules into bounded automata. Arbitrary graph queries are excluded from the hot path.

## 10. Descriptor rules

```yaml
descriptorIntegrity:
  manifest: review_on_change
  findings:
    AG-DESC-HIDDEN-CONTROL: quarantine
    AG-DESC-CREDENTIAL-SOLICITATION: deny
    AG-DESC-POLICY-OVERRIDE: quarantine
    AG-DESC-CROSS-TOOL-COERCION: require_review
```

Unknown critical-severity finding IDs default to quarantine. Finding policy can increase severity but cannot suppress invariant detectors without a versioned explicit exception and reason.

## 11. Decision algorithm

1. Validate protocol and resolve immutable tool identity.
2. Derive effects, sources, sinks, provenance evidence, and chain facts.
3. Apply non-configurable v1 safety invariants.
4. Collect explicit deny matches.
5. Evaluate information-flow and session-taint rules.
6. Collect allow matches and obligations.
7. If no allow matches, deny.
8. If any deny matches, deny.
9. If obligations exist, return `allow_with_obligations`; forwarding waits for completion.
10. Otherwise allow and return the explanation tree.

Policy order in the YAML file does not change conflict semantics. Specificity is diagnostic, not an implicit privilege rule.

## 12. Policy testing

Cases are data, not scripts:

```yaml
name: blocks message content upload
given:
  sessionLabels: [personal.messages.content]
call:
  server: fake-upload
  tool: upload_text
  arguments:
    body: synthetic secret message
expect:
  decision: deny
  code: AG-FLOW-BLOCKED
  rules: [deny-messages-to-network]
```

`agentgate policy test` freezes clock and randomness, validates each fixture, evaluates the compiled policy, and reports semantic diffs. Tests must cover every allow, deny, declassification, and high-impact obligation rule before release.

## 13. Evolution

- `v1alpha1` is a retired preview input accepted only by `policy migrate`.
- `v1` follows semantic versioning, ignores no unknown fields, and changes security semantics only through a new API version and ADR.
- Migration writes a new reviewed file and never silently activates or overwrites policy.
- The audit log records authoring and compiled-policy digests so replay does not depend on mutable files.
