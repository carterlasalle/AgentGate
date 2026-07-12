# Contributing

AgentGate uses security-first, test-first changes.

1. Link the change to requirement, threat, and test identifiers when applicable.
2. Add a failing test or corpus case before changing an enforcement path.
3. Assert both the returned decision and whether the downstream server observed the call.
4. Update policy examples, traceability, and security limitations with behavior changes.
5. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `python3 scripts/check_docs.py`.

Changes to canonicalization, policy precedence, approvals, provenance/declassification, manifest trust, audit cryptography, or new external I/O require explicit security review.
