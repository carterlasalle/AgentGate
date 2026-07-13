//! Stable-v1 command-line contract tests.

use std::fs;
use std::process::Command;

use agentgate_audit::AuditWriter;
use agentgate_policy::CompiledPolicy;
use tempfile::tempdir;

const LEGACY_POLICY: &str = r#"
apiVersion: agentgate.dev/v1alpha1
kind: GatewayPolicy
metadata: { name: migration-fixture, version: 1 }
defaults: { decision: deny, audit: metadata }
servers:
  - id: fake
    command: { executable: fake, args: [], inheritEnvironment: [] }
    rules:
      - { id: ping, tools: [ping], decision: allow }
"#;

fn agentgate() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentgate"))
}

#[test]
fn migrates_and_diffs_stable_policy_without_overwrite() {
    let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
    let legacy = directory.path().join("legacy.yaml");
    let stable = directory.path().join("stable.yaml");
    fs::write(&legacy, LEGACY_POLICY).unwrap_or_else(|error| unreachable!("{error}"));
    let status = agentgate()
        .args([
            "policy",
            "migrate",
            "--policy",
            legacy.to_str().unwrap_or(""),
            "--output",
            stable.to_str().unwrap_or(""),
        ])
        .status()
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(status.success());
    assert!(CompiledPolicy::from_path(&stable).is_ok());

    let second = agentgate()
        .args([
            "policy",
            "migrate",
            "--policy",
            legacy.to_str().unwrap_or(""),
            "--output",
            stable.to_str().unwrap_or(""),
        ])
        .status()
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(
        !second.success(),
        "migration must never overwrite reviewed policy"
    );

    let diff = agentgate()
        .args([
            "policy",
            "diff",
            "--current",
            stable.to_str().unwrap_or(""),
            "--candidate",
            stable.to_str().unwrap_or(""),
        ])
        .output()
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(diff.status.success());
    let report: serde_json::Value =
        serde_json::from_slice(&diff.stdout).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(report["changed"], false);
}

#[test]
fn exports_public_verifier_and_round_trips_detached_anchor() {
    let directory = tempdir().unwrap_or_else(|error| unreachable!("{error}"));
    let log = directory.path().join("audit.jsonl");
    let secret = directory.path().join("audit.key");
    AuditWriter::create(&log, &secret, 1)
        .unwrap_or_else(|error| unreachable!("{error}"))
        .finish(None)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let public = directory.path().join("audit.pub");
    let anchor = directory.path().join("audit.anchor.json");

    for arguments in [
        vec![
            "audit",
            "export-key",
            "--signing-key",
            secret.to_str().unwrap_or(""),
            "--output",
            public.to_str().unwrap_or(""),
        ],
        vec![
            "audit",
            "anchor",
            log.to_str().unwrap_or(""),
            "--signing-key",
            secret.to_str().unwrap_or(""),
            "--output",
            anchor.to_str().unwrap_or(""),
        ],
        vec![
            "audit",
            "verify-anchor",
            log.to_str().unwrap_or(""),
            "--anchor",
            anchor.to_str().unwrap_or(""),
            "--public-key",
            public.to_str().unwrap_or(""),
        ],
    ] {
        let status = agentgate()
            .args(arguments)
            .status()
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(status.success());
    }
}
