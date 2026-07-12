//! Standalone canonical-action latency smoke benchmark.

use std::collections::BTreeSet;
use std::hint::black_box;
use std::time::{Duration, Instant};

use agentgate_core::{CanonicalAction, Digest, Effect, ServerId, SessionId, ToolIdentity};
use serde_json::json;

fn main() {
    let iterations = 100_000_u32;
    let arguments = json!({
        "recipient": "+15555550100",
        "message": "Synthetic benchmark message with enough content to represent a normal action",
        "metadata": {"priority": "normal", "tags": ["benchmark", "local"]}
    });
    let tool = ToolIdentity {
        server_id: ServerId::new("benchmark").unwrap_or_else(|error| unreachable!("{error}")),
        name: "send_message".to_owned(),
        manifest_digest: Digest::domain(b"benchmark", b"manifest"),
        protocol_version: "2025-11-25".to_owned(),
    };
    let started = Instant::now();
    for _ in 0..iterations {
        let action = CanonicalAction::new(
            SessionId::default(),
            tool.clone(),
            black_box(&arguments),
            BTreeSet::from([Effect::Send]),
            Digest::domain(b"benchmark", b"policy"),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        black_box(
            action
                .digest()
                .unwrap_or_else(|error| unreachable!("{error}")),
        );
    }
    let elapsed = started.elapsed();
    let per_action = elapsed / iterations;
    println!(
        "canonical_action iterations={iterations} elapsed={elapsed:?} per_action={per_action:?}"
    );
    assert!(per_action < Duration::from_millis(5));
}
