//! Deterministic test support for security invariant assertions.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

/// Thread-safe recorder used to prove whether a downstream call occurred.
#[derive(Clone, Debug, Default)]
pub struct CallRecorder(Arc<Mutex<Vec<String>>>);

impl CallRecorder {
    /// Records a downstream tool name.
    pub fn record(&self, tool: impl Into<String>) {
        if let Ok(mut calls) = self.0.lock() {
            calls.push(tool.into());
        }
    }

    /// Returns a snapshot of all observed calls.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.0
            .lock()
            .map_or_else(|_| Vec::new(), |calls| calls.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::CallRecorder;

    #[test]
    fn recorder_starts_empty_and_tracks_calls() {
        let recorder = CallRecorder::default();
        assert!(recorder.calls().is_empty());
        recorder.record("read");
        assert_eq!(recorder.calls(), vec!["read"]);
    }
}
