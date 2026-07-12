#![no_main]

use agentgate_integrity::{manifest_digest, scan_tool_descriptor};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice(data) {
        let _ = manifest_digest(&value);
        let _ = scan_tool_descriptor(&value);
    }
});
