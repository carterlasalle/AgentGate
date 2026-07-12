#![no_main]

use agentgate_protocol::{Limits, Message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_frame_bytes: 64 * 1024,
        max_depth: 32,
        max_string_bytes: 16 * 1024,
        max_collection_items: 2_048,
    };
    let _ = Message::parse(data, limits);
});
