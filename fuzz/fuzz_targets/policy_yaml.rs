#![no_main]

use agentgate_policy::CompiledPolicy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data) {
        let _ = CompiledPolicy::from_yaml(source);
    }
});
