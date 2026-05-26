#![no_main]

use ebpfkit::compiler::compile_literal_search;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = compile_literal_search(data);
});
