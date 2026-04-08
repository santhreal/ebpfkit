#![no_main]
use libfuzzer_sys::fuzz_target;
use ebpfkit::compiler::{compile_literal_search, MAX_BPF_PATTERN_LEN};

fuzz_target!(|data: &[u8]| {
    // Only test patterns within the BPF verifier limit
    if data.len() > MAX_BPF_PATTERN_LEN || data.is_empty() {
        return;
    }

    let prog = match compile_literal_search(data) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Verify structural invariants
    assert!(!prog.is_empty(), "program must not be empty");

    // Last instruction must be EXIT
    let last = prog.last().unwrap();
    assert_eq!(last.code & 0xF0, 0x90, "last instruction must be EXIT");

    // All jump offsets must be in bounds
    for (idx, insn) in prog.iter().enumerate() {
        let is_jump = (insn.code & 0x07) == 0x05; // BPF_JMP
        let is_exit = (insn.code & 0xF0) == 0x90;
        let is_call = (insn.code & 0xF0) == 0x80;
        if is_jump && !is_exit && !is_call {
            let target = idx as isize + 1 + insn.off as isize;
            assert!(
                target >= 0 && (target as usize) < prog.len(),
                "jump at {} targets {} (off={}), out of bounds for program len {}",
                idx, target, insn.off, prog.len()
            );
        }
    }
});
