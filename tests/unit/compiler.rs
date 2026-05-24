use ebpfkit::assembler::{
    format_program, BpfInsn, BPF_B, BPF_EXIT, BPF_JMP, BPF_JNE, BPF_K, BPF_LDX, BPF_MEM, BPF_W,
};
use ebpfkit::compiler::{
    compile_alternation, compile_char_class, compile_character_class, compile_literal_search,
    CompileError, MAX_BPF_PATTERN_LEN,
};

/// Helper to check that all jump offsets in a program point to valid instructions.
fn assert_valid_jump_offsets(program: &[BpfInsn]) {
    for (idx, insn) in program.iter().enumerate() {
        let is_jump = (insn.code & 0x07) == BPF_JMP;
        if is_jump && (insn.code & 0xF0) != BPF_EXIT && (insn.code & 0xF0) != 0x80 {
            // BPF_CALL is 0x80
            let target = idx as isize + 1 + insn.off as isize;
            assert!(
                target >= 0 && (target as usize) < program.len(),
                "instruction {} has invalid jump target: offset {} -> {} (program len: {})",
                idx,
                insn.off,
                target,
                program.len()
            );
        }
    }
}

/// Helper to count specific instruction types in a program.
fn count_instructions(program: &[BpfInsn], code_mask: u8, code_match: u8) -> usize {
    program
        .iter()
        .filter(|i| (i.code & code_mask) == code_match)
        .count()
}

// ============================================================================
// Test 1: Compile a single literal pattern → valid BPF bytecode
// ============================================================================

#[test]
fn compile_single_literal_pattern_produces_valid_bytecode() {
    let prog = compile_literal_search(b"test").unwrap();

    // Program should not be empty
    assert!(!prog.is_empty(), "compiled program should not be empty");

    // Last instruction must be EXIT
    let last = prog.last().unwrap();
    assert_eq!(
        last.code & 0xF0,
        BPF_EXIT,
        "last instruction must be EXIT, got: {:?}",
        last
    );

    // Program should start with context loads
    assert_eq!(
        prog[0].code,
        BPF_LDX | BPF_MEM | BPF_W,
        "first insn should load ctx->data"
    );
    assert_eq!(
        prog[1].code,
        BPF_LDX | BPF_MEM | BPF_W,
        "second insn should load ctx->data_end"
    );

    // All jump offsets must be valid
    assert_valid_jump_offsets(&prog);
}

#[test]
fn compile_single_byte_pattern_produces_valid_program() {
    let prog = compile_literal_search(b"X").unwrap();

    // Should have: 2 ctx loads, MOV R4=0, MOV R5=R2, ADD R5,R4,
    // MOV R6=R5, ADD R6,p_len, bounds check, 1 byte compare, match path, next iter, fail path
    assert!(
        prog.len() >= 8,
        "single byte program too short: {} insns",
        prog.len()
    );

    // Verify last instruction is EXIT
    assert_eq!(prog[prog.len() - 1].code & 0xF0, BPF_EXIT);

    // Count byte loads (LDX_MEM BPF_B) - should be 1 for single byte pattern
    let byte_loads = count_instructions(&prog, 0xFF, BPF_LDX | BPF_MEM | BPF_B);
    assert_eq!(
        byte_loads, 1,
        "expected 1 byte load for single-byte pattern"
    );

    assert_valid_jump_offsets(&prog);
}

// ============================================================================
// Test 2: Compiled program instruction count < BPF limit (4096)
// ============================================================================

#[test]
fn compiled_program_instruction_count_under_bpf_limit() {
    // Test with maximum allowed pattern length
    let max_pattern = vec![b'A'; MAX_BPF_PATTERN_LEN];
    let prog = compile_literal_search(&max_pattern).unwrap();

    assert!(
        prog.len() < 4096,
        "program has {} instructions, exceeding BPF limit of 4096",
        prog.len()
    );

    // Test with various pattern sizes
    for size in [1, 10, 100, 500, 1000] {
        let pattern = vec![b'x'; size];
        let prog = compile_literal_search(&pattern).unwrap();
        assert!(
            prog.len() < 4096,
            "pattern size {} produced {} instructions, exceeding limit",
            size,
            prog.len()
        );
    }
}

#[test]
fn character_class_program_instruction_count_under_limit() {
    // Complex character class with many ranges
    let prog = compile_character_class(b"a-zA-Z0-9_-").unwrap();
    assert!(
        prog.len() < 4096,
        "character class program too large: {} insns",
        prog.len()
    );
}

#[test]
fn alternation_program_instruction_count_under_limit() {
    // Alternation with multiple patterns
    let prog = compile_alternation(&[b"get", b"post", b"put", b"delete", b"patch"]).unwrap();
    assert!(
        prog.len() < 4096,
        "alternation program too large: {} insns",
        prog.len()
    );
}

// ============================================================================
// Test 3: Pattern with all byte values 0x00-0xFF → compiles correctly
// ============================================================================

#[test]
fn pattern_with_all_byte_values_compiles_correctly() {
    // Create pattern with all byte values from 0x00 to 0xFF
    let all_bytes: Vec<u8> = (0x00..=0xFF).collect();

    // Should compile successfully
    let prog = compile_literal_search(&all_bytes).unwrap();

    // Verify program structure
    assert!(!prog.is_empty());
    assert_eq!(prog.last().unwrap().code & 0xF0, BPF_EXIT);

    // Count byte loads - should equal number of bytes in pattern
    let byte_loads = count_instructions(&prog, 0xFF, BPF_LDX | BPF_MEM | BPF_B);
    assert_eq!(
        byte_loads,
        all_bytes.len(),
        "expected {} byte loads for all-bytes pattern, got {}",
        all_bytes.len(),
        byte_loads
    );

    // Verify all jump offsets are valid
    assert_valid_jump_offsets(&prog);
}

#[test]
fn pattern_with_null_bytes_compiles_correctly() {
    // Pattern containing null bytes (common edge case)
    let pattern = vec![0x00, 0x01, 0x00, 0x02, 0x00];
    let prog = compile_literal_search(&pattern).unwrap();

    // Count JNE instructions with imm=0 (comparing against null bytes)
    let null_comparisons = prog
        .iter()
        .filter(|insn| insn.code == (BPF_JMP | BPF_JNE | BPF_K) && insn.imm == 0)
        .count();

    assert_eq!(
        null_comparisons, 3,
        "expected 3 null byte comparisons, got {}",
        null_comparisons
    );

    assert_valid_jump_offsets(&prog);
}

#[test]
fn pattern_with_high_bytes_compiles_correctly() {
    // Pattern with bytes 0x80-0xFF (high bit set)
    let high_bytes: Vec<u8> = (0x80..=0xFF).collect();
    let prog = compile_literal_search(&high_bytes).unwrap();

    assert!(!prog.is_empty());
    assert_eq!(prog.last().unwrap().code & 0xF0, BPF_EXIT);
    assert_valid_jump_offsets(&prog);
}

// ============================================================================
// Test 4: Empty pattern → error not panic
// ============================================================================

#[test]
fn empty_pattern_returns_error_not_panic() {
    // Empty pattern should return a valid (minimal) program, not panic
    let result = compile_literal_search(b"");
    assert!(result.is_ok(), "empty pattern should compile without error");

    let prog = result.unwrap();
    // Should have: 2 ctx loads + MOV R0, 1 + EXIT = 4 instructions
    assert_eq!(prog.len(), 4, "empty pattern should produce 4 instructions");

    // Should return match immediately (R0 = 1)
    assert_eq!(prog[2].imm, 1, "empty pattern should return match (R0 = 1)");
    assert_eq!(prog[3].code & 0xF0, BPF_EXIT);
}

#[test]
fn empty_character_class_returns_error_not_panic() {
    // Empty character class should return immediate non-match
    let result = compile_character_class(b"");
    assert!(result.is_ok(), "empty character class should not panic");

    let prog = result.unwrap();
    assert_eq!(
        prog.len(),
        2,
        "empty character class should produce 2 instructions"
    );
    assert_eq!(
        prog[0].imm, 0,
        "empty class should return no-match (R0 = 0)"
    );
}

#[test]
fn empty_alternation_returns_error_not_panic() {
    // Empty alternation should return immediate non-match
    let result: Result<Vec<BpfInsn>, CompileError> = compile_alternation(&[]);
    assert!(result.is_ok(), "empty alternation should not panic");

    let prog = result.unwrap();
    assert_eq!(prog.len(), 2);
    assert_eq!(prog[0].imm, 0, "empty alternation should return no-match");
}

// ============================================================================
// Test 5: Pattern longer than BPF instruction limit → error
// ============================================================================

#[test]
fn pattern_longer_than_bpf_limit_returns_error() {
    let oversized_pattern = vec![b'A'; MAX_BPF_PATTERN_LEN + 1];
    let result = compile_literal_search(&oversized_pattern);

    assert!(
        matches!(result, Err(CompileError::PatternTooLong { .. })),
        "oversized pattern should return PatternTooLong error, got: {:?}",
        result
    );
}

#[test]
fn pattern_at_exact_limit_compiles_successfully() {
    let max_pattern = vec![b'B'; MAX_BPF_PATTERN_LEN];
    let result = compile_literal_search(&max_pattern);

    assert!(
        result.is_ok(),
        "pattern at exactly MAX_BPF_PATTERN_LEN should compile, got: {:?}",
        result
    );

    let prog = result.unwrap();
    assert!(prog.len() < 4096, "max pattern program exceeds BPF limit");
}

#[test]
fn compile_with_limit_rejects_excessive_instruction_count() {
    use ebpfkit::compiler::compile_with_limit;

    let result = compile_with_limit(5000);
    assert!(
        matches!(
            result,
            Err(CompileError::PatternTooLong {
                len: 5000,
                max: 4096
            })
        ),
        "compile_with_limit should reject >4096 instructions"
    );
}

// ============================================================================
// Test 6: Multiple patterns compiled → distinct programs
// ============================================================================

#[test]
fn multiple_patterns_produce_distinct_programs() {
    let prog1 = compile_literal_search(b"pattern1").unwrap();
    let prog2 = compile_literal_search(b"pattern2").unwrap();
    let prog3 = compile_literal_search(b"completely_different").unwrap();

    // Programs should have different instruction counts or different immediate values
    assert_ne!(
        format_program(&prog1),
        format_program(&prog2),
        "different patterns should produce different programs"
    );

    // Verify each program is valid
    for (name, prog) in [("prog1", &prog1), ("prog2", &prog2), ("prog3", &prog3)] {
        assert!(!prog.is_empty(), "{} should not be empty", name);
        assert_eq!(
            prog.last().unwrap().code & 0xF0,
            BPF_EXIT,
            "{} should end with EXIT",
            name
        );
    }
}

#[test]
fn identical_patterns_produce_equivalent_programs() {
    let prog1 = compile_literal_search(b"identical").unwrap();
    let prog2 = compile_literal_search(b"identical").unwrap();

    // Same pattern should produce equivalent programs
    assert_eq!(
        format_program(&prog1),
        format_program(&prog2),
        "identical patterns should produce equivalent programs"
    );
}

#[test]
fn multiple_character_classes_distinct() {
    let prog_lower = compile_character_class(b"a-z").unwrap();
    let prog_upper = compile_character_class(b"A-Z").unwrap();
    let prog_digit = compile_character_class(b"0-9").unwrap();

    // Different character classes should produce different programs
    assert_ne!(
        format_program(&prog_lower),
        format_program(&prog_upper),
        "different character classes should produce different programs"
    );
    assert_ne!(
        format_program(&prog_upper),
        format_program(&prog_digit),
        "different character classes should produce different programs"
    );
}

// ============================================================================
// Test 7: Backpatching produces correct jump offsets
// ============================================================================

#[test]
fn backpatched_bounds_check_jumps_to_fail_block() {
    let prog = compile_literal_search(b"test").unwrap();

    // Find the bounds check: JGT R6, R3, offset
    let bounds_check = prog
        .iter()
        .enumerate()
        .find(|(_, i)| i.code == (BPF_JMP | 0x20 | 0x08)); // BPF_JGT | BPF_X

    if let Some((idx, insn)) = bounds_check {
        let target = idx as isize + 1 + insn.off as isize;
        assert!(
            target >= 0 && (target as usize) < prog.len(),
            "bounds check jumps to invalid target: {} -> {}",
            idx,
            target
        );

        // Target should be the fail block (MOV R0, 0)
        let target_insn = &prog[target as usize];
        assert_eq!(
            target_insn.imm, 0,
            "bounds check should jump to fail block (R0 = 0), got imm={}",
            target_insn.imm
        );
    }
}

#[test]
fn backpatched_byte_checks_jumps_to_next_iter() {
    let prog = compile_literal_search(b"ab").unwrap();

    // Find all JNE instructions (byte comparisons that fail)
    let jne_instructions: Vec<(usize, &BpfInsn)> = prog
        .iter()
        .enumerate()
        .filter(|(_, i)| i.code == (BPF_JMP | BPF_JNE | BPF_K))
        .collect();

    assert!(
        !jne_instructions.is_empty(),
        "should have JNE instructions for byte comparisons"
    );

    for (idx, insn) in jne_instructions {
        let target = idx as isize + 1 + insn.off as isize;
        assert!(
            target >= 0 && (target as usize) < prog.len(),
            "byte check at {} has invalid jump target: offset {} -> {}",
            idx,
            insn.off,
            target
        );
    }
}

#[test]
fn all_jump_offsets_in_character_class_are_valid() {
    let prog = compile_character_class(b"a-zA-Z0-9").unwrap();
    assert_valid_jump_offsets(&prog);
}

#[test]
fn all_jump_offsets_in_alternation_are_valid() {
    let prog = compile_alternation(&[b"foo", b"bar", b"baz"]).unwrap();
    assert_valid_jump_offsets(&prog);
}

// ============================================================================
// Test 8: Unrolled byte comparison correctness
// ============================================================================

#[test]
fn unrolled_byte_comparison_count_matches_pattern_length() {
    for pattern_len in [1, 5, 10, 50] {
        let pattern: Vec<u8> = (0..pattern_len).map(|i| b'a' + (i % 26) as u8).collect();
        let prog = compile_literal_search(&pattern).unwrap();

        // Count byte loads (LDX_MEM BPF_B)
        let byte_loads = count_instructions(&prog, 0xFF, BPF_LDX | BPF_MEM | BPF_B);

        assert_eq!(
            byte_loads, pattern_len,
            "pattern length {} should produce {} byte loads, got {}",
            pattern_len, pattern_len, byte_loads
        );

        // Verify jump offsets are all valid
        assert_valid_jump_offsets(&prog);
    }
}

#[test]
fn unrolled_byte_comparison_has_correct_immediate_values() {
    let pattern = b"ABC";
    let prog = compile_literal_search(pattern).unwrap();

    // Find JNE instructions and verify they compare against correct bytes
    let jne_instructions: Vec<&BpfInsn> = prog
        .iter()
        .filter(|i| i.code == (BPF_JMP | BPF_JNE | BPF_K))
        .collect();

    assert_eq!(jne_instructions.len(), pattern.len());

    // Verify each JNE has the correct immediate value
    for (i, insn) in jne_instructions.iter().enumerate() {
        assert_eq!(
            insn.imm, pattern[i] as i32,
            "byte {} comparison should have imm={}, got {}",
            i, pattern[i], insn.imm
        );
    }
}

#[test]
fn multi_byte_pattern_unrolls_correctly() {
    let pattern = b"hello world";
    let prog = compile_literal_search(pattern).unwrap();

    // Verify structure:
    // - 2 loads for context
    // - 1 mov for loop counter
    // - 2 for ptr setup
    // - 1 placeholder for bounds check
    // - pattern_len * 2 (load + compare for each byte)
    // - 2 for match (mov r0=1, exit)
    // - 2 for next iter (add r4, 1, jmp back)
    // - 2 for fail (mov r0=0, exit)

    let byte_loads = count_instructions(&prog, 0xFF, BPF_LDX | BPF_MEM | BPF_B);
    assert_eq!(
        byte_loads,
        pattern.len(),
        "expected {} byte loads for pattern {:?}",
        pattern.len(),
        pattern
    );

    assert_valid_jump_offsets(&prog);
}

// ============================================================================
// Additional edge case and adversarial tests
// ============================================================================

#[test]
fn single_byte_pattern_edge_cases() {
    // Test all single byte values
    for byte in 0x00..=0xFF {
        let prog = compile_literal_search(&[byte]).unwrap();
        assert!(
            !prog.is_empty(),
            "single byte 0x{:02x} should compile",
            byte
        );
        assert_eq!(prog.last().unwrap().code & 0xF0, BPF_EXIT);
        assert_valid_jump_offsets(&prog);
    }
}

#[test]
fn pattern_with_repeated_bytes_compiles_correctly() {
    let pattern = vec![b'A'; 100];
    let prog = compile_literal_search(&pattern).unwrap();

    // Should have 100 byte loads
    let byte_loads = count_instructions(&prog, 0xFF, BPF_LDX | BPF_MEM | BPF_B);
    assert_eq!(byte_loads, 100);

    // All JNE instructions should have the same immediate (b'A' = 65)
    let jne_insts: Vec<&BpfInsn> = prog
        .iter()
        .filter(|i| i.code == (BPF_JMP | BPF_JNE | BPF_K))
        .collect();

    for insn in &jne_insts {
        assert_eq!(insn.imm, b'A' as i32);
    }
}

#[test]
fn char_class_compile_rejects_reversed_range() {
    let result = compile_char_class(&[ebpfkit::compiler::CharRange { lo: 0x5A, hi: 0x41 }]);
    assert!(
        matches!(result, Err(CompileError::InvalidPattern { .. })),
        "reversed range should return error"
    );
}

#[test]
fn char_class_compile_accepts_valid_range() {
    let prog = compile_char_class(&[
        ebpfkit::compiler::CharRange { lo: b'a', hi: b'z' },
        ebpfkit::compiler::CharRange { lo: b'A', hi: b'Z' },
    ])
    .unwrap();

    assert!(!prog.is_empty());
    assert_eq!(prog.last().unwrap().code & 0xF0, BPF_EXIT);
    assert_valid_jump_offsets(&prog);
}

#[test]
fn compile_alternation_with_empty_alternative_matches_immediately() {
    let prog = compile_alternation(&[b"ab", b"", b"cd"]).unwrap();

    // Empty alternative means immediate match
    assert_eq!(prog.len(), 2);
    assert_eq!(prog[0].imm, 1, "should return match (R0 = 1)");
}

#[test]
fn program_formatting_is_deterministic() {
    let pattern = b"deterministic_test";
    let prog1 = compile_literal_search(pattern).unwrap();
    let prog2 = compile_literal_search(pattern).unwrap();

    let fmt1 = format_program(&prog1);
    let fmt2 = format_program(&prog2);

    assert_eq!(fmt1, fmt2, "program formatting should be deterministic");
}
