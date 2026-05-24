//! JIT Compiler for dynamic eBPF filter generation.
//!
//! Generates raw instruction sequences allowing structural searches
//! to run natively in kernel-space without bridging context switching.

mod codegen;
mod emit;
mod verify;

pub use codegen::{
    compile_alternation, compile_char_class, compile_character_class, compile_literal_search,
};
pub use verify::{compile_with_limit, CharRange, CompileError, MAX_BPF_PATTERN_LEN};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::{
        format_program, BpfInsn, BPF_B, BPF_CALL, BPF_EXIT, BPF_JGT, BPF_JMP, BPF_JNE, BPF_K,
        BPF_LDX, BPF_MEM, BPF_X,
    };

    fn assert_jump_offsets_are_valid(program: &[BpfInsn]) {
        for (idx, insn) in program.iter().enumerate() {
            let is_jump = (insn.code & 0x07) == BPF_JMP;
            if is_jump && (insn.code & 0xF0) != BPF_EXIT && (insn.code & 0xF0) != BPF_CALL {
                let target = idx as isize + 1 + insn.off as isize;
                assert!(
                    target >= 0 && (target as usize) < program.len(),
                    "instruction {} has invalid jump target: offset {} -> {}",
                    idx,
                    insn.off,
                    target
                );
            }
        }
    }

    #[test]
    fn empty_pattern_returns_immediate_true() -> Result<(), CompileError> {
        let prog = compile_literal_search(b"")?;
        // 2 ctx loads + MOV R0, 1 + EXIT
        assert_eq!(prog.len(), 4);
        assert_eq!(prog[2].imm, 1); // R0 = 1 (match found)
        Ok(())
    }

    #[test]
    fn single_byte_pattern_generates_valid_program() -> Result<(), CompileError> {
        let prog = compile_literal_search(b"A")?;
        // Should have: 2 loads (ctx->data, ctx->data_end), MOV R4=0,
        // loop body, bounds check, 1 byte compare, match path, next iter, fail path
        assert!(prog.len() >= 8, "program too short: {} insns", prog.len());
        // Last instruction must be EXIT
        assert_eq!(prog[prog.len() - 1].code & 0xF0, BPF_EXIT);
        Ok(())
    }

    #[test]
    fn multi_byte_pattern_unrolls_correctly() -> Result<(), CompileError> {
        let prog = compile_literal_search(b"abc")?;
        // 3-byte pattern should have 3 byte comparisons in the unrolled body.
        // Count LDX_MEM BPF_B instructions (byte loads from R5+offset)
        let byte_loads = prog
            .iter()
            .filter(|i| i.code == (BPF_LDX | BPF_MEM | BPF_B))
            .count();
        assert_eq!(byte_loads, 3, "expected 3 byte loads for 3-byte pattern");
        Ok(())
    }

    #[test]
    fn jump_offsets_are_valid() -> Result<(), CompileError> {
        let prog = compile_literal_search(b"XY")?;
        assert_jump_offsets_are_valid(&prog);
        Ok(())
    }

    #[test]
    fn program_terminates_with_exit() -> Result<(), CompileError> {
        for pattern in [b"a".as_slice(), b"ab", b"hello world", b""] {
            let prog = compile_literal_search(pattern)?;
            let last = &prog[prog.len() - 1];
            assert_eq!(
                last.code & 0xF0,
                BPF_EXIT,
                "pattern {pattern:?}: last insn is not EXIT"
            );
        }
        Ok(())
    }

    #[test]
    fn backpatch_bounds_check_points_to_fail() -> Result<(), CompileError> {
        let prog = compile_literal_search(b"test")?;
        // The bounds check should jump to the fail label (R0=0, EXIT)
        // Find the bounds check: JGT R6, R3, offset
        let bounds_check = prog
            .iter()
            .enumerate()
            .find(|(_, i)| i.code == (BPF_JMP | BPF_JGT | BPF_X));
        assert!(bounds_check.is_some(), "no bounds check found");
        if let Some((idx, insn)) = bounds_check {
            let target = idx + 1 + insn.off as usize;
            // Target should be the fail block: MOV R0, 0
            assert_eq!(prog[target].imm, 0, "bounds check doesn't jump to fail");
        }
        Ok(())
    }

    #[test]
    fn long_pattern_compiles() -> Result<(), CompileError> {
        let pattern = b"this is a longer pattern for testing unroll depth";
        let prog = compile_literal_search(pattern)?;
        let byte_loads = prog
            .iter()
            .filter(|i| i.code == (BPF_LDX | BPF_MEM | BPF_B))
            .count();
        assert_eq!(byte_loads, pattern.len());
        Ok(())
    }

    #[test]
    fn max_length_pattern_compiles() -> Result<(), CompileError> {
        let pattern = vec![b'A'; MAX_BPF_PATTERN_LEN];
        let prog = compile_literal_search(&pattern)?;
        assert!(prog.len() > pattern.len()); // at least 1 insn per byte
        Ok(())
    }

    #[test]
    fn oversized_pattern_returns_error() {
        let pattern = vec![b'A'; MAX_BPF_PATTERN_LEN + 1];
        let message = match compile_literal_search(&pattern) {
            Ok(_) => String::new(),
            Err(error) => error.to_string(),
        };
        assert!(message.contains("exceeds BPF verifier limit"));
    }

    #[test]
    fn character_class_with_ranges_generates_match_and_fail_paths() -> Result<(), CompileError> {
        let prog = compile_character_class(b"a-z0-9")?;
        assert!(prog.len() > 4);
        // Last block is success path, previous block is fail path.
        assert_eq!(prog[prog.len() - 4].imm, 0);
        assert_eq!(prog[prog.len() - 2].imm, 1);
        assert_eq!(prog[prog.len() - 1].code & 0xF0, BPF_EXIT);
        assert_jump_offsets_are_valid(&prog);
        Ok(())
    }

    #[test]
    fn empty_character_class_is_impossible_match() -> Result<(), CompileError> {
        let prog = compile_character_class(b"")?;
        assert_eq!(prog.len(), 2);
        assert_eq!(prog[0].imm, 0);
        assert_eq!(prog[1].code & 0xF0, BPF_EXIT);
        Ok(())
    }

    #[test]
    fn alternation_compiles_sequence_with_match_and_fail_paths() -> Result<(), CompileError> {
        let prog = compile_alternation(&[b"ab", b"xy", b"z"])?;
        assert!(prog.len() > 4);
        assert_eq!(prog[prog.len() - 4].imm, 0);
        assert_eq!(prog[prog.len() - 2].imm, 1);
        assert_jump_offsets_are_valid(&prog);
        Ok(())
    }

    #[test]
    fn alternation_with_empty_alternative_matches_immediately() -> Result<(), CompileError> {
        let prog = compile_alternation(&[b"ab", b"", b"cd"])?;
        assert_eq!(prog.len(), 2);
        assert_eq!(prog[0].imm, 1);
        assert_eq!(prog[1].code & 0xF0, BPF_EXIT);
        Ok(())
    }

    #[test]
    fn all_nul_pattern_compiles_and_compares_zero_bytes() -> Result<(), CompileError> {
        let pattern = [0_u8, 0, 0, 0];
        let prog = compile_literal_search(&pattern)?;
        let zero_comparisons = prog
            .iter()
            .filter(|insn| insn.code == (BPF_JMP | BPF_JNE | BPF_K) && insn.imm == 0)
            .count();
        assert_eq!(zero_comparisons, pattern.len());
        assert_jump_offsets_are_valid(&prog);
        Ok(())
    }

    #[test]
    fn pattern_with_1025_bytes_is_rejected() {
        let pattern = vec![0_u8; MAX_BPF_PATTERN_LEN + 1];
        assert!(matches!(
            compile_literal_search(&pattern),
            Err(CompileError::PatternTooLong { len: 1025, max }) if max == MAX_BPF_PATTERN_LEN
        ));
    }

    #[test]
    fn character_class_rejects_reversed_ranges() {
        assert!(matches!(
            compile_character_class(b"z-a"),
            Err(CompileError::InvalidPattern {
                reason: "character class range endpoints are reversed"
            })
        ));
    }

    #[test]
    fn pretty_printer_formats_compiled_program() -> Result<(), CompileError> {
        let prog = compile_literal_search(b"AZ")?;
        let rendered = format_program(&prog);
        assert!(rendered.contains("0000: r2 = *(u32 *)(r1 + 0)"));
        assert!(rendered.contains("if r7 != 65 goto"));
        assert!(rendered.contains("exit"));
        Ok(())
    }
}
