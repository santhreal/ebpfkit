use crate::assembler::*;
use crate::{alu64_imm, alu64_reg, exit, jmp_imm, jmp_reg, ldx_mem};

use super::{
    compile_with_limit,
    emit::{patch_imm_jump, patch_match_jump, patch_reg_jump},
    verify::{
        estimate_alternation_instructions, estimate_character_class_instructions,
        literal_search_instruction_count, parse_character_class, CharRange, CompileError,
        PatternRange,
    },
};

/// Compile a literal search pattern into BPF instructions.
///
/// # Errors
///
/// Returns [`CompileError::PatternTooLong`] if the pattern exceeds [`MAX_BPF_PATTERN_LEN`].
pub fn compile_literal_search(pattern: &[u8]) -> Result<Vec<BpfInsn>, CompileError> {
    compile_with_limit(literal_search_instruction_count(pattern.len()))?;
    if pattern.len() > super::MAX_BPF_PATTERN_LEN {
        return Err(CompileError::PatternTooLong {
            len: pattern.len(),
            max: super::MAX_BPF_PATTERN_LEN,
        });
    }
    let mut prog = Vec::new();

    // Inputs:
    // R1 = ctx (context struct pointing to data)
    // Here we assume standard XDP / Socket filter context where:
    // data = (void*)(long)ctx->data;
    // data_end = (void*)(long)ctx->data_end;

    // R2 = data
    prog.push(ldx_mem!(BPF_W, R2, R1, 0)); // ctx->data offset
                                           // R3 = data_end
    prog.push(ldx_mem!(BPF_W, R3, R1, 4)); // ctx->data_end offset

    if pattern.is_empty() {
        prog.push(alu64_imm!(BPF_MOV, R0, 1));
        prog.push(exit!());
        return Ok(prog);
    }

    let p_len = pattern.len() as i32;

    // R4 = current match index (loop iterator)
    prog.push(alu64_imm!(BPF_MOV, R4, 0));

    // --- LOOP START ---
    let loop_start_idx = prog.len();

    // R5 = R2 + R4 (current ptr)
    prog.push(alu64_reg!(BPF_MOV, R5, R2));
    prog.push(alu64_reg!(BPF_ADD, R5, R4));

    // Bounds check: if (R5 + p_len > R3) goto LOOP_FAIL
    // R6 = R5 + p_len
    prog.push(alu64_reg!(BPF_MOV, R6, R5));
    prog.push(alu64_imm!(BPF_ADD, R6, p_len));

    // We cannot jump forward directly yet since we don't know the exact length of the unrolled loop,
    // so we use a placeholder and fix it later.
    let bounds_check_idx = prog.len();
    prog.push(exit!()); // Backpatched to: jmp_reg!(BPF_JGT, R6, R3, offset) at line 102

    // Unrolled byte comparison iteration
    let mut jump_to_next_targets = Vec::new();

    for (i, &byte) in pattern.iter().enumerate() {
        // Load byte at R5 + i into R7
        prog.push(ldx_mem!(BPF_B, R7, R5, i as i16));

        // if R7 != byte goto NEXT_ITER
        let jump_idx = prog.len();
        prog.push(exit!()); // Backpatched to: jmp_imm!(BPF_JNE, R7, byte, offset) at line 108
        jump_to_next_targets.push(jump_idx);
    }

    // If we passed all unrolled checks, we found the pattern!
    // return 1;
    prog.push(alu64_imm!(BPF_MOV, R0, 1)); // Found!
    prog.push(exit!());

    // --- NEXT ITER ---
    let next_iter_idx = prog.len();

    // R4 += 1
    prog.push(alu64_imm!(BPF_ADD, R4, 1));

    // Loop back to start (negative jump)
    let jump_back_offset = (loop_start_idx as isize - prog.len() as isize - 1) as i16;
    prog.push(jmp_imm!(BPF_JA, R0, 0, jump_back_offset));

    // --- LOOP FAIL ---
    let loop_fail_idx = prog.len();
    prog.push(alu64_imm!(BPF_MOV, R0, 0)); // Not found!
    prog.push(exit!());

    // Backpatch phase
    // 1. Bounds check (if R6 > R3 goto LOOP_FAIL)
    let bounds_offset = (loop_fail_idx - bounds_check_idx - 1) as i16;
    prog[bounds_check_idx] = jmp_reg!(BPF_JGT, R6, R3, bounds_offset);

    // 2. Unrolled byte checks (if R7 != byte goto NEXT_ITER)
    for (i, &jump_idx) in jump_to_next_targets.iter().enumerate() {
        let pattern_byte = pattern[i] as i32;
        let iter_offset = (next_iter_idx - jump_idx - 1) as i16;
        prog[jump_idx] = jmp_imm!(BPF_JNE, R7, pattern_byte, iter_offset);
    }

    Ok(prog)
}

/// Compile a character class (e.g., `a-z0-9`) into BPF byte-comparison logic.
///
/// The input `class` should contain only the inside of the square brackets,
/// e.g. `b"a-z0-9"` for `[a-z0-9]`.
/// The register `R7` must already hold the byte to evaluate.
///
/// On match the program sets `R0 = 1` and exits.
/// On mismatch the program sets `R0 = 0` and exits.
pub fn compile_character_class(class: &[u8]) -> Result<Vec<BpfInsn>, CompileError> {
    let ranges = parse_character_class(class)?;
    if ranges.is_empty() {
        return Ok(vec![alu64_imm!(BPF_MOV, R0, 0), exit!()]);
    }

    compile_with_limit(estimate_character_class_instructions(&ranges))?;

    let mut prog = Vec::with_capacity(estimate_character_class_instructions(&ranges));
    let mut mismatch_jump_indices: Vec<Vec<usize>> = Vec::with_capacity(ranges.len());
    let mut range_match_jump_indices: Vec<usize> = Vec::with_capacity(ranges.len());
    let mut range_start_indices = Vec::with_capacity(ranges.len());

    for range in ranges {
        range_start_indices.push(prog.len());
        mismatch_jump_indices.push(Vec::new());
        let current_range = mismatch_jump_indices.len() - 1;

        match range {
            PatternRange::Single(value) => {
                let jump_idx = prog.len();
                prog.push(jmp_imm!(BPF_JEQ, R7, value as i32, 0));
                mismatch_jump_indices[current_range].push(jump_idx);

                let match_jump_idx = prog.len();
                prog.push(jmp_imm!(BPF_JA, R0, 0, 0));
                range_match_jump_indices.push(match_jump_idx);
            }
            PatternRange::Span(start, end) => {
                let low_jump_idx = prog.len();
                prog.push(jmp_imm!(BPF_JLT, R7, start as i32, 0));
                mismatch_jump_indices[current_range].push(low_jump_idx);

                let high_jump_idx = prog.len();
                prog.push(jmp_imm!(BPF_JGT, R7, end as i32, 0));
                mismatch_jump_indices[current_range].push(high_jump_idx);

                let match_jump_idx = prog.len();
                prog.push(jmp_imm!(BPF_JA, R0, 0, 0));
                range_match_jump_indices.push(match_jump_idx);
            }
        }
    }

    let fail_idx = prog.len();
    prog.push(alu64_imm!(BPF_MOV, R0, 0));
    prog.push(exit!());

    let match_idx = prog.len();
    prog.push(alu64_imm!(BPF_MOV, R0, 1));
    prog.push(exit!());

    for (i, range_mismatches) in mismatch_jump_indices.iter().enumerate() {
        let next_target = range_start_indices.get(i + 1).copied().unwrap_or(fail_idx);
        for &jump_idx in range_mismatches {
            let expected = prog[jump_idx].imm;
            let op = if prog[jump_idx].code == (BPF_JMP | BPF_JEQ | BPF_K) {
                BPF_JNE
            } else {
                prog[jump_idx].code & 0xF0
            };

            patch_imm_jump(&mut prog, jump_idx, next_target, R7, expected, op);
        }
    }

    for jump_idx in range_match_jump_indices {
        patch_match_jump(&mut prog, jump_idx, match_idx);
    }

    Ok(prog)
}

/// Compile a single-byte alternation matcher by evaluating alternatives in sequence.
///
/// The generated program matches one of the provided alternatives anchored at the
/// current scan position.
///
/// Register usage:
/// - `R5` must point to the current scan start.
/// - `R3` must contain the end pointer for bounds checks.
pub fn compile_alternation(alternatives: &[&[u8]]) -> Result<Vec<BpfInsn>, CompileError> {
    if alternatives.is_empty() {
        return Ok(vec![alu64_imm!(BPF_MOV, R0, 0), exit!()]);
    }

    if alternatives.iter().any(|alt| alt.is_empty()) {
        return Ok(vec![alu64_imm!(BPF_MOV, R0, 1), exit!()]);
    }

    compile_with_limit(estimate_alternation_instructions(alternatives))?;

    let mut prog = Vec::with_capacity(estimate_alternation_instructions(alternatives));
    let mut mismatch_jump_indices = Vec::with_capacity(alternatives.len());
    let mut bound_jump_indices = Vec::with_capacity(alternatives.len());
    let mut match_jump_indices = Vec::with_capacity(alternatives.len());
    let mut alternative_start_indices = Vec::with_capacity(alternatives.len());

    for alt in alternatives {
        alternative_start_indices.push(prog.len());

        let mut alt_mismatches = Vec::with_capacity(alt.len() + 1);

        let bound_check_idx = prog.len();
        prog.push(alu64_reg!(BPF_MOV, R6, R5));
        prog.push(alu64_imm!(BPF_ADD, R6, alt.len() as i32));
        prog.push(jmp_reg!(BPF_JGT, R6, R3, 0));
        bound_jump_indices.push(bound_check_idx + 2);

        for (offset, expected) in alt.iter().enumerate() {
            prog.push(ldx_mem!(BPF_B, R7, R5, offset as i16));
            let mismatch_idx = prog.len();
            prog.push(jmp_imm!(BPF_JNE, R7, *expected as i32, 0));
            alt_mismatches.push(mismatch_idx);
        }

        let match_idx = prog.len();
        prog.push(jmp_imm!(BPF_JA, R0, 0, 0));
        match_jump_indices.push(match_idx);
        mismatch_jump_indices.push(alt_mismatches);
    }

    let fail_idx = prog.len();
    prog.push(alu64_imm!(BPF_MOV, R0, 0));
    prog.push(exit!());

    let success_idx = prog.len();
    prog.push(alu64_imm!(BPF_MOV, R0, 1));
    prog.push(exit!());

    for (alt_idx, alt_mismatches) in mismatch_jump_indices.iter().enumerate() {
        let next_alt_idx = alternative_start_indices
            .get(alt_idx + 1)
            .copied()
            .unwrap_or(fail_idx);

        for &jump_idx in alt_mismatches {
            let expected = prog[jump_idx].imm;
            patch_imm_jump(&mut prog, jump_idx, next_alt_idx, R7, expected, BPF_JNE);
        }
    }

    for (alt_position, &bound_jump_idx) in bound_jump_indices.iter().enumerate() {
        let next_alt_idx = alternative_start_indices
            .get(alt_position + 1)
            .copied()
            .unwrap_or(fail_idx);
        patch_reg_jump(&mut prog, bound_jump_idx, next_alt_idx, R6, R3, BPF_JGT);
    }

    for &jump_idx in &match_jump_indices {
        patch_match_jump(&mut prog, jump_idx, success_idx);
    }

    Ok(prog)
}

/// A character class range for BPF compilation.
///
/// Compiles a single-byte character class check.
///
/// The character class is a set of ranges (e.g., `[a-zA-Z0-9]`).
/// Generates BPF instructions that load one byte and check if it falls
/// within any of the ranges.
///
/// Register usage:
/// - `R5` must point to the byte to check.
/// - Returns 1 if the byte matches any range, 0 otherwise.
///
/// # Errors
///
/// Returns [`CompileError::InvalidPattern`] if ranges is empty or any range has `lo > hi`.
pub fn compile_char_class(ranges: &[CharRange]) -> Result<Vec<BpfInsn>, CompileError> {
    if ranges.is_empty() {
        return Err(CompileError::InvalidPattern {
            reason: "character class must have at least one range",
        });
    }
    for r in ranges {
        if r.lo > r.hi {
            return Err(CompileError::InvalidPattern {
                reason: "character class range start must be <= end",
            });
        }
    }

    let estimated = 4 + ranges.len() * 3;
    compile_with_limit(estimated)?;

    let mut prog = Vec::with_capacity(estimated);

    // Load byte at R5: R6 = *(u8 *)(R5 + 0)
    prog.push(ldx_mem!(BPF_B, R6, R5, 0));

    // For each range, check if R6 is in [lo, hi]
    // If match: jump to MATCH label
    let mut match_jumps = Vec::with_capacity(ranges.len());
    for r in ranges {
        // if R6 < lo: skip this range
        prog.push(jmp_imm!(BPF_JLT, R6, i32::from(r.lo), 2));
        // if R6 <= hi: match!
        prog.push(jmp_imm!(BPF_JLE, R6, i32::from(r.hi), 0));
        match_jumps.push(prog.len() - 1);
        // fall through to next range
    }

    // No range matched: return 0
    prog.push(alu64_imm!(BPF_MOV, R0, 0));
    prog.push(exit!());

    // MATCH: return 1
    let match_target = prog.len();
    prog.push(alu64_imm!(BPF_MOV, R0, 1));
    prog.push(exit!());

    // Patch match jumps to target the MATCH label
    for &idx in &match_jumps {
        prog[idx].off = (match_target as i16) - (idx as i16) - 1;
    }

    Ok(prog)
}
