#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    missing_docs,
    function_casts_as_integer
)]
//! S-perf-pmg: BPF compile hot-path edge catalog.

use ebpfkit::assembler::{format_program, BpfInsn, BPF_EXIT};
use ebpfkit::compiler::{
    compile_alternation, compile_char_class, compile_character_class, compile_literal_search,
    compile_with_limit, CharRange, CompileError, MAX_BPF_PATTERN_LEN,
};

fn assert_valid_jumps(program: &[BpfInsn]) {
    for (idx, insn) in program.iter().enumerate() {
        if (insn.code & 0x07) == 0x05 && (insn.code & 0xF0) != BPF_EXIT {
            let target = idx as isize + 1 + insn.off as isize;
            assert!(target >= 0 && (target as usize) < program.len());
        }
    }
}

#[test]
fn edge_literal_empty() {
    let p = compile_literal_search(b"").unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_literal_single_byte() {
    let p = compile_literal_search(b"x").unwrap();
    assert_valid_jumps(&p);
    assert!(!p.is_empty());
}

#[test]
fn edge_literal_max_len() {
    let pat = vec![b'a'; MAX_BPF_PATTERN_LEN];
    assert!(compile_literal_search(&pat).is_ok());
}

#[test]
fn edge_literal_over_max() {
    let pat = vec![b'a'; MAX_BPF_PATTERN_LEN + 1];
    assert!(matches!(
        compile_literal_search(&pat),
        Err(CompileError::PatternTooLong { .. })
    ));
}

#[test]
fn edge_char_class_single() {
    let p = compile_character_class(b"abc").unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_char_class_empty() {
    assert!(compile_character_class(b"").is_ok());
}

#[test]
fn edge_alternation_two() {
    let p = compile_alternation(&[b"ab", b"cd"]).unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_alternation_empty_branch() {
    let p = compile_alternation(&[b"", b"x"]).unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_char_ranges_single() {
    let p = compile_char_class(&[CharRange { lo: b'a', hi: b'z' }]).unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_char_ranges_inverted() {
    let p = compile_char_class(&[CharRange { lo: b'0', hi: b'9' }]).unwrap();
    assert!(!p.is_empty());
}

#[test]
fn edge_compile_with_limit_ok() {
    assert!(compile_with_limit(8).is_ok());
}

#[test]
fn edge_format_program_nonempty() {
    let p = compile_literal_search(b"test").unwrap();
    let s = format_program(&p);
    assert!(s.contains("exit"));
}

#[test]
fn edge_literal_null_byte() {
    let p = compile_literal_search(b"\x00").unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_literal_all_bytes_too_long() {
    // Literal search emits ~2 insns/byte; exceed the 4096-instruction verifier cap.
    let pat = vec![b'a'; 2044];
    assert!(compile_literal_search(&pat).is_err());
}

#[test]
fn edge_alternation_many() {
    let alts: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
    assert_valid_jumps(&compile_alternation(&alts).unwrap());
}

#[test]
fn edge_literal_repeated() {
    let p = compile_literal_search(b"aaaa").unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_char_class_high_bytes() {
    let p = compile_character_class(&[0xFF, 0xFE]).unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_alternation_one_branch() {
    let p = compile_alternation(&[b"only"]).unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_char_range_point() {
    let p = compile_char_class(&[CharRange { lo: b'X', hi: b'X' }]).unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_literal_ascii_printable() {
    let p = compile_literal_search(b"Hello, BPF!").unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_compile_with_limit_zero() {
    assert!(compile_with_limit(0).is_ok());
}

#[test]
fn edge_alternation_long_branches() {
    let a = b"short";
    let b = vec![b'x'; 32];
    let p = compile_alternation(&[a, &b]).unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_char_class_duplicates() {
    let p = compile_character_class(b"aaa").unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_literal_binary_nonutf8() {
    let p = compile_literal_search(&[0x80, 0x81, 0x82]).unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_char_ranges_adjacent() {
    let p = compile_char_class(&[
        CharRange { lo: b'a', hi: b'c' },
        CharRange { lo: b'd', hi: b'f' },
    ])
    .unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_program_ends_with_exit_class() {
    let p = compile_literal_search(b"z").unwrap();
    assert!(p.last().map(|i| i.code & 0xF0 == BPF_EXIT).unwrap_or(false));
}

#[test]
fn edge_alternation_identical_branches() {
    let p = compile_alternation(&[b"same", b"same"]).unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_literal_two_bytes() {
    let p = compile_literal_search(b"xy").unwrap();
    assert!(p.len() >= 2);
}

#[test]
fn edge_char_class_all_range() {
    let p = compile_char_class(&[CharRange { lo: 0, hi: 255 }]).unwrap();
    assert_valid_jumps(&p);
}

#[test]
fn edge_compile_with_limit_large() {
    assert!(compile_with_limit(10_000).is_err());
}

#[test]
fn edge_format_empty_program() {
    assert!(format_program(&[]).contains("program"));
}

#[test]
fn edge_literal_near_max() {
    let pat = vec![b'z'; MAX_BPF_PATTERN_LEN - 1];
    assert!(compile_literal_search(&pat).is_ok());
}

#[test]
fn edge_alternation_empty_list() {
    let p = compile_alternation(&[]).unwrap();
    assert_valid_jumps(&p);
}
