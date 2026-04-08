use ebpfkit::assembler::BPF_EXIT;
use ebpfkit::compiler::{
    compile_alternation, compile_character_class, compile_literal_search, CompileError,
    MAX_BPF_PATTERN_LEN,
};

#[test]
fn compile_literal_search_unicode_high_bytes() {
    let pattern = "a💖b🚀c"; // Contains multi-byte characters
    let result = compile_literal_search(pattern.as_bytes());
    assert!(result.is_ok());
    let prog = result.unwrap();
    assert!(prog.len() > 0);
    assert_eq!(prog.last().unwrap().code & 0xF0, BPF_EXIT);
}

#[test]
fn compile_literal_search_extreme_length() {
    let pattern = vec![b'a'; MAX_BPF_PATTERN_LEN];
    let result = compile_literal_search(&pattern);
    assert!(result.is_ok());

    let pattern_too_long = vec![b'a'; MAX_BPF_PATTERN_LEN + 1];
    let result_err = compile_literal_search(&pattern_too_long);
    assert!(matches!(
        result_err,
        Err(CompileError::PatternTooLong { .. })
    ));
}

#[test]
fn compile_character_class_invalid_ranges() {
    // Range with start > end should fail
    let pattern = b"z-a";
    let result = compile_character_class(pattern);
    assert!(matches!(result, Err(CompileError::InvalidPattern { .. })));
}

#[test]
fn compile_alternation_empty_strings() {
    let patterns: &[&[u8]] = &[b"a", b"", b"c"];
    let result = compile_alternation(patterns);
    assert!(result.is_ok()); // Should compile and just return match immediately
}
