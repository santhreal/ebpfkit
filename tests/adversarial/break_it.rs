//! Adversarial tests designed to BREAK the `ebpfkit` crate.
//!
//! These tests verify empty inputs, null bytes, max values, resource exhaustion,
//! concurrency, and malformed structures. Failures here are intentional findings.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ebpfkit::compiler::{
    compile_alternation, compile_character_class, compile_literal_search, CompileError,
    MAX_BPF_PATTERN_LEN,
};
use std::sync::{Arc, Barrier};
use std::thread;

// Helper to check error format
fn assert_has_fix(err: &CompileError) {
    let msg = err.to_string();
    assert!(
        msg.contains("Fix:"),
        "Error message MUST contain an actionable 'Fix:' recommendation. Got: {}",
        msg
    );
}

// 1. Empty input / zero-length slices
#[test]
fn test_empty_literal() {
    let res = compile_literal_search(b"");
    // Should compile to an immediate match
    assert!(
        res.is_ok(),
        "Empty literal should compile to an immediate match program"
    );
}

#[test]
fn test_empty_character_class() {
    let res = compile_character_class(b"");
    assert!(
        res.is_ok(),
        "Empty character class should compile to an immediate failure program"
    );
}

#[test]
fn test_empty_alternation_slice() {
    // Empty alternation = no alternatives = never matches.
    // Returns a valid BPF program that sets R0=0 (no match) and exits.
    let res = compile_alternation(&[]);
    assert!(
        res.is_ok(),
        "empty alternation should produce a valid no-match program"
    );
}

// 2. Null bytes in input
#[test]
fn test_null_bytes_in_literal() {
    let pattern = [0u8, 0, 0, 0];
    let res = compile_literal_search(&pattern);
    assert!(
        res.is_ok(),
        "Literal with null bytes should compile successfully"
    );
}

#[test]
fn test_null_bytes_in_character_class() {
    let pattern = [0u8, b'-', 0u8];
    let res = compile_character_class(&pattern);
    assert!(
        res.is_ok(),
        "Character class with null byte ranges should compile successfully"
    );
}

#[test]
fn test_null_bytes_in_alternation() {
    let pattern = [0u8, 0u8];
    let res = compile_alternation(&[&pattern, &[0u8]]);
    assert!(
        res.is_ok(),
        "Alternation with null bytes should compile successfully"
    );
}

// 3. Maximum values for numeric parameters
#[test]
fn test_max_bpf_pattern_len_exact() {
    let pattern = vec![b'A'; MAX_BPF_PATTERN_LEN];
    let res = compile_literal_search(&pattern);
    assert!(res.is_ok(), "Pattern at MAX_BPF_PATTERN_LEN should compile");
}

#[test]
fn test_max_bpf_pattern_len_plus_one() {
    let pattern = vec![b'A'; MAX_BPF_PATTERN_LEN + 1];
    let res = compile_literal_search(&pattern);
    match res {
        Ok(_) => panic!("Pattern exceeding MAX_BPF_PATTERN_LEN should return an error"),
        Err(e) => assert_has_fix(&e),
    }
}

// 4. 1MB+ input
#[test]
fn test_huge_1mb_literal() {
    let pattern = vec![b'B'; 1024 * 1024]; // 1MB pattern
    let res = compile_literal_search(&pattern);
    match res {
        Ok(_) => panic!("1MB pattern should fail gracefully without crashing or panicking"),
        Err(e) => assert_has_fix(&e),
    }
}

#[test]
fn test_huge_1mb_alternation() {
    let item = vec![b'C'; 1024];
    let items: Vec<&[u8]> = vec![&item; 1024]; // 1024 * 1024 bytes total
    let res = compile_alternation(&items);
    match res {
        Ok(_) => panic!("1MB alternation should fail gracefully without crashing or panicking"),
        Err(e) => assert_has_fix(&e),
    }
}

// 5. Concurrent access from 8 threads
#[test]
fn test_concurrent_compilation() {
    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = vec![];

    for _ in 0..num_threads {
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let pattern = b"concurrent_pattern";
            let res = compile_literal_search(pattern);
            assert!(res.is_ok(), "Concurrent compilation failed");
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

#[test]
fn test_concurrent_huge_compilation() {
    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = vec![];

    for _ in 0..num_threads {
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let pattern = vec![b'A'; MAX_BPF_PATTERN_LEN + 10]; // Expecting failure
            let res = compile_literal_search(&pattern);
            match res {
                Ok(_) => panic!("Concurrent huge compilation should fail properly"),
                Err(e) => assert_has_fix(&e),
            }
        }));
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

// 6. Malformed/truncated input (partial data)
#[test]
fn test_malformed_character_class_trailing_dash() {
    // Trailing dash in character class: either error or treat dash as literal.
    let res = compile_character_class(b"a-");
    // Both Ok (dash as literal) and Err are acceptable — must not panic.
    if let Err(e) = &res {
        assert_has_fix(e);
    }
}

#[test]
fn test_malformed_character_class_leading_dash() {
    // Some regex dialects allow leading dash to mean literal dash, but let's check behavior
    let res = compile_character_class(b"-z");
    if let Err(e) = res {
        assert_has_fix(&e);
    }
}

#[test]
fn test_malformed_character_class_reversed_range() {
    let res = compile_character_class(b"z-a");
    match res {
        Ok(_) => panic!("Character class with reversed range should return error"),
        Err(e) => assert_has_fix(&e),
    }
}

#[test]
fn test_malformed_character_class_multiple_dashes() {
    let res = compile_character_class(b"a--z");
    match res {
        Ok(_) => panic!("Character class with multiple dashes should return error"),
        Err(e) => assert_has_fix(&e),
    }
}

// 7. Unicode edge cases (BOM, overlong sequences, surrogates)
#[test]
fn test_unicode_bom() {
    let pattern = [0xEF, 0xBB, 0xBF]; // UTF-8 BOM
    let res = compile_literal_search(&pattern);
    assert!(res.is_ok(), "BOM should compile as a literal byte sequence");
}

#[test]
fn test_unicode_overlong_sequence() {
    // 2-byte overlong sequence for 'A' (0x41): 11000001 10000001 -> C1 81
    let pattern = [0xC1, 0x81];
    let res = compile_literal_search(&pattern);
    assert!(
        res.is_ok(),
        "Overlong UTF-8 sequence should compile as raw bytes"
    );
}

#[test]
fn test_unicode_surrogate_half() {
    let pattern = [0xED, 0xA0, 0x80]; // D800 (surrogate half)
    let res = compile_literal_search(&pattern);
    assert!(res.is_ok(), "Surrogate half should compile as raw bytes");
}

#[test]
fn test_unicode_character_class() {
    let pattern = "a-🦀".as_bytes(); // Range with multi-byte character
    let res = compile_character_class(pattern);
    // Multi-byte range endpoints: either error or handle byte-level range.
    // BPF operates on bytes, not Unicode codepoints.
    if let Err(e) = &res {
        assert_has_fix(e);
    }
}

// 8. Duplicate entries
#[test]
fn test_duplicate_character_class() {
    let res = compile_character_class(b"a-za-z0-90-9");
    // Depending on implementation, might succeed or fail, but shouldn't panic.
    if let Err(e) = res {
        assert_has_fix(&e);
    }
}

#[test]
fn test_duplicate_alternation() {
    let res = compile_alternation(&[b"test", b"test", b"test"]);
    // Should compile, potentially deduplicated
    if let Err(e) = res {
        assert_has_fix(&e);
    }
}

// 9. Off-by-one testing
#[test]
fn test_alternation_max_items() {
    // If there's an internal limit to number of alternations, we test a large number
    let items: Vec<&[u8]> = vec![b"a"; 1024];
    let res = compile_alternation(&items);
    if let Err(e) = res {
        assert_has_fix(&e);
    }
}

#[test]
fn test_character_class_max_ranges() {
    let mut pattern = Vec::new();
    for i in 0..128 {
        pattern.push(i as u8);
        pattern.push(b'-');
        pattern.push(i as u8);
    }
    // Pattern like "0-01-12-2..."
    let res = compile_character_class(&pattern);
    if let Err(e) = res {
        assert_has_fix(&e);
    }
}

// 10. Resource exhaustion: 100K items, deeply nested structures
#[test]
fn test_resource_exhaustion_alternation() {
    let item = b"a";
    let items: Vec<&[u8]> = vec![item; 100_000];
    let res = compile_alternation(&items);
    match res {
        Ok(_) => panic!(
            "100K items should trigger verifier limits/errors, not compile successfully or panic"
        ),
        Err(e) => assert_has_fix(&e),
    }
}

#[test]
fn test_resource_exhaustion_character_class_long() {
    // Creating a massive character class string
    let mut pattern = Vec::new();
    for _ in 0..100_000 {
        pattern.push(b'a');
    }
    let res = compile_character_class(&pattern);
    match res {
        Ok(_) => panic!("100K char class should fail gracefully"),
        Err(e) => assert_has_fix(&e),
    }
}

// 11. Extra tests for breaking verifier limits inside compiler logic
#[test]
fn test_alternation_with_empty_and_max_len() {
    let max_len_pattern = vec![b'A'; MAX_BPF_PATTERN_LEN];
    let res = compile_alternation(&[b"", &max_len_pattern]);
    if let Err(e) = res {
        assert_has_fix(&e);
    }
}

#[test]
fn test_alternation_with_too_long_item() {
    let too_long = vec![b'A'; MAX_BPF_PATTERN_LEN + 1];
    let res = compile_alternation(&[b"test", &too_long]);
    // Too-long pattern may be rejected or may exceed instruction limit.
    if let Err(e) = &res {
        assert_has_fix(e);
    }
}

#[test]
fn test_compile_alternation_all_empty() {
    let res = compile_alternation(&[b"", b"", b""]);
    assert!(
        res.is_ok(),
        "Alternation with all empty strings should compile to an immediate match"
    );
}

#[test]
fn test_compile_character_class_only_dashes() {
    // All-dashes character class: either error or treat as literal dash.
    let res = compile_character_class(b"-----");
    if let Err(e) = &res {
        assert_has_fix(e);
    }
}

#[test]
fn test_compile_literal_search_verifier_limit_stress() {
    // Trying to generate exactly MAX_BPF_INSNS instructions
    // MAX_BPF_INSNS is 4096 in loader.rs, let's see how compiler handles a pattern length
    // that might generate more than 4096 instructions if not handled.
    // MAX_BPF_PATTERN_LEN is currently 1024, let's assume each byte generates >4 insns.
    let pattern = vec![b'X'; MAX_BPF_PATTERN_LEN];
    let res = compile_literal_search(&pattern);
    // If it compiles, the resulting instructions shouldn't crash the loader, but we only test compiler here.
    if let Err(e) = res {
        assert_has_fix(&e);
    }
}

#[test]
fn test_character_class_all_bytes() {
    let res = compile_character_class(b"\x00-\xFF");
    if let Err(e) = res {
        assert_has_fix(&e);
    }
}

#[test]
fn test_alternation_long_strings() {
    let p1 = vec![b'A'; 512];
    let p2 = vec![b'B'; 512];
    let res = compile_alternation(&[&p1, &p2]);
    if let Err(e) = res {
        assert_has_fix(&e);
    }
}
