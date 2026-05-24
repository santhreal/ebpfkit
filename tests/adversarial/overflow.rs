use ebpfkit::compiler::{compile_literal_search, CompileError, MAX_BPF_PATTERN_LEN};
use ebpfkit::loader::create_ringbuf;

#[test]
fn adversarial_compile_overflow_pattern_len() {
    let pattern = vec![b'A'; MAX_BPF_PATTERN_LEN + 1];
    let result = compile_literal_search(&pattern);

    assert!(
        result.is_err(),
        "GAP FINDING: Engine compiled a literal pattern larger than the MAX_BPF_PATTERN_LEN boundary!"
    );

    if let Err(e) = result {
        assert!(
            matches!(e, CompileError::PatternTooLong { .. }),
            "GAP FINDING: Expected PatternTooLong error, got another error kind: {:?}",
            e
        );
    }
}

#[test]
fn adversarial_compile_extreme_u32_max_len() {
    // Note: We don't allocate u32::MAX bytes, but we simulate what an engine might receive.
    // Given the memory constraints, we verify that a very large sequence correctly maps to PatternTooLong.
    // Instead of actually making a massive vector which would just run out of test memory,
    // we use a custom slice reference mechanism or rely on standard oversized buffers.
    let pattern = vec![0xFF; MAX_BPF_PATTERN_LEN * 10];
    let result = compile_literal_search(&pattern);

    assert!(
        result.is_err(),
        "GAP FINDING: Engine compiled a massive array, risking buffer overflows!"
    );
}

#[test]
fn adversarial_create_ringbuf_overflow_size() {
    // 1 << 31 is 2147483648, a power of two, but extremely large.
    // The kernel will either map this, or return ENOMEM/EPERM/EINVAL.
    // We strictly assert it does not panic the wrapper function or cause a segmentation fault.
    let result = create_ringbuf(1 << 31);

    // We don't check for Ok/Err here specifically because on extremely large boxen it MIGHT pass,
    // but the critical invariant is that it handles it gracefully (returns Result) and DOES NOT PANIC.
    if let Err(e) = result {
        assert!(
            e.raw_os_error().is_some(),
            "GAP FINDING: ringbuf creation overflow resulted in custom error without OS code"
        );
    } else if let Ok(fd) = result {
        // Just in case it actually worked, clean up.
        unsafe {
            libc::close(fd);
        }
    }
}
