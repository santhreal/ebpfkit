use ebpfkit::assembler::{BpfInsn, BPF_EXIT, BPF_JMP};
use ebpfkit::loader::{attach_to_socket, create_ringbuf, load_filter, poll_ringbuf};

#[test]
fn adversarial_io_attach_invalid_socket() {
    // Generate valid instructions first
    let insns = vec![BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)];
    let fd_result = load_filter(&insns);

    // We only test the attach if load_filter succeeded (e.g. running on Linux with proper perms)
    // If we're not on linux or missing privileges, it'll fail early which is fine.
    if let Ok(prog_fd) = fd_result {
        // -1 is an invalid FD.
        let result = attach_to_socket(prog_fd, -1);

        assert!(
            result.is_err(),
            "GAP FINDING: attach_to_socket accepted an invalid socket fd (-1)!"
        );

        let err = result.unwrap_err();
        assert!(
            err.raw_os_error().is_some(),
            "GAP FINDING: Expected IO OS error for invalid socket, got something else: {:?}",
            err
        );

        unsafe {
            libc::close(prog_fd);
        }
    }
}

#[test]
fn adversarial_io_poll_invalid_ringbuf_fd() {
    // Polling an invalid file descriptor (-1) must cleanly return an IO error, not panic
    let mut cb = |_: &[u8]| {};
    let result = poll_ringbuf(-1, &mut cb);

    assert!(
        result.is_err(),
        "GAP FINDING: poll_ringbuf accepted an invalid FD (-1)!"
    );
}

#[test]
fn adversarial_io_create_ringbuf_zero() {
    let result = create_ringbuf(0);
    assert!(
        result.is_err(),
        "GAP FINDING: create_ringbuf accepted a zero size argument!"
    );

    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "GAP FINDING: create_ringbuf with 0 size did not return InvalidInput error"
    );
}
