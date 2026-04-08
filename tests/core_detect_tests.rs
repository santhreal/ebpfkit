//! Platform-detection tests for CO-RE capability probe functions.
//!
//! These tests exercise `ebpfkit::loader::core_detect` on any Linux system,
//! regardless of whether the kernel actually supports BPF.

use ebpfkit::loader::core_detect;

#[test]
fn has_btf_returns_bool_without_panic() {
    let _ = core_detect::has_btf();
}

#[test]
fn has_ringbuf_returns_bool_without_panic() {
    let _ = core_detect::has_ringbuf();
}

#[test]
fn has_fentry_returns_bool_without_panic() {
    let _ = core_detect::has_fentry();
}

#[test]
fn diagnostics_returns_non_empty_vec() {
    let diags = core_detect::diagnostics();
    assert!(!diags.is_empty(), "diagnostics() returned an empty vector");
}

#[test]
fn diagnostics_contains_kernel_version_string() {
    let diags = core_detect::diagnostics();
    assert!(
        diags.iter().any(|s| s.starts_with("kernel: ")),
        "diagnostics() missing kernel version string: {:?}",
        diags
    );
}
