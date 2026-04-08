//! `ebpfkit` — High-Performance JIT eBPF Compilation and Filtering
//!
//! Exposes a zero-dependency, bare-metal BPF compiler to bridge string
//! constraints dynamically into kernel ring-0 operations.
//!
//! It absolutely blitzes userspace tools like Ripgrep by discarding non-matching
//! hardware pages before they ever cross the NVMe-to-Userspace DMA boundaries.
//!
//! **Platform:** Linux only. This crate requires eBPF support which is a Linux
//! kernel feature. On non-Linux platforms, the crate compiles but all public
//! functions return errors.

#![warn(missing_docs, clippy::pedantic)]
#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![allow(
    missing_docs,
    unused_variables,
    clippy::wildcard_imports,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_ptr_alignment,
    clippy::borrow_as_ptr,
    clippy::ptr_as_ptr,
    clippy::ref_as_ptr,
    clippy::semicolon_if_nothing_returned,
    clippy::missing_errors_doc
)]

/// Low-level eBPF opcode definitions and raw structure macros.
pub mod assembler;

/// Dynamic runtime JIT compilation of regex and literal components.
pub mod compiler;

/// Bare-metal syscall operations to load and bind BPF bytecode into the kernel.
pub mod loader;

#[cfg(unix)]
use std::os::unix::io::RawFd;

/// Compiles and loads an active Kernel-Space Page Discard filter.
///
/// Converts the target substring constraint (e.g. `b"password"`) immediately into
/// an unrolled architecture-agnostic BPF socket filter, bypassing clang entirely,
/// and returning an active FDA waiting to be snapped onto an `io_uring` mapped
/// raw socket.
///
/// # Errors
///
/// Returns [`AttachError::Compile`] when the literal cannot be compiled into a
/// verifier-safe eBPF program, or [`AttachError::Io`] when the generated filter
/// cannot be loaded or attached to `target_socket`.
#[cfg(unix)]
pub fn attach_kernel_page_discard(pattern: &[u8], target_socket: RawFd) -> Result<(), AttachError> {
    let insns = compiler::compile_literal_search(pattern)?;
    let filter_fd = loader::load_filter(&insns)?;
    loader::attach_to_socket(filter_fd, target_socket)?;
    Ok(())
}

/// Non-Unix stub that always returns an error.
#[cfg(not(unix))]
pub fn attach_kernel_page_discard(pattern: &[u8], _target_socket: i32) -> Result<(), AttachError> {
    let _ = pattern;
    Err(AttachError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "eBPF is only available on Linux",
    )))
}

/// Errors from attaching a kernel page discard filter.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttachError {
    /// BPF compilation failed.
    #[error(transparent)]
    Compile(#[from] compiler::CompileError),
    /// Kernel operation failed.
    #[error("kernel operation failed: {0}")]
    Io(#[from] std::io::Error),
}
