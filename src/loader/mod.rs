//! Native Linux syscall bridge for injecting JIT'd eBPF filters.
//!
//! Uses bare-metal libc `bpf()` syscall constraints without relying on heavyweight
//! libraries like `libbpf` or `aya`. This forces ultimate alignment and allows zero-dependency
//! kernel injections.

pub mod core_detect;
mod prog;
mod ringbuf;

pub use prog::{attach_to_socket, load_filter};
pub use ringbuf::{create_ringbuf, poll_ringbuf};

/// BPF syscall number (use libc constant for portability across architectures).
#[cfg(target_os = "linux")]
pub(super) const SYS_BPF: libc::c_long = libc::SYS_bpf;
#[cfg(not(target_os = "linux"))]
pub(super) const SYS_BPF: libc::c_long = 321;
