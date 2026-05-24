//! CO-RE (Compile Once — Run Everywhere) capability detection.

use std::path::Path;

/// Check if the kernel supports BTF-based CO-RE.
///
/// Returns `true` if `/sys/kernel/btf/vmlinux` exists, indicating
/// the kernel was built with `CONFIG_DEBUG_INFO_BTF=y`.
pub fn has_btf() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// Check if the kernel supports BPF ring buffers (Linux 5.8+).
pub fn has_ringbuf() -> bool {
    kernel_version() >= (5, 8, 0)
}

/// Check if the kernel supports fentry/fexit tracing programs (Linux 5.5+).
pub fn has_fentry() -> bool {
    kernel_version() >= (5, 5, 0)
}

/// Get a diagnostic summary of BPF CO-RE capabilities.
pub fn diagnostics() -> Vec<String> {
    let mut diags = Vec::new();
    let version = kernel_version();
    diags.push(format!("kernel: {}.{}.{}", version.0, version.1, version.2));
    diags.push(format!("BTF available: {}", has_btf()));
    diags.push(format!("fentry support: {}", has_fentry()));
    diags.push(format!("ring buffer support: {}", has_ringbuf()));

    #[cfg(target_os = "linux")]
    {
        let euid = unsafe { libc::geteuid() };
        diags.push(format!("running as root: {}", euid == 0));
    }

    diags
}

/// Parse the kernel version from /proc/sys/kernel/osrelease.
fn kernel_version() -> (u32, u32, u32) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let trimmed = release.trim();
            let mut parts = trimmed.split(|c: char| !c.is_ascii_digit());
            let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            return (major, minor, patch);
        }
    }
    (0, 0, 0)
}
