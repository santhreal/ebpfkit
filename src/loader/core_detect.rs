//! CO-RE (Compile Once: Run Everywhere) capability detection.

use std::path::Path;

/// Check if the kernel supports BTF-based CO-RE.
///
/// Returns `true` if `/sys/kernel/btf/vmlinux` exists, indicating
/// the kernel was built with `CONFIG_DEBUG_INFO_BTF=y`.
#[must_use]
pub fn has_btf() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// Check if the kernel supports BPF ring buffers (Linux 5.8+).
#[must_use]
pub fn has_ringbuf() -> bool {
    kernel_version() >= (5, 8, 0)
}

/// Check if the kernel supports fentry/fexit tracing programs (Linux 5.5+).
#[must_use]
pub fn has_fentry() -> bool {
    kernel_version() >= (5, 5, 0)
}

/// Get a diagnostic summary of BPF CO-RE capabilities.
#[must_use]
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

/// Warn (exactly once) that kernel detection failed and every version-gated
/// eBPF feature is being treated as unavailable. Returning (0,0,0) is the
/// correct fail-closed default, but doing so SILENTLY hid the reason a host
/// with a perfectly capable kernel reported "no ring buffer / no fentry"
/// (Law-10). The warning fires once so repeated has_*() calls do not spam.
fn warn_kernel_undetected(reason: &str) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "ebpfkit: could not determine kernel version ({reason}); treating all \
             version-gated eBPF features (ring buffer, fentry, ...) as UNAVAILABLE"
        );
    });
}

/// Parse "major.minor.patch..." from an osrelease string. Returns `None` when
/// the MAJOR component is absent/empty/non-numeric/`u32`-overflowing - the case
/// that would collapse the kernel to 0.x and silently disable every feature
/// gate, so the caller fails closed AND warns. Absent minor/patch legitimately
/// default to 0 (e.g. osrelease "6" or "6.1") and are NOT treated as a failure.
fn parse_kernel_release(trimmed: &str) -> Option<(u32, u32, u32)> {
    let mut parts = trimmed.split(|c: char| !c.is_ascii_digit());
    let major = parts.next().and_then(|s| s.parse().ok())?;
    let minor = parts.next().map_or(Some(0), |s| s.parse().ok())?;
    let patch = parts.next().map_or(Some(0), |s| s.parse().ok())?;
    Some((major, minor, patch))
}

/// Parse the kernel version from /proc/sys/kernel/osrelease.
///
/// Returns (0,0,0) when the kernel version cannot be determined - a fail-closed
/// default that disables every version-gated feature - but surfaces the failure
/// loudly (once) instead of degrading silently.
fn kernel_version() -> (u32, u32, u32) {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            Ok(release) => match parse_kernel_release(release.trim()) {
                Some(version) => return version,
                None => warn_kernel_undetected(&format!(
                    "unparseable major version in osrelease {:?}",
                    release.trim()
                )),
            },
            Err(error) => {
                warn_kernel_undetected(&format!("cannot read /proc/sys/kernel/osrelease: {error}"));
            }
        }
    }
    (0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::parse_kernel_release;

    #[test]
    fn parses_full_and_partial_versions() {
        assert_eq!(parse_kernel_release("6.1.0"), Some((6, 1, 0)));
        assert_eq!(parse_kernel_release("5.15.137-generic"), Some((5, 15, 137)));
        // Absent minor/patch legitimately default to 0 (not a failure).
        assert_eq!(parse_kernel_release("6"), Some((6, 0, 0)));
        assert_eq!(parse_kernel_release("6.1"), Some((6, 1, 0)));
        // Vendor suffixes and separators after the digits are ignored.
        assert_eq!(parse_kernel_release("6.8.0-31-generic"), Some((6, 8, 0)));
    }

    #[test]
    fn rejects_unparseable_major_so_caller_fails_closed() {
        // These are the cases that previously collapsed to 0.x SILENTLY,
        // disabling every eBPF feature gate. parse now returns None so the
        // caller warns loudly and fails closed (Law-10).
        assert_eq!(parse_kernel_release(""), None);
        assert_eq!(parse_kernel_release("unknown"), None);
        assert_eq!(parse_kernel_release("-generic"), None); // leading non-digit -> empty major
                                                            // u32-overflowing major must NOT wrap to a small number.
        assert_eq!(parse_kernel_release("99999999999.1.0"), None);
    }

    #[test]
    fn rejects_unparseable_minor_or_patch() {
        // Overflowing or non-numeric minor/patch must not silently default to 0.
        assert_eq!(parse_kernel_release("6.99999999999.0"), None);
        assert_eq!(parse_kernel_release("6.abc"), None);
        assert_eq!(parse_kernel_release("6.1.xyz"), None);
    }
}
