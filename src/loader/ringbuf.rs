use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::SYS_BPF;

const BPF_MAP_CREATE: u32 = 0;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;
const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
const BPF_RINGBUF_HDR_SZ: usize = 8;

#[repr(C)]
#[derive(Default)]
struct BpfAttrMapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
}

#[repr(C)]
#[derive(Default)]
struct BpfAttrObjInfoByFd {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C)]
#[derive(Default)]
struct BpfMapInfo {
    map_type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [u8; 16],
    ifindex: u32,
    btf_vmlinux_value_type_id: u32,
    netns_dev: u64,
    netns_ino: u64,
    btf_id: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    map_extra: u64,
}

#[repr(C)]
struct RingbufHeader {
    len: AtomicU32,
    pad: u32,
}

/// Creates a `BPF_MAP_TYPE_RINGBUF` map with the requested capacity.
///
/// `size_bytes` must be a non-zero power of two because the kernel uses it as
/// the ring size directly.
pub fn create_ringbuf(size_bytes: u32) -> Result<RawFd, std::io::Error> {
    if size_bytes == 0 || !size_bytes.is_power_of_two() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ring buffer size must be a non-zero power of two. Fix: pass 4096, 8192, 16384, or another power of two.",
        ));
    }

    let attr = BpfAttrMapCreate {
        map_type: BPF_MAP_TYPE_RINGBUF,
        max_entries: size_bytes,
        ..Default::default()
    };

    // SAFETY: `attr` is a valid `BPF_MAP_CREATE` payload for the duration of
    // the syscall and the kernel copies it before returning.
    let fd = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_MAP_CREATE,
            &attr as *const BpfAttrMapCreate,
            std::mem::size_of::<BpfAttrMapCreate>(),
        )
    };

    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(fd as RawFd)
}

/// Blocks until the kernel ring buffer contains events and invokes `callback`
/// for each record available at that wake-up.
pub fn poll_ringbuf(map_fd: RawFd, callback: &mut dyn FnMut(&[u8])) -> Result<(), std::io::Error> {
    let info = map_info(map_fd)?;
    if info.map_type != BPF_MAP_TYPE_RINGBUF {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fd does not reference a BPF ring buffer map. Fix: pass the fd returned by create_ringbuf or a BPF_MAP_TYPE_RINGBUF map.",
        ));
    }

    let page_size = page_size()?;
    let ring_size = usize::try_from(info.max_entries).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ring buffer max_entries does not fit in usize. Fix: use a smaller ring size.",
        )
    })?;
    let consumer = RingbufConsumer::new(map_fd, ring_size, page_size)?;
    let epoll_fd = EpollFd::new()?;
    epoll_fd.add(map_fd)?;

    epoll_fd.wait()?;
    consume_ring_records(&consumer, callback);
    Ok(())
}

fn page_size() -> Result<usize, std::io::Error> {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    if let Some(&value) = CACHE.get() {
        return Ok(value);
    }
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    let value = usize::try_from(value).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "system page size does not fit in usize. Fix: run on a supported userspace architecture.",
        )
    })?;
    let _ = CACHE.set(value);
    Ok(value)
}

fn map_info(map_fd: RawFd) -> Result<BpfMapInfo, std::io::Error> {
    let mut info = MaybeUninit::<BpfMapInfo>::zeroed();
    let attr = BpfAttrObjInfoByFd {
        bpf_fd: map_fd as u32,
        info_len: std::mem::size_of::<BpfMapInfo>() as u32,
        info: info.as_mut_ptr() as u64,
    };

    // SAFETY: the kernel writes at most `info_len` bytes into `info`.
    let rc = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_OBJ_GET_INFO_BY_FD,
            &attr as *const BpfAttrObjInfoByFd,
            std::mem::size_of::<BpfAttrObjInfoByFd>(),
        )
    };

    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: successful syscall fully initializes the bytes we requested.
    Ok(unsafe { info.assume_init() })
}

fn consume_ring_records(consumer: &RingbufConsumer, callback: &mut dyn FnMut(&[u8])) {
    let mut consumer_pos = consumer.consumer_pos().load(Ordering::Acquire);

    loop {
        let producer_pos = consumer.producer_pos().load(Ordering::Acquire);
        let mut consumed_any = false;

        while consumer_pos < producer_pos {
            let offset = (consumer_pos as usize) & consumer.mask;
            let header = consumer.header(offset);
            let raw_len = header.len.load(Ordering::Acquire);
            if raw_len & BPF_RINGBUF_BUSY_BIT != 0 {
                consumer
                    .consumer_pos()
                    .store(consumer_pos, Ordering::Release);
                return;
            }

            let data_len = (raw_len & !(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT)) as usize;
            let record_len = round_record_len(data_len);
            if raw_len & BPF_RINGBUF_DISCARD_BIT == 0 {
                let data_offset = offset + BPF_RINGBUF_HDR_SZ;
                // Validate the record stays within the double-mapped data region
                // BEFORE building the slice: `data_slice` is an unchecked
                // from_raw_parts, so a corrupt/hostile `data_len` in the header
                // would read out of bounds. A valid record never extends past
                // the 2*ring_size mirror; if this one does, the ring is corrupt
                // - stop consuming (do NOT advance past it) and surface loudly
                // rather than degrade into UB (Law-10, memory safety).
                let ring_size = consumer.mask.checked_add(1);
                if ring_size.is_none_or(|rs| !record_within_mapping(data_offset, data_len, rs)) {
                    eprintln!(
                        "ebpfkit: ringbuf record out of bounds (data_offset={data_offset}, \
                         data_len={data_len}, mask={}); stopping consumption to avoid an \
                         out-of-bounds read",
                        consumer.mask
                    );
                    consumer
                        .consumer_pos()
                        .store(consumer_pos, Ordering::Release);
                    return;
                }
                callback(unsafe { consumer.data_slice(data_offset, data_len) });
            }

            consumer_pos += record_len as u64;
            consumer
                .consumer_pos()
                .store(consumer_pos, Ordering::Release);
            consumed_any = true;
        }

        if !consumed_any {
            return;
        }
    }
}

/// Whether a record's data slice `[data_offset, data_offset + data_len)` stays
/// within the readable data region. The ring data pages are mapped TWICE (the
/// kernel's wraparound mirror), so `2 * ring_size` bytes are addressable from
/// `data_ptr`. A corrupt/hostile `data_len` in the record header that would read
/// past that mirror must be rejected before `data_slice` (an unchecked
/// `from_raw_parts`) is built. All arithmetic is checked so a near-`usize::MAX`
/// length or offset cannot wrap the bound into a false pass.
fn record_within_mapping(data_offset: usize, data_len: usize, ring_size: usize) -> bool {
    match (data_offset.checked_add(data_len), ring_size.checked_mul(2)) {
        (Some(end), Some(bound)) => end <= bound,
        _ => false,
    }
}

fn round_record_len(data_len: usize) -> usize {
    // Round `data_len + header` up to the next multiple of 8. Every step
    // saturates so a near-`usize::MAX` `data_len` cannot wrap: `total + 7` would
    // overflow, so we saturate it, and the mask then yields the largest 8-aligned
    // value. (A ring record this large never occurs in practice, but the arith
    // must be closed against a hostile/corrupt length.)
    let total = data_len.saturating_add(BPF_RINGBUF_HDR_SZ);
    total.saturating_add(7) & !7
}

/// Best-effort `munmap` that surfaces a failure instead of discarding it.
///
/// A failed unmap on a Drop or error path leaks the mapping and usually signals
/// a bug (a wrong length or address). There is nothing to recover in a
/// destructor, so rather than silently swallow the error (Law 10) we log it
/// loudly to stderr - matching the crate's existing `eprintln!` diagnostics -
/// turning an invisible mapping leak into an operator-visible warning.
fn munmap_or_warn(addr: *mut libc::c_void, len: usize, context: &str) {
    let rc = unsafe { libc::munmap(addr, len) };
    if rc != 0 {
        eprintln!(
            "ebpfkit: munmap failed while {context}: {} (mapping may be leaked)",
            std::io::Error::last_os_error()
        );
    }
}

/// Best-effort `close` that surfaces a failure instead of discarding it.
///
/// On Linux the descriptor is released even when `close` returns an error
/// (including `EINTR`), so there is nothing to retry; we log the error loudly
/// (Law 10) rather than hide a potential I/O flush failure behind `let _ =`.
fn close_or_warn(fd: RawFd, context: &str) {
    let rc = unsafe { libc::close(fd) };
    if rc != 0 {
        eprintln!(
            "ebpfkit: close failed while {context}: {}",
            std::io::Error::last_os_error()
        );
    }
}

struct EpollFd(RawFd);

impl EpollFd {
    fn new() -> Result<Self, std::io::Error> {
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(fd))
    }

    fn add(&self, map_fd: RawFd) -> Result<(), std::io::Error> {
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: map_fd as u64,
        };
        let rc = unsafe { libc::epoll_ctl(self.0, libc::EPOLL_CTL_ADD, map_fd, &mut event) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn wait(&self) -> Result<(), std::io::Error> {
        let mut event = libc::epoll_event { events: 0, u64: 0 };
        loop {
            let rc = unsafe { libc::epoll_wait(self.0, &mut event, 1, -1) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            return Ok(());
        }
    }
}

impl Drop for EpollFd {
    fn drop(&mut self) {
        close_or_warn(self.0, "closing epoll fd");
    }
}

struct RingbufConsumer {
    consumer_mapping: *mut libc::c_void,
    producer_mapping: *mut libc::c_void,
    data_ptr: *const u8,
    mapping_len: usize,
    mask: usize,
    page_size: usize,
}

impl RingbufConsumer {
    fn new(map_fd: RawFd, ring_size: usize, page_size: usize) -> Result<Self, std::io::Error> {
        let consumer_mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                map_fd,
                0,
            )
        };
        if consumer_mapping == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        let mapping_len = page_size
            .checked_add(ring_size.checked_mul(2).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ring buffer mapping length overflowed. Fix: use a smaller ring size.",
                )
            })?)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ring buffer mapping length overflowed. Fix: use a smaller ring size.",
                )
            })?;

        let producer_mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapping_len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                map_fd,
                page_size as libc::off_t,
            )
        };
        if producer_mapping == libc::MAP_FAILED {
            let error = std::io::Error::last_os_error();
            munmap_or_warn(
                consumer_mapping,
                page_size,
                "unmapping consumer page after producer mmap failed",
            );
            return Err(error);
        }

        let data_ptr = unsafe { (producer_mapping as *const u8).add(page_size) };
        Ok(Self {
            consumer_mapping,
            producer_mapping,
            data_ptr,
            mapping_len,
            mask: ring_size - 1,
            page_size,
        })
    }

    fn consumer_pos(&self) -> &AtomicU64 {
        unsafe { &*(self.consumer_mapping as *const AtomicU64) }
    }

    fn producer_pos(&self) -> &AtomicU64 {
        unsafe { &*(self.producer_mapping as *const AtomicU64) }
    }

    fn header(&self, offset: usize) -> &RingbufHeader {
        unsafe { &*(self.data_ptr.add(offset) as *const RingbufHeader) }
    }

    /// Returns a slice of `len` bytes starting at `offset` within the ring data
    /// pages.
    ///
    /// # Safety
    ///
    /// The caller must ensure `offset + len <= ring_size * 2` (the double-mapped
    /// data region). `consume_ring_records` validates this via
    /// `record_within_mapping` before calling `data_slice`.
    unsafe fn data_slice(&self, offset: usize, len: usize) -> &[u8] {
        std::slice::from_raw_parts(self.data_ptr.add(offset), len)
    }
}

impl Drop for RingbufConsumer {
    fn drop(&mut self) {
        munmap_or_warn(
            self.consumer_mapping,
            self.page_size,
            "unmapping ring consumer page",
        );
        munmap_or_warn(
            self.producer_mapping,
            self.mapping_len,
            "unmapping ring producer/data pages",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_record_len_rounds_up_to_8() {
        assert_eq!(round_record_len(0), 8); // header only
        assert_eq!(round_record_len(1), 16); // 1 + 8 = 9 -> 16
        assert_eq!(round_record_len(8), 16); // 8 + 8 = 16
        assert_eq!(round_record_len(9), 24); // 9 + 8 = 17 -> 24
    }

    #[test]
    fn round_record_len_saturates_without_overflow() {
        // Regression for ringbuf.rs:209: a hostile/corrupt near-usize::MAX
        // data_len must saturate, not wrap/panic in debug on `total + 7`.
        let r = round_record_len(usize::MAX);
        assert_eq!(r, usize::MAX & !7, "largest 8-aligned value, no overflow");
        assert_eq!(r % 8, 0);
        // A value just below the rounding boundary also saturates cleanly.
        assert_eq!(round_record_len(usize::MAX - 8), usize::MAX & !7);
    }

    #[test]
    fn record_within_mapping_accepts_valid_and_rejects_out_of_bounds() {
        let ring = 4096usize; // readable data region = 2*ring = 8192
        // Ordinary record well inside the ring.
        assert!(record_within_mapping(BPF_RINGBUF_HDR_SZ, 100, ring));
        // Exactly at the 2*ring boundary is fine (end == bound).
        assert!(record_within_mapping(0, 2 * ring, ring));
        assert!(record_within_mapping(ring, ring, ring));
        // One byte past the mirror must be rejected.
        assert!(!record_within_mapping(0, 2 * ring + 1, ring));
        assert!(!record_within_mapping(ring + 1, ring, ring));
    }

    #[test]
    fn record_within_mapping_rejects_corrupt_lengths_without_wrapping() {
        // Regression for ringbuf.rs:191 (OOB read): a corrupt header length must
        // be rejected via CHECKED arithmetic, never wrap into a false pass.
        let ring = 4096usize;
        assert!(!record_within_mapping(8, usize::MAX, ring));
        assert!(!record_within_mapping(usize::MAX, 1, ring));
        assert!(!record_within_mapping(usize::MAX, usize::MAX, ring));
        // A pathological ring_size whose double overflows also fails closed.
        assert!(!record_within_mapping(0, 1, usize::MAX));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_ringbuf_rejects_non_power_of_two_sizes() {
        let error = match create_ringbuf(3) {
            Ok(fd) => {
                let _ = unsafe { libc::close(fd) };
                std::io::Error::other(
                    "create_ringbuf unexpectedly accepted a non-power-of-two size",
                )
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_ringbuf_gracefully_handles_kernel_support() {
        match create_ringbuf(4096) {
            Ok(fd) => {
                let close_rc = unsafe { libc::close(fd) };
                assert_eq!(close_rc, 0);
            }
            Err(error) => {
                assert!(
                    matches!(error.raw_os_error(), Some(code) if [
                        libc::EINVAL,
                        libc::EPERM,
                        libc::ENOSYS,
                        libc::EOPNOTSUPP
                    ]
                    .contains(&code)),
                    "unexpected ringbuf create failure: {error}",
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn epoll_wait_retries_on_eintr() {
        extern "C" fn noop_signal_handler(_: libc::c_int) {}

        let efd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        assert!(efd >= 0, "eventfd failed");

        let old = unsafe {
            libc::signal(libc::SIGUSR1, noop_signal_handler as libc::sighandler_t)
        };
        assert!(old != libc::SIG_ERR, "failed to install SIGUSR1 handler");

        let epoll = EpollFd::new().expect("epoll_create1 failed");
        epoll.add(efd).expect("epoll_ctl ADD failed");

        let start = std::time::Instant::now();
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(10));
                let killed = unsafe { libc::kill(libc::getpid(), libc::SIGUSR1) };
                assert!(killed >= 0, "kill(SIGUSR1) failed");
                std::thread::sleep(std::time::Duration::from_millis(10));
                let value = 1u64;
                let written = unsafe {
                    libc::write(
                        efd,
                        std::ptr::addr_of!(value).cast::<libc::c_void>(),
                        std::mem::size_of::<u64>(),
                    )
                };
                assert_eq!(written, std::mem::size_of::<u64>() as isize, "eventfd write failed");
            });
            let result = epoll.wait();
            assert!(result.is_ok(), "epoll_wait should return after EINTR retry: {result:?}");
        });

        let elapsed = start.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_millis(15),
            "wait returned too early (elapsed {elapsed:?}); the EINTR path was likely not exercised"
        );

        unsafe {
            let _ = libc::signal(libc::SIGUSR1, old);
            let _ = libc::close(efd);
        }
    }
}
