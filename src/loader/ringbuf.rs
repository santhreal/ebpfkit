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
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    usize::try_from(value).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "system page size does not fit in usize. Fix: run on a supported userspace architecture.",
        )
    })
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
                callback(consumer.data_slice(data_offset, data_len));
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

fn round_record_len(data_len: usize) -> usize {
    let total = data_len.saturating_add(BPF_RINGBUF_HDR_SZ);
    (total + 7) & !7
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
        let rc = unsafe { libc::epoll_wait(self.0, &mut event, 1, -1) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for EpollFd {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.0) };
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
            let _ = unsafe { libc::munmap(consumer_mapping, page_size) };
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

    fn data_slice(&self, offset: usize, len: usize) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data_ptr.add(offset), len) }
    }
}

impl Drop for RingbufConsumer {
    fn drop(&mut self) {
        let _ = unsafe { libc::munmap(self.consumer_mapping, self.page_size) };
        let _ = unsafe { libc::munmap(self.producer_mapping, self.mapping_len) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
