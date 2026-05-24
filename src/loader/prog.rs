use crate::assembler::BpfInsn;
use std::os::unix::io::RawFd;

use super::SYS_BPF;

const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;

/// Maximum BPF program instructions the verifier accepts.
const MAX_BPF_INSNS: usize = 4096;

#[repr(C)]
#[derive(Default)]
struct BpfAttrProgLoad {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
}

/// Injects a dynamically compiled JIT bytecode array deep into the kernel.
///
/// Returns the Raw File Descriptor representing the active verified filter program.
/// This FD can then be locked onto sockets or natively bound to `io_uring` drops.
pub fn load_filter(insns: &[BpfInsn]) -> Result<RawFd, std::io::Error> {
    if insns.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "BPF program is empty. Fix: provide at least one instruction.",
        ));
    }
    if insns.len() > MAX_BPF_INSNS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "BPF program has {} instructions, exceeding the {MAX_BPF_INSNS}-instruction verifier limit. Fix: simplify the pattern or split into multiple programs.",
                insns.len()
            ),
        ));
    }
    let insn_cnt = u32::try_from(insns.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "BPF instruction count exceeds u32. Fix: reduce program size.",
        )
    })?;
    let license = b"GPL\0";

    let attr = BpfAttrProgLoad {
        prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
        insn_cnt,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        ..Default::default()
    };

    // SAFETY: The syscall transfers boundaries correctly to the kernel BPF verifier.
    let fd = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_PROG_LOAD,
            &attr as *const BpfAttrProgLoad,
            std::mem::size_of::<BpfAttrProgLoad>(),
        )
    };

    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(fd as RawFd)
}

/// Dynamically attaches the loaded eBPF prog FD to an active raw socket file descriptor.
pub fn attach_to_socket(prog_fd: RawFd, socket_fd: RawFd) -> Result<(), std::io::Error> {
    const SO_ATTACH_BPF: libc::c_int = 50;

    // SAFETY: Both file descriptors are valid (caller contract). The prog_fd
    // pointer is a stack reference valid for the duration of the syscall.
    let res = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            SO_ATTACH_BPF,
            &prog_fd as *const _ as *const libc::c_void,
            std::mem::size_of::<RawFd>() as libc::socklen_t,
        )
    };

    if res < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}
