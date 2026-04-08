use crate::assembler::{BpfInsn, BPF_JMP, BPF_K, BPF_X};
use crate::assembler::{BPF_JA, R0};

pub(super) fn jump_offset(from: usize, to: usize) -> i16 {
    (to as isize - from as isize - 1) as i16
}

pub(crate) fn patch_match_jump(program: &mut [BpfInsn], from: usize, match_idx: usize) {
    program[from] = BpfInsn::new(BPF_JMP | BPF_JA, R0, 0, jump_offset(from, match_idx), 0);
}

pub(crate) fn patch_reg_jump(
    program: &mut [BpfInsn],
    from: usize,
    to: usize,
    dst: u8,
    src: u8,
    op: u8,
) {
    program[from] = BpfInsn::new(BPF_JMP | op | BPF_X, dst, src, jump_offset(from, to), 0)
}

pub(crate) fn patch_imm_jump(
    program: &mut [BpfInsn],
    from: usize,
    to: usize,
    dst: u8,
    imm: i32,
    op: u8,
) {
    program[from] = BpfInsn::new(BPF_JMP | op | BPF_K, dst, 0, jump_offset(from, to), imm)
}
