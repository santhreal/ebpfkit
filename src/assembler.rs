//! Core eBPF (extended Berkeley Packet Filter) Assembler Primitive.
//!
//! Exposes structures and opcodes to dynamically JIT-compile bytecode
//! programs natively in Rust without wrapping external Clang/LLVM dependencies.
//! This allows instantaneous dynamic generation of ring-0 page drop filters.

#![allow(dead_code)]

use std::fmt;

/// Representation of a single 64-bit eBPF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BpfInsn {
    /// Opcode
    pub code: u8,
    /// Destination register (4 bits) and Source register (4 bits)
    pub regs: u8,
    /// Signed 16-bit offset (used for jumps and memory addressing)
    pub off: i16,
    /// Signed 32-bit immediate value
    pub imm: i32,
}

impl BpfInsn {
    /// Creates a generic Instruction.
    #[must_use]
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (src << 4) | (dst & 0x0F),
            off,
            imm,
        }
    }

    const fn dst_reg(self) -> u8 {
        self.regs & 0x0F
    }

    const fn src_reg(self) -> u8 {
        self.regs >> 4
    }
}

impl fmt::Display for BpfInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let instruction = match self.code {
            code if code == (BPF_JMP | BPF_EXIT) => "exit".to_owned(),
            code if code == (BPF_LDX | BPF_MEM | BPF_B) => {
                format!(
                    "r{} = *(u8 *)(r{} + {})",
                    self.dst_reg(),
                    self.src_reg(),
                    self.off
                )
            }
            code if code == (BPF_LDX | BPF_MEM | BPF_W) => {
                format!(
                    "r{} = *(u32 *)(r{} + {})",
                    self.dst_reg(),
                    self.src_reg(),
                    self.off
                )
            }
            code if code == (BPF_ALU64 | BPF_MOV | BPF_K) => {
                format!("r{} = {}", self.dst_reg(), self.imm)
            }
            code if code == (BPF_ALU64 | BPF_MOV | BPF_X) => {
                format!("r{} = r{}", self.dst_reg(), self.src_reg())
            }
            code if code == (BPF_ALU64 | BPF_ADD | BPF_K) => {
                format!("r{} += {}", self.dst_reg(), self.imm)
            }
            code if code == (BPF_ALU64 | BPF_ADD | BPF_X) => {
                format!("r{} += r{}", self.dst_reg(), self.src_reg())
            }
            code if code == (BPF_JMP | BPF_JA) => format!("goto {:+}", self.off + 1),
            code if code == (BPF_JMP | BPF_JEQ | BPF_K) => format!(
                "if r{} == {} goto {:+}",
                self.dst_reg(),
                self.imm,
                self.off + 1
            ),
            code if code == (BPF_JMP | BPF_JNE | BPF_K) => format!(
                "if r{} != {} goto {:+}",
                self.dst_reg(),
                self.imm,
                self.off + 1
            ),
            code if code == (BPF_JMP | BPF_JGT | BPF_X) => format!(
                "if r{} > r{} goto {:+}",
                self.dst_reg(),
                self.src_reg(),
                self.off + 1
            ),
            code if code == (BPF_JMP | BPF_JLT | BPF_K) => format!(
                "if r{} < {} goto {:+}",
                self.dst_reg(),
                self.imm,
                self.off + 1
            ),
            code if code == (BPF_JMP | BPF_JLE | BPF_K) => format!(
                "if r{} <= {} goto {:+}",
                self.dst_reg(),
                self.imm,
                self.off + 1
            ),
            _ => format!(
                "code=0x{:02x} dst=r{} src=r{} off={} imm={}",
                self.code,
                self.dst_reg(),
                self.src_reg(),
                self.off,
                self.imm
            ),
        };

        f.write_str(&instruction)
    }
}

/// Formats a BPF program into a readable instruction listing.
///
/// Each line is prefixed with the instruction index and the decoded mnemonic.
///
/// # Examples
///
/// ```
/// use ebpfkit::assembler::{format_program, BpfInsn, BPF_EXIT, BPF_JMP};
///
/// let program = [BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)];
/// assert_eq!(format_program(&program), "0000: exit");
/// ```
#[must_use]
pub fn format_program(program: &[BpfInsn]) -> String {
    program
        .iter()
        .enumerate()
        .map(|(index, instruction)| format!("{index:04}: {instruction}"))
        .collect::<Vec<_>>()
        .join("\n")
}

// Memory Operations
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

// Memory Sizes
pub const BPF_B: u8 = 0x10; // Byte
pub const BPF_H: u8 = 0x08; // Half-word (16-bit)
pub const BPF_W: u8 = 0x00; // Word (32-bit)
pub const BPF_DW: u8 = 0x18; // Double-word (64-bit)

// ALU Operations
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xa0;
pub const BPF_MOV: u8 = 0xb0;
pub const BPF_ARSH: u8 = 0xc0;
pub const BPF_END: u8 = 0xd0;

// JMP Operations
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_JSGT: u8 = 0x60;
pub const BPF_JSGE: u8 = 0x70;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;
pub const BPF_JLT: u8 = 0xa0;
pub const BPF_JLE: u8 = 0xb0;
pub const BPF_JSLT: u8 = 0xc0;
pub const BPF_JSLE: u8 = 0xd0;

// Source classes
pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;

// Memory modes
pub const BPF_IMM: u8 = 0x00;
pub const BPF_ABS: u8 = 0x20;
pub const BPF_IND: u8 = 0x40;
pub const BPF_MEM: u8 = 0x60;

// eBPF Registers
pub const R0: u8 = 0; // Return value
pub const R1: u8 = 1; // Context ptr / Arg 1
pub const R2: u8 = 2; // Arg 2
pub const R3: u8 = 3; // Arg 3
pub const R4: u8 = 4; // Arg 4
pub const R5: u8 = 5; // Arg 5
pub const R6: u8 = 6; // Callee saved
pub const R7: u8 = 7; // Callee saved
pub const R8: u8 = 8; // Callee saved
pub const R9: u8 = 9; // Callee saved
pub const R10: u8 = 10; // Frame pointer (read-only)

/// Helper macro for assembling ALU operations with Immediate values.
#[macro_export]
macro_rules! alu64_imm {
    ($op:ident, $dst:ident, $imm:expr) => {
        $crate::assembler::BpfInsn::new(
            $crate::assembler::BPF_ALU64 | $crate::assembler::$op | $crate::assembler::BPF_K,
            $crate::assembler::$dst,
            0,
            0,
            $imm,
        )
    };
}

/// Helper macro for assembling ALU operations with Register sources.
#[macro_export]
macro_rules! alu64_reg {
    ($op:ident, $dst:ident, $src:ident) => {
        $crate::assembler::BpfInsn::new(
            $crate::assembler::BPF_ALU64 | $crate::assembler::$op | $crate::assembler::BPF_X,
            $crate::assembler::$dst,
            $crate::assembler::$src,
            0,
            0,
        )
    };
}

/// Load explicitly from mapped pointers.
#[macro_export]
macro_rules! ldx_mem {
    ($size:ident, $dst:ident, $src:ident, $off:expr) => {
        $crate::assembler::BpfInsn::new(
            $crate::assembler::BPF_LDX | $crate::assembler::BPF_MEM | $crate::assembler::$size,
            $crate::assembler::$dst,
            $crate::assembler::$src,
            $off,
            0,
        )
    };
}

/// Conditional Jumps.
#[macro_export]
macro_rules! jmp_imm {
    ($op:ident, $dst:ident, $imm:expr, $off:expr) => {
        $crate::assembler::BpfInsn::new(
            $crate::assembler::BPF_JMP | $crate::assembler::$op | $crate::assembler::BPF_K,
            $crate::assembler::$dst,
            0,
            $off,
            $imm,
        )
    };
}

#[macro_export]
macro_rules! jmp_reg {
    ($op:ident, $dst:ident, $src:ident, $off:expr) => {
        $crate::assembler::BpfInsn::new(
            $crate::assembler::BPF_JMP | $crate::assembler::$op | $crate::assembler::BPF_X,
            $crate::assembler::$dst,
            $crate::assembler::$src,
            $off,
            0,
        )
    };
}

#[macro_export]
macro_rules! exit {
    () => {
        $crate::assembler::BpfInsn::new(
            $crate::assembler::BPF_JMP | $crate::assembler::BPF_EXIT,
            0,
            0,
            0,
            0,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_instruction_packs_registers() {
        let instruction = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_X, R3, R7, 2, 0);
        assert_eq!(instruction.regs, 0x73);
        assert_eq!(instruction.dst_reg(), R3);
        assert_eq!(instruction.src_reg(), R7);
    }

    #[test]
    fn display_renders_exit() {
        let instruction = BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
        assert_eq!(instruction.to_string(), "exit");
    }

    #[test]
    fn display_renders_word_load() {
        let instruction = BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, R2, R1, 4, 0);
        assert_eq!(instruction.to_string(), "r2 = *(u32 *)(r1 + 4)");
    }

    #[test]
    fn display_renders_move_immediate() {
        let instruction = BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 1);
        assert_eq!(instruction.to_string(), "r0 = 1");
    }

    #[test]
    fn display_renders_add_register() {
        let instruction = BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_X, R5, R4, 0, 0);
        assert_eq!(instruction.to_string(), "r5 += r4");
    }

    #[test]
    fn display_renders_conditional_jump_with_immediate() {
        let instruction = BpfInsn::new(BPF_JMP | BPF_JNE | BPF_K, R7, 0, 3, 255);
        assert_eq!(instruction.to_string(), "if r7 != 255 goto +4");
    }

    #[test]
    fn display_renders_conditional_jump_with_register() {
        let instruction = BpfInsn::new(BPF_JMP | BPF_JGT | BPF_X, R6, R3, 8, 0);
        assert_eq!(instruction.to_string(), "if r6 > r3 goto +9");
    }

    #[test]
    fn display_falls_back_for_unknown_opcode() {
        let instruction = BpfInsn::new(0xff, R1, R2, -1, 42);
        assert_eq!(
            instruction.to_string(),
            "code=0xff dst=r1 src=r2 off=-1 imm=42"
        );
    }

    #[test]
    fn format_program_lists_each_instruction() {
        let program = [
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 1),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        assert_eq!(format_program(&program), "0000: r0 = 1\n0001: exit");
    }
}
