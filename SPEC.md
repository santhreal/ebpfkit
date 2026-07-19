# ebpfkit: Technical Spec

## Overview

`ebpfkit`: High-Performance JIT eBPF Compilation and Filtering  Exposes a zero-dependency, bare-metal BPF compiler to bridge string constraints dynamically into kernel ring-0 operations.  It absolutely blitzes userspace tools like Ripgrep by discarding non-matching hardware pages before they ever cross the NVMe-to-Userspace DMA boundaries.  **Platform:** Linux only. This crate requires eBPF support which is a Linux kernel feature. On non-Linux platforms, the crate compiles but all public functions return errors.

## Architecture

The crate is organized into the following public modules:

- `assembler`
- `compiler`
- `loader`

## Guarantees

- `#![forbid(unsafe_code)]` where applicable; see `src/lib.rs` for the exact lint preamble.
- All public types have doc comments.
- Error messages are actionable where applicable.

## Public API Summary

Key entry points are exported from `src/lib.rs` via `pub mod` and `pub use` re-exports.
Consult the module-level documentation in each source file for function signatures and usage examples.

## Error Handling

- `AttachError`
