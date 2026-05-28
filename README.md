# ebpfkit

Part of [Santh](https://santh.dev) - open source Rust security and infrastructure tooling. Follow [@SanthProject](https://x.com/SanthProject) on X.

Kernel-Space eBPF Just-In-Time Pipeline Filter Compiler

`ebpfkit` — High-Performance JIT eBPF Compilation and Filtering

Exposes a zero-dependency, bare-metal BPF compiler to bridge string
constraints dynamically into kernel ring-0 operations.

It absolutely blitzes userspace tools like Ripgrep by discarding non-matching
hardware pages before they ever cross the NVMe-to-Userspace DMA boundaries.

**Platform:** Linux only. This crate requires eBPF support which is a Linux
kernel feature. On non-Linux platforms, the crate compiles but all public
functions return errors.

## License

MIT OR Apache-2.0
