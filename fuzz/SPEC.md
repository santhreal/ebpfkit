# ebpfkit-fuzz — Technical Spec

## Overview

ebpfkit-fuzz crate.

## Architecture

Public modules:

- (see source)

## Guarantees

- `#![forbid(unsafe_code)]` where applicable.
- All public types are documented.

## Public API Summary

See `src/lib.rs` re-exports and module-level documentation for function signatures.

## Error Handling

- Standard `Result` / error types.
