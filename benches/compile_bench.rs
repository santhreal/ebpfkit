#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ebpfkit::compiler::compile_literal_search;

fn usize_to_u8(value: usize) -> u8 {
    u8::try_from(value).unwrap_or(0)
}

fn ascii_pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| b'a' + usize_to_u8(index % 26))
        .collect()
}

fn binary_pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| usize_to_u8((index * 37 + 11) % 251))
        .collect()
}

fn bench_compile_ascii(c: &mut Criterion) {
    let mut group = c.benchmark_group("compile_literal_search_ascii");
    for size in [4_usize, 16, 64] {
        let pattern = ascii_pattern(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &pattern, |b, pattern| {
            b.iter(|| {
                let _ = compile_literal_search(pattern);
            });
        });
    }
    group.finish();
}

fn bench_compile_binary(c: &mut Criterion) {
    let mut group = c.benchmark_group("compile_literal_search_binary");
    for size in [4_usize, 16, 64] {
        let pattern = binary_pattern(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &pattern, |b, pattern| {
            b.iter(|| {
                let _ = compile_literal_search(pattern);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_compile_ascii, bench_compile_binary);
criterion_main!(benches);
