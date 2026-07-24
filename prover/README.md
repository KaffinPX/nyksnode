# Prover

**nyks-prover** is a standalone prover process for generating Triton VM STARK proofs. It reads its inputs from `stdin` and writes the serialized proof to `stdout`.

## Building

For the best proving throughput, build with:

```bash
RUSTFLAGS="-C target-cpu=native" \
cargo build --profile perf --bin nyks-prover --features mimalloc
```

### `target-cpu=native`

`target-cpu=native` allows LLVM to generate code optimized for the CPU it is built on, which can noticeably improve proving performance.

It is **not enabled by default** because the resulting binary is no longer portable, it may not run on machines with different CPU capabilities.

### `mimalloc`

The optional `mimalloc` feature replaces the system allocator with `mimalloc`, which typically performs better for the allocation patterns encountered during proof generation.

It is **not enabled by default** so downstream users can choose their preferred allocator.
