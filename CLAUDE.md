# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

MurmurHash3 for .NET 8 and .NET 10 (library multi-targets both). Two sealed classes, `MurmurHash3x86_32` and `MurmurHash3x64_128`, derive from `System.IO.Hashing.NonCryptographicHashAlgorithm` and mirror the `XxHash32`/`XxHash128` API (static `Hash`/`TryHash`/`HashToUInt*`, plus incremental `Append`/`GetCurrentHash*`). Output must match the reference C++ byte for byte.

## Layout

Everything lives under `src/` (solution: `src/NetMurmurHash3.slnx`):

- `NetMurmurHash3/`: the library (one file per variant, no shared base).
- `NetMurmurHash3.Tests/`: xUnit tests, run on `Microsoft.Testing.Platform` (set in `global.json`). `Support/TestData.cs` generates deterministic random bytes.
- `NetMurmurHash3.Benchmarks/`: BenchmarkDotNet comparisons. `JeremyEspresso/MurmurHash3.cs` is third-party code compiled in on purpose, because its NuGet package has the same assembly name as darrenkopp's and the two can't load together.

## Implementation notes

- The one-shot path (`HashCore`) and the incremental path (`Append`/`GetCurrentHash`) share the same `MixBlocks` and `Finish` helpers. Keep them in sync; don't fork the logic.
- The code is tuned for per-call cost on short inputs: `ref byte`/`Unsafe` instead of slicing and indexing, `[AggressiveInlining]`, state held in locals inside loops, byte-wise tail assembly. Don't "simplify" these back to spans or indexers without benchmarking.
- Total length is mixed in as 64 bits (the reference uses `int`), so output matches the reference only up to `int.MaxValue` bytes.
- 128-bit output is h1 then h2, each little-endian. `HashToUInt128` puts h2 in the upper and h1 in the lower 64 bits.
- Big-endian hosts are handled with `BitConverter.IsLittleEndian` checks on block reads.

## Unit tests

- Aim for 100% behavior coverage, not 100% code coverage.
- Follow Arrange, Act, Assert in every test.
- Name test classes `<Domain>ServiceShould`.
