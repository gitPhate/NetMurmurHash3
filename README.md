# NetMurmurHash3

MurmurHash3 for .NET 8 and .NET 10, with an API modeled on `System.IO.Hashing` (`XxHash32`, `XxHash128`).

| Class | Variant | Output |
|---|---|---|
| `MurmurHash3x86_32` | x86_32 | 4 bytes, or `uint` |
| `MurmurHash3x64_128` | x64_128 | 16 bytes, or `UInt128` |

Both derive from `NonCryptographicHashAlgorithm`, take an optional `uint` seed (default 0), and match the reference C++ output byte for byte. Not for cryptographic use.

## Usage

```csharp
using NetMurmurHash3;

// One-shot
byte[] hash = MurmurHash3x64_128.Hash(data);
uint h32 = MurmurHash3x86_32.HashToUInt32(data, seed: 42);
UInt128 h128 = MurmurHash3x64_128.HashToUInt128(data);

// Into a span, without allocating
bool ok = MurmurHash3x64_128.TryHash(data, destination, out int written);

// Incremental
MurmurHash3x86_32 hasher = new MurmurHash3x86_32();
hasher.Append(chunk1);
hasher.Append(chunk2);
uint result = hasher.GetCurrentHashAsUInt32();
```

## Notes

- The total length is mixed in as 64 bits. The reference takes an `int`, so results match it for inputs up to `int.MaxValue` bytes; longer incremental inputs have no reference counterpart.
- 128-bit output is h1 then h2, each little-endian, as in the reference. `HashToUInt128` returns h2 as the upper and h1 as the lower 64 bits.

## Benchmarks

```
BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.9550/25H2/2025Update/HudsonValley2)
Intel Core i9-10885H CPU 2.40GHz, 1 CPU, 16 logical and 8 physical cores
.NET SDK 10.0.401
  [Host]     : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3
  DefaultJob : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3
```

Inputs are random bytes (fixed seed 42). Ratio is relative to NetMurmurHash3 in each group. `XxHash32` and `XxHash128` from `System.IO.Hashing` are not MurmurHash3; they are included as a reference point.

### x86_32

[JeremyEspresso/MurmurHash](https://github.com/JeremyEspresso/MurmurHash) (v0.0.1) and [darrenkopp/murmurhash-net](https://github.com/darrenkopp/murmurhash-net) as `DarrenKopp`. DarrenKopp goes through `HashAlgorithm.ComputeHash` and returns a `byte[]`.

JeremyEspresso's code is compiled into the benchmark project rather than referenced as a package. Its NuGet package ships `MurmurHash.dll`, the same assembly name as darrenkopp's package, so the two can't be loaded in one process.

| Method                | Length  |           Mean | Ratio | Allocated |
|-----------------------|---------|---------------:|------:|----------:|
| NetMurmurHash3        | 16      |       4.455 ns |  1.00 |         - |
| JeremyEspresso_Hash32 | 16      |       4.776 ns |  1.07 |         - |
| DarrenKopp_Murmur32   | 16      |      57.279 ns | 12.87 |      64 B |
| XxHash32_reference    | 16      |       3.539 ns |  0.80 |         - |
| NetMurmurHash3        | 1024    |     256.060 ns |  1.00 |         - |
| JeremyEspresso_Hash32 | 1024    |     264.790 ns |  1.03 |         - |
| DarrenKopp_Murmur32   | 1024    |     521.054 ns |  2.04 |      64 B |
| XxHash32_reference    | 1024    |     119.045 ns |  0.47 |         - |
| NetMurmurHash3        | 1048576 | 273,467.376 ns |  1.00 |         - |
| JeremyEspresso_Hash32 | 1048576 | 293,286.643 ns |  1.07 |         - |
| DarrenKopp_Murmur32   | 1048576 | 478,622.413 ns |  1.75 |      64 B |
| XxHash32_reference    | 1048576 | 126,829.749 ns |  0.46 |         - |

### x64_128

| Method                   | Length  |           Mean | Ratio | Allocated |
|--------------------------|---------|---------------:|------:|----------:|
| NetMurmurHash3           | 16      |       9.258 ns |  1.00 |      40 B |
| DarrenKopp_Murmur128_x64 | 16      |      82.803 ns |  8.96 |     144 B |
| XxHash128_reference      | 16      |       9.283 ns |  1.00 |      40 B |
| NetMurmurHash3           | 1024    |     125.015 ns |  1.00 |      40 B |
| DarrenKopp_Murmur128_x64 | 1024    |     448.469 ns |  3.59 |     144 B |
| XxHash128_reference      | 1024    |      43.347 ns |  0.35 |      40 B |
| NetMurmurHash3           | 1048576 | 122,897.052 ns |  1.00 |      40 B |
| DarrenKopp_Murmur128_x64 | 1048576 | 398,543.178 ns |  3.24 |     144 B |
| XxHash128_reference      | 1048576 |  36,995.998 ns |  0.30 |      40 B |

## History
This project is born because Claude accidentally created an implementation of the x64_128 version of the algorithm while I was working for another project, because the base class implementation `NonCryptographicHashAlgorithm` was needed.

I then decided to expand it and create a separated project for that, which turned out to be super fast.