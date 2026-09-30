using BenchmarkDotNet.Running;
using NetMurmurHash3.Benchmarks;

BenchmarkRunner.Run<HashBenchmarks>(args: args);
