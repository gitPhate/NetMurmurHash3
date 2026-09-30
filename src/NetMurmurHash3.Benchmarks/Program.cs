using BenchmarkDotNet.Running;
using NetMurmurHash3.Benchmarks;

BenchmarkSwitcher.FromAssembly(typeof(HashBenchmarks).Assembly).Run(args);
