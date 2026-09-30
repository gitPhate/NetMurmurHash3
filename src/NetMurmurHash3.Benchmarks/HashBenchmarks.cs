using BenchmarkDotNet.Attributes;
using System.IO.Hashing;
using System.Security.Cryptography;

namespace NetMurmurHash3.Benchmarks
{
    [MemoryDiagnoser]
    public class HashBenchmarks
    {
        [Params(16, 1024, 1024 * 1024)]
        public int Length { get; set; }

        private byte[] _input = [];
        private readonly HashAlgorithm _darrenKopp = Murmur.MurmurHash.Create128(0, true, Murmur.AlgorithmPreference.X64);

        [GlobalSetup]
        public void Setup()
        {
            _input = new byte[Length];
            new Random(42).NextBytes(_input);
        }

        [Benchmark(Baseline = true)]
        public byte[] NetMurmurHash3() => MurmurHash3x64_128.Hash(_input);

        // https://github.com/darrenkopp/murmurhash-net
        [Benchmark]
        public byte[] DarrenKopp_Murmur128_x64() => _darrenKopp.ComputeHash(_input);

        [Benchmark]
        public byte[] XxHash128_reference() => XxHash128.Hash(_input);
    }
}
