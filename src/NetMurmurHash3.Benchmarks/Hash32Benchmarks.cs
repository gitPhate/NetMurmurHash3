using BenchmarkDotNet.Attributes;
using System.IO.Hashing;
using System.Security.Cryptography;

namespace NetMurmurHash3.Benchmarks
{
    [MemoryDiagnoser]
    public class Hash32Benchmarks
    {
        [Params(16, 1024, 1024 * 1024)]
        public int Length { get; set; }

        private byte[] _input = [];
        private readonly HashAlgorithm _darrenKopp = Murmur.MurmurHash.Create32(0, true);

        [GlobalSetup]
        public void Setup()
        {
            _input = new byte[Length];
            new Random(42).NextBytes(_input);
        }

        [Benchmark(Baseline = true)]
        public uint NetMurmurHash3() => MurmurHash3x86_32.HashToUInt32(_input);

        // https://github.com/JeremyEspresso/MurmurHash, vendored (see JeremyEspresso/MurmurHash3.cs for why)
        [Benchmark]
        public uint JeremyEspresso_Hash32()
        {
            ReadOnlySpan<byte> input = _input;
            return JeremyEspresso.MurmurHash3.Hash32(ref input, 0);
        }

        // https://github.com/darrenkopp/murmurhash-net
        [Benchmark]
        public byte[] DarrenKopp_Murmur32() => _darrenKopp.ComputeHash(_input);

        [Benchmark]
        public uint XxHash32_reference() => XxHash32.HashToUInt32(_input);
    }
}
