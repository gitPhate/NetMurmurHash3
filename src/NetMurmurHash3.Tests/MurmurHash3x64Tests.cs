using FluentAssertions;
using NetMurmurHash3;
using NetMurmurHash3.Tests.Support;
using System.Text;

namespace NetMurmurHash3.Tests
{
    public class MurmurHash3x64Tests
    {
        // Pattern bytes whose prefixes are hashed below; expected values generated with the Python mmh3 package (hash_bytes, seed 0).
        private static readonly byte[] Pattern = Enumerable.Range(0, 64).Select(i => (byte)((i * 31 + 7) & 0xFF)).ToArray();

        private static string Hex(byte[] bytes) => Convert.ToHexString(bytes);

        [Theory]
        [InlineData("", "00000000000000000000000000000000")]
        [InlineData("hello", "029BBD41B3A7D8CB191DAE486A901E5B")]
        [InlineData("The quick brown fox jumps over the lazy dog", "6C1B07BC7BBC4BE347939AC4A93C437A")]
        public void Hash_matches_reference_for_ascii_strings(string input, string expectedHex)
        {
            Hex(MurmurHash3x64_128.Hash(Encoding.ASCII.GetBytes(input))).Should().Be(expectedHex);
        }

        [Fact]
        public void Hash_with_seed_matches_reference()
        {
            Hex(MurmurHash3x64_128.Hash(Encoding.ASCII.GetBytes("hello"), 42)).Should().Be("086FAF60C9B3B8C47ABCEFB075B83423");
        }

        [Fact]
        public void HashToUInt128_has_h1_as_lower_and_h2_as_upper_half()
        {
            // "hello" hashes to h1 bytes 029BBD41B3A7D8CB and h2 bytes 191DAE486A901E5B, each little-endian.
            MurmurHash3x64_128.HashToUInt128(Encoding.ASCII.GetBytes("hello"))
                .Should().Be(new UInt128(0x5B1E906A48AE1D19UL, 0xCBD8A7B341BD9B02UL));
        }

        [Fact]
        public void GetCurrentHashAsUInt128_matches_HashToUInt128()
        {
            MurmurHash3x64_128 hasher = new(42);
            hasher.Append(Pattern.AsSpan(0, 20));
            hasher.Append(Pattern.AsSpan(20, 13));

            hasher.GetCurrentHashAsUInt128().Should().Be(MurmurHash3x64_128.HashToUInt128(Pattern.AsSpan(0, 33), 42));
        }

        [Fact]
        public void Hash_into_destination_writes_16_bytes_and_leaves_the_rest()
        {
            byte[] destination = Enumerable.Repeat((byte)0xAA, 20).ToArray();

            int written = MurmurHash3x64_128.Hash(Pattern.AsSpan(0, 33), destination, 42);

            written.Should().Be(16);
            destination.Take(16).Should().Equal(MurmurHash3x64_128.Hash(Pattern.AsSpan(0, 33), 42));
            destination.Skip(16).Should().AllBeEquivalentTo((byte)0xAA);
        }

        [Fact]
        public void Hash_into_short_destination_throws()
        {
            Action act = () => MurmurHash3x64_128.Hash(Pattern, new byte[15]);

            act.Should().Throw<ArgumentException>().WithParameterName("destination");
        }

        [Fact]
        public void TryHash_into_short_destination_returns_false_and_writes_nothing()
        {
            byte[] destination = new byte[15];

            MurmurHash3x64_128.TryHash(Pattern, destination, out int written).Should().BeFalse();

            written.Should().Be(0);
            destination.Should().OnlyContain(b => b == 0);
        }

        [Fact]
        public void TryHash_matches_Hash()
        {
            byte[] destination = new byte[16];

            MurmurHash3x64_128.TryHash(Pattern, destination, out int written, 42).Should().BeTrue();

            written.Should().Be(16);
            destination.Should().Equal(MurmurHash3x64_128.Hash(Pattern, 42));
        }

        [Fact]
        public void Hash_into_destination_does_not_allocate()
        {
            byte[] data = TestData.Bytes(100);
            byte[] destination = new byte[16];
            MurmurHash3x64_128.Hash(data, destination);

            long before = GC.GetAllocatedBytesForCurrentThread();
            MurmurHash3x64_128.Hash(data, destination);

            (GC.GetAllocatedBytesForCurrentThread() - before).Should().Be(0);
        }

        [Fact]
        public void Reset_restores_seeded_state()
        {
            MurmurHash3x64_128 hasher = new(42);
            hasher.Append(Pattern.AsSpan(0, 20));
            hasher.Reset();
            hasher.Append(Pattern.AsSpan(0, 20));
            hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(Pattern.AsSpan(0, 20), 42));
        }

        // Lengths cover every tail branch (0, 1..8, 9..15) with zero, one and several full 16-byte blocks.
        [Theory]
        [InlineData(1, "17BD72899D9027C4DD99B1452A70155C")]
        [InlineData(2, "90F5777B245DAABCEED7327FC8E89B2B")]
        [InlineData(3, "3BA2A04DDA6EFF33FB3A3CD98B5E905F")]
        [InlineData(4, "B4A3373991951133661D61DB45082E64")]
        [InlineData(5, "0FE0388754324363FC8AAD335C8E3605")]
        [InlineData(6, "40C1D5AA6D24B772368D240CEF8C7412")]
        [InlineData(7, "1CB9D9C2FCFD143F4F20F19810FDEB01")]
        [InlineData(8, "5DAFA33E0C1327D932687EFBB44CABEE")]
        [InlineData(9, "E43BFBFBF3430F32A2F746D02D1773A3")]
        [InlineData(10, "97807E5E9D5B19FA4A8ECD4E4343B0D3")]
        [InlineData(11, "12E7EC2E20449A091DFDBE3CCD1F4C43")]
        [InlineData(12, "04BFEFF933C9F046F508E142FC4C994D")]
        [InlineData(13, "C4B3B087C7C6B8E5A7C012FD52D1FFB5")]
        [InlineData(14, "D58692FD93BB2E67060C595ACCD4A615")]
        [InlineData(15, "17AB8267B5F475375E412BB1809D296C")]
        [InlineData(16, "14DA89F6EB796B468A8505B8028B548C")]
        [InlineData(17, "24E59D30842F32EB1B4828271FA02A08")]
        [InlineData(31, "69059632DA93DB491E6CDC33601EB290")]
        [InlineData(32, "326112A8CE3886422E5D152A511DCAF0")]
        [InlineData(33, "EBCD309230C70BFA642153960CC72137")]
        [InlineData(64, "F0C58C1AF19DD01C9D8CD7D53442BE55")]
        public void Hash_matches_reference_for_block_and_tail_lengths(int length, string expectedHex)
        {
            Hex(MurmurHash3x64_128.Hash(Pattern.AsSpan(0, length))).Should().Be(expectedHex);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(3)]
        [InlineData(15)]
        [InlineData(16)]
        [InlineData(17)]
        [InlineData(100)]
        public void Incremental_append_in_fixed_chunks_matches_one_shot(int chunkSize)
        {
            byte[] data = TestData.Bytes(1003);
            MurmurHash3x64_128 hasher = new();

            for (int offset = 0; offset < data.Length; offset += chunkSize)
            {
                hasher.Append(data.AsSpan(offset, Math.Min(chunkSize, data.Length - offset)));
            }

            hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(data));
        }

        [Fact]
        public void Incremental_single_append_matches_one_shot_for_every_length()
        {
            for (int length = 0; length <= Pattern.Length; length++)
            {
                MurmurHash3x64_128 hasher = new(42);
                hasher.Append(Pattern.AsSpan(0, length));

                hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(Pattern.AsSpan(0, length), 42), $"length {length}");
            }
        }

        [Fact]
        public void Hash_allocates_only_the_result_array()
        {
            byte[] data = TestData.Bytes(100);
            MurmurHash3x64_128.Hash(data);

            long before = GC.GetAllocatedBytesForCurrentThread();
            byte[] hash = MurmurHash3x64_128.Hash(data);
            long hashAllocated = GC.GetAllocatedBytesForCurrentThread() - before;

            before = GC.GetAllocatedBytesForCurrentThread();
            byte[] array = new byte[hash.Length];
            long arrayAllocated = GC.GetAllocatedBytesForCurrentThread() - before;

            hashAllocated.Should().Be(arrayAllocated);
            GC.KeepAlive(array);
        }

        [Fact]
        public void Incremental_append_in_random_chunks_matches_one_shot()
        {
            byte[] data = TestData.Bytes(5000);
            Random random = new(42);
            MurmurHash3x64_128 hasher = new();

            int offset = 0;
            while (offset < data.Length)
            {
                int size = Math.Min(random.Next(0, 40), data.Length - offset);
                hasher.Append(data.AsSpan(offset, size));
                offset += size;
            }

            hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(data));
        }

        [Fact]
        public void Stale_pending_bytes_do_not_leak_into_the_tail()
        {
            // 15 + 1 fills and flushes the pending block, leaving its old bytes behind; the 2-byte tail must ignore them.
            MurmurHash3x64_128 hasher = new();
            hasher.Append(Pattern.AsSpan(0, 15));
            hasher.Append(Pattern.AsSpan(15, 1));
            hasher.Append(Pattern.AsSpan(16, 2));

            Hex(hasher.GetCurrentHash()).Should().Be("9E5F2E48DA90B244F61BCD23380AC584");
        }

        [Fact]
        public void Empty_appends_do_not_change_the_hash()
        {
            MurmurHash3x64_128 hasher = new();
            hasher.Append([]);
            hasher.Append(Pattern.AsSpan(0, 9));
            hasher.Append([]);

            hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(Pattern.AsSpan(0, 9)));
        }

        [Fact]
        public void GetCurrentHash_does_not_alter_state()
        {
            MurmurHash3x64_128 hasher = new();
            hasher.Append(Pattern.AsSpan(0, 20));

            byte[] first = hasher.GetCurrentHash();
            byte[] second = hasher.GetCurrentHash();
            hasher.Append(Pattern.AsSpan(20, 13));

            second.Should().Equal(first);
            first.Should().Equal(MurmurHash3x64_128.Hash(Pattern.AsSpan(0, 20)));
            hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(Pattern.AsSpan(0, 33)));
        }

        [Fact]
        public void Fresh_hasher_returns_empty_input_hash()
        {
            new MurmurHash3x64_128().GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash([]));
        }

        [Fact]
        public void Trailing_zero_bytes_change_the_hash()
        {
            // Length is mixed into finalization, so zero padding must not collide.
            MurmurHash3x64_128.Hash(new byte[5]).Should().NotEqual(MurmurHash3x64_128.Hash(new byte[6]));
        }
    }
}
