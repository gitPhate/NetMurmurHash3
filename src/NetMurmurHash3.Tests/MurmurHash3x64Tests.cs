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
            Hex(MurmurHash3x64.Hash(Encoding.ASCII.GetBytes(input))).Should().Be(expectedHex);
        }

        [Fact]
        public void Hash_with_seed_matches_reference()
        {
            Hex(MurmurHash3x64.Hash(Encoding.ASCII.GetBytes("hello"), 42)).Should().Be("086FAF60C9B3B8C47ABCEFB075B83423");
        }

        [Fact]
        public void Reset_restores_seeded_state()
        {
            MurmurHash3x64 hasher = new(42);
            hasher.Append(Pattern.AsSpan(0, 20));
            hasher.Reset();
            hasher.Append(Pattern.AsSpan(0, 20));
            hasher.GetCurrentHash().Should().Equal(MurmurHash3x64.Hash(Pattern.AsSpan(0, 20), 42));
        }

        // Lengths cover every tail branch (0, 1..8, 9..15) with zero, one and several full 16-byte blocks.
        [Theory]
        [InlineData(1, "17BD72899D9027C4DD99B1452A70155C")]
        [InlineData(7, "1CB9D9C2FCFD143F4F20F19810FDEB01")]
        [InlineData(8, "5DAFA33E0C1327D932687EFBB44CABEE")]
        [InlineData(9, "E43BFBFBF3430F32A2F746D02D1773A3")]
        [InlineData(15, "17AB8267B5F475375E412BB1809D296C")]
        [InlineData(16, "14DA89F6EB796B468A8505B8028B548C")]
        [InlineData(17, "24E59D30842F32EB1B4828271FA02A08")]
        [InlineData(31, "69059632DA93DB491E6CDC33601EB290")]
        [InlineData(32, "326112A8CE3886422E5D152A511DCAF0")]
        [InlineData(33, "EBCD309230C70BFA642153960CC72137")]
        [InlineData(64, "F0C58C1AF19DD01C9D8CD7D53442BE55")]
        public void Hash_matches_reference_for_block_and_tail_lengths(int length, string expectedHex)
        {
            Hex(MurmurHash3x64.Hash(Pattern.AsSpan(0, length))).Should().Be(expectedHex);
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
            MurmurHash3x64 hasher = new();

            for (int offset = 0; offset < data.Length; offset += chunkSize)
            {
                hasher.Append(data.AsSpan(offset, Math.Min(chunkSize, data.Length - offset)));
            }

            hasher.GetCurrentHash().Should().Equal(MurmurHash3x64.Hash(data));
        }

        [Fact]
        public void Incremental_append_in_random_chunks_matches_one_shot()
        {
            byte[] data = TestData.Bytes(5000);
            Random random = new(42);
            MurmurHash3x64 hasher = new();

            int offset = 0;
            while (offset < data.Length)
            {
                int size = Math.Min(random.Next(0, 40), data.Length - offset);
                hasher.Append(data.AsSpan(offset, size));
                offset += size;
            }

            hasher.GetCurrentHash().Should().Equal(MurmurHash3x64.Hash(data));
        }

        [Fact]
        public void Empty_appends_do_not_change_the_hash()
        {
            MurmurHash3x64 hasher = new();
            hasher.Append([]);
            hasher.Append(Pattern.AsSpan(0, 9));
            hasher.Append([]);

            hasher.GetCurrentHash().Should().Equal(MurmurHash3x64.Hash(Pattern.AsSpan(0, 9)));
        }

        [Fact]
        public void GetCurrentHash_does_not_alter_state()
        {
            MurmurHash3x64 hasher = new();
            hasher.Append(Pattern.AsSpan(0, 20));

            byte[] first = hasher.GetCurrentHash();
            byte[] second = hasher.GetCurrentHash();
            hasher.Append(Pattern.AsSpan(20, 13));

            second.Should().Equal(first);
            first.Should().Equal(MurmurHash3x64.Hash(Pattern.AsSpan(0, 20)));
            hasher.GetCurrentHash().Should().Equal(MurmurHash3x64.Hash(Pattern.AsSpan(0, 33)));
        }

        [Fact]
        public void Fresh_hasher_returns_empty_input_hash()
        {
            new MurmurHash3x64().GetCurrentHash().Should().Equal(MurmurHash3x64.Hash([]));
        }

        [Fact]
        public void Trailing_zero_bytes_change_the_hash()
        {
            // Length is mixed into finalization, so zero padding must not collide.
            MurmurHash3x64.Hash(new byte[5]).Should().NotEqual(MurmurHash3x64.Hash(new byte[6]));
        }
    }
}
