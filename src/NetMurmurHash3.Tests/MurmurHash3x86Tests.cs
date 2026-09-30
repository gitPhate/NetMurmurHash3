using FluentAssertions;
using NetMurmurHash3.Tests.Support;
using System.Text;

namespace NetMurmurHash3.Tests
{
    public class MurmurHash3x86Tests
    {
        // Pattern bytes whose prefixes are hashed below; expected values generated with the Python mmh3 package (hash, unsigned, written little-endian).
        private static readonly byte[] Pattern = Enumerable.Range(0, 64).Select(i => (byte)((i * 31 + 7) & 0xFF)).ToArray();

        private static string Hex(byte[] bytes) => Convert.ToHexString(bytes);

        [Theory]
        [InlineData("", "00000000")]
        [InlineData("hello", "47FA8B24")]
        [InlineData("The quick brown fox jumps over the lazy dog", "23F74F2E")]
        public void Hash_matches_reference_for_ascii_strings(string input, string expectedHex)
        {
            Hex(MurmurHash3x86_32.Hash(Encoding.ASCII.GetBytes(input))).Should().Be(expectedHex);
        }

        [Fact]
        public void Hash_with_seed_matches_reference()
        {
            Hex(MurmurHash3x86_32.Hash(Encoding.ASCII.GetBytes("hello"), 42)).Should().Be("E1D2DBE2");
        }

        [Fact]
        public void HashToUInt32_is_the_little_endian_reading_of_Hash()
        {
            MurmurHash3x86_32.HashToUInt32(Encoding.ASCII.GetBytes("hello")).Should().Be(0x248BFA47U);
        }

        [Fact]
        public void HashToUInt32_matches_JeremyEspresso_readme_example()
        {
            MurmurHash3x86_32.HashToUInt32(Encoding.UTF8.GetBytes("Hello World!"), 420).Should().Be(1535517821U);
        }

        [Fact]
        public void GetCurrentHashAsUInt32_matches_HashToUInt32()
        {
            MurmurHash3x86_32 hasher = new(42);
            hasher.Append(Pattern.AsSpan(0, 6));
            hasher.Append(Pattern.AsSpan(6, 27));

            hasher.GetCurrentHashAsUInt32().Should().Be(MurmurHash3x86_32.HashToUInt32(Pattern.AsSpan(0, 33), 42));
        }

        [Fact]
        public void Hash_into_destination_writes_4_bytes_and_leaves_the_rest()
        {
            byte[] destination = Enumerable.Repeat((byte)0xAA, 8).ToArray();

            int written = MurmurHash3x86_32.Hash(Pattern.AsSpan(0, 33), destination, 42);

            written.Should().Be(4);
            destination.Take(4).Should().Equal(MurmurHash3x86_32.Hash(Pattern.AsSpan(0, 33), 42));
            destination.Skip(4).Should().AllBeEquivalentTo((byte)0xAA);
        }

        [Fact]
        public void Hash_into_short_destination_throws()
        {
            Action act = () => MurmurHash3x86_32.Hash(Pattern, new byte[3]);

            act.Should().Throw<ArgumentException>().WithParameterName("destination");
        }

        [Fact]
        public void TryHash_into_short_destination_returns_false_and_writes_nothing()
        {
            byte[] destination = new byte[3];

            MurmurHash3x86_32.TryHash(Pattern, destination, out int written).Should().BeFalse();

            written.Should().Be(0);
            destination.Should().OnlyContain(b => b == 0);
        }

        [Fact]
        public void TryHash_matches_Hash()
        {
            byte[] destination = new byte[4];

            MurmurHash3x86_32.TryHash(Pattern, destination, out int written, 42).Should().BeTrue();

            written.Should().Be(4);
            destination.Should().Equal(MurmurHash3x86_32.Hash(Pattern, 42));
        }

        [Fact]
        public void Hash_into_destination_does_not_allocate()
        {
            byte[] data = TestData.Bytes(100);
            byte[] destination = new byte[4];
            MurmurHash3x86_32.Hash(data, destination);

            long before = GC.GetAllocatedBytesForCurrentThread();
            MurmurHash3x86_32.Hash(data, destination);

            (GC.GetAllocatedBytesForCurrentThread() - before).Should().Be(0);
        }

        [Fact]
        public void Hash_allocates_only_the_result_array()
        {
            byte[] data = TestData.Bytes(100);
            MurmurHash3x86_32.Hash(data);

            long before = GC.GetAllocatedBytesForCurrentThread();
            byte[] hash = MurmurHash3x86_32.Hash(data);
            long hashAllocated = GC.GetAllocatedBytesForCurrentThread() - before;

            before = GC.GetAllocatedBytesForCurrentThread();
            byte[] array = new byte[hash.Length];
            long arrayAllocated = GC.GetAllocatedBytesForCurrentThread() - before;

            hashAllocated.Should().Be(arrayAllocated);
            GC.KeepAlive(array);
        }

        [Fact]
        public void Reset_restores_seeded_state()
        {
            MurmurHash3x86_32 hasher = new(42);
            hasher.Append(Pattern.AsSpan(0, 7));
            hasher.Reset();
            hasher.Append(Pattern.AsSpan(0, 7));
            hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(Pattern.AsSpan(0, 7), 42));
        }

        // Lengths cover every tail length (0..3) with zero, one and several full 4-byte blocks.
        [Theory]
        [InlineData(1, "82F38268")]
        [InlineData(2, "925D6610")]
        [InlineData(3, "44B1B05D")]
        [InlineData(4, "0E309AC0")]
        [InlineData(5, "AD138026")]
        [InlineData(7, "69C11B5B")]
        [InlineData(8, "A364ADEC")]
        [InlineData(9, "F93CD6C4")]
        [InlineData(31, "4D90D946")]
        [InlineData(32, "F378991E")]
        [InlineData(33, "899ED0D7")]
        [InlineData(64, "4967944B")]
        public void Hash_matches_reference_for_block_and_tail_lengths(int length, string expectedHex)
        {
            Hex(MurmurHash3x86_32.Hash(Pattern.AsSpan(0, length))).Should().Be(expectedHex);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(100)]
        public void Incremental_append_in_fixed_chunks_matches_one_shot(int chunkSize)
        {
            byte[] data = TestData.Bytes(1003);
            MurmurHash3x86_32 hasher = new();

            for (int offset = 0; offset < data.Length; offset += chunkSize)
            {
                hasher.Append(data.AsSpan(offset, Math.Min(chunkSize, data.Length - offset)));
            }

            hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(data));
        }

        [Fact]
        public void Incremental_single_append_matches_one_shot_for_every_length()
        {
            for (int length = 0; length <= Pattern.Length; length++)
            {
                MurmurHash3x86_32 hasher = new(42);
                hasher.Append(Pattern.AsSpan(0, length));

                hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(Pattern.AsSpan(0, length), 42), $"length {length}");
            }
        }

        [Fact]
        public void Incremental_append_in_random_chunks_matches_one_shot()
        {
            byte[] data = TestData.Bytes(5000);
            Random random = new(42);
            MurmurHash3x86_32 hasher = new();

            int offset = 0;
            while (offset < data.Length)
            {
                int size = Math.Min(random.Next(0, 10), data.Length - offset);
                hasher.Append(data.AsSpan(offset, size));
                offset += size;
            }

            hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(data));
        }

        [Fact]
        public void Stale_pending_bytes_do_not_leak_into_the_tail()
        {
            // 3 + 1 fills and flushes the pending block, leaving its old bytes behind; the 2-byte tail must ignore them.
            MurmurHash3x86_32 hasher = new();
            hasher.Append(Pattern.AsSpan(0, 3));
            hasher.Append(Pattern.AsSpan(3, 1));
            hasher.Append(Pattern.AsSpan(4, 2));

            Hex(hasher.GetCurrentHash()).Should().Be("D582CC73");
        }

        [Fact]
        public void Empty_appends_do_not_change_the_hash()
        {
            MurmurHash3x86_32 hasher = new();
            hasher.Append([]);
            hasher.Append(Pattern.AsSpan(0, 5));
            hasher.Append([]);

            hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(Pattern.AsSpan(0, 5)));
        }

        [Fact]
        public void GetCurrentHash_does_not_alter_state()
        {
            MurmurHash3x86_32 hasher = new();
            hasher.Append(Pattern.AsSpan(0, 6));

            byte[] first = hasher.GetCurrentHash();
            byte[] second = hasher.GetCurrentHash();
            hasher.Append(Pattern.AsSpan(6, 27));

            second.Should().Equal(first);
            first.Should().Equal(MurmurHash3x86_32.Hash(Pattern.AsSpan(0, 6)));
            hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(Pattern.AsSpan(0, 33)));
        }

        [Fact]
        public void Fresh_hasher_returns_empty_input_hash()
        {
            new MurmurHash3x86_32().GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash([]));
        }

        [Fact]
        public void Trailing_zero_bytes_change_the_hash()
        {
            // Length is mixed into finalization, so zero padding must not collide.
            MurmurHash3x86_32.Hash(new byte[1]).Should().NotEqual(MurmurHash3x86_32.Hash(new byte[2]));
        }
    }
}
