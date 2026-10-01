using FluentAssertions;
using NetMurmurHash3.Tests.Support;
using System.Text;
using static NetMurmurHash3.Tests.Support.ReferenceData;

namespace NetMurmurHash3.Tests;

public class MurmurHash3x64_128ServiceShould
{
    [Theory]
    [InlineData("", "00000000000000000000000000000000")]
    [InlineData("hello", "029BBD41B3A7D8CB191DAE486A901E5B")]
    [InlineData("The quick brown fox jumps over the lazy dog", "6C1B07BC7BBC4BE347939AC4A93C437A")]
    public void MatchReferenceForAsciiStrings(string input, string expectedHex)
    {
        // Arrange
        byte[] data = Encoding.ASCII.GetBytes(input);

        // Act
        byte[] hash = MurmurHash3x64_128.Hash(data);

        // Assert
        Hex(hash).Should().Be(expectedHex);
    }

    [Fact]
    public void MatchReferenceWithSeed()
    {
        // Arrange
        byte[] data = Encoding.ASCII.GetBytes("hello");

        // Act
        byte[] hash = MurmurHash3x64_128.Hash(data, 42);

        // Assert
        Hex(hash).Should().Be("086FAF60C9B3B8C47ABCEFB075B83423");
    }

    [Fact]
    public void MatchReferenceWithSeedAcrossBlocksAndTail()
    {
        // Arrange
        byte[] data = Pattern[..45];

        // Act
        byte[] hash = MurmurHash3x64_128.Hash(data, 42);

        // Assert
        Hex(hash).Should().Be("37FB5146E7163F26ED4EA08E8C600CC6");
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
    public void MatchReferenceForBlockAndTailLengths(int length, string expectedHex)
    {
        // Arrange
        byte[] data = Pattern[..length];

        // Act
        byte[] hash = MurmurHash3x64_128.Hash(data);

        // Assert
        Hex(hash).Should().Be(expectedHex);
    }

    [Fact]
    public void ReturnH1AsLowerAndH2AsUpperHalfOfUInt128()
    {
        // Arrange
        // "hello" hashes to h1 bytes 029BBD41B3A7D8CB and h2 bytes 191DAE486A901E5B, each little-endian.
        byte[] data = Encoding.ASCII.GetBytes("hello");

        // Act
        UInt128 hash = MurmurHash3x64_128.HashToUInt128(data);

        // Assert
        hash.Should().Be(new UInt128(0x5B1E906A48AE1D19UL, 0xCBD8A7B341BD9B02UL));
    }

    [Fact]
    public void ReturnSameUInt128FromIncrementalAndOneShot()
    {
        // Arrange
        MurmurHash3x64_128 hasher = new(42);
        hasher.Append(Pattern.AsSpan(0, 20));
        hasher.Append(Pattern.AsSpan(20, 25));

        // Act
        UInt128 incremental = hasher.GetCurrentHashAsUInt128();

        // Assert
        incremental.Should().Be(MurmurHash3x64_128.HashToUInt128(Pattern[..45], 42));
    }

    [Fact]
    public void WriteSixteenBytesIntoDestination()
    {
        // Arrange
        byte[] data = Pattern[..33];
        byte[] destination = new byte[20];

        // Act
        int written = MurmurHash3x64_128.Hash(data, destination, 42);

        // Assert
        written.Should().Be(16);
        destination.Take(16).Should().Equal(MurmurHash3x64_128.Hash(data, 42));
    }

    [Fact]
    public void LeaveBytesBeyondTheHashUntouchedInDestination()
    {
        // Arrange
        byte[] destination = Enumerable.Repeat((byte)0xAA, 20).ToArray();

        // Act
        MurmurHash3x64_128.Hash(Pattern[..33], destination, 42);

        // Assert
        destination.Skip(16).Should().AllBeEquivalentTo((byte)0xAA);
    }

    [Fact]
    public void ThrowWhenHashingIntoShortDestination()
    {
        // Arrange
        byte[] destination = new byte[15];

        // Act
        Action act = () => MurmurHash3x64_128.Hash(Pattern, destination);

        // Assert
        act.Should().Throw<ArgumentException>().WithParameterName("destination");
    }

    [Fact]
    public void ReturnFalseWhenTryHashingIntoShortDestination()
    {
        // Arrange
        byte[] destination = new byte[15];

        // Act
        bool result = MurmurHash3x64_128.TryHash(Pattern, destination, out int written);

        // Assert
        result.Should().BeFalse();
        written.Should().Be(0);
    }

    [Fact]
    public void WriteNothingWhenTryHashingIntoShortDestination()
    {
        // Arrange
        byte[] destination = new byte[15];

        // Act
        MurmurHash3x64_128.TryHash(Pattern, destination, out _);

        // Assert
        destination.Should().OnlyContain(b => b == 0);
    }

    [Fact]
    public void TryHashToTheSameBytesAsHash()
    {
        // Arrange
        byte[] destination = new byte[16];

        // Act
        bool result = MurmurHash3x64_128.TryHash(Pattern, destination, out int written, 42);

        // Assert
        result.Should().BeTrue();
        written.Should().Be(16);
        destination.Should().Equal(MurmurHash3x64_128.Hash(Pattern, 42));
    }

    [Fact]
    public void NotAllocateWhenHashingIntoDestination()
    {
        // Arrange
        byte[] data = TestData.Bytes(100);
        byte[] destination = new byte[16];
        MurmurHash3x64_128.Hash(data, destination);
        long before = GC.GetAllocatedBytesForCurrentThread();

        // Act
        MurmurHash3x64_128.Hash(data, destination);

        // Assert
        (GC.GetAllocatedBytesForCurrentThread() - before).Should().Be(0);
    }

    [Fact]
    public void AllocateOnlyTheResultArrayWhenHashing()
    {
        // Arrange
        byte[] data = TestData.Bytes(100);
        MurmurHash3x64_128.Hash(data);
        long before = GC.GetAllocatedBytesForCurrentThread();
        byte[] array = new byte[16];
        long arrayAllocated = GC.GetAllocatedBytesForCurrentThread() - before;
        before = GC.GetAllocatedBytesForCurrentThread();

        // Act
        byte[] hash = MurmurHash3x64_128.Hash(data);
        long hashAllocated = GC.GetAllocatedBytesForCurrentThread() - before;

        // Assert
        hashAllocated.Should().Be(arrayAllocated);
        GC.KeepAlive(array);
        GC.KeepAlive(hash);
    }

    [Fact]
    public void ReturnEmptyInputHashFromFreshHasher()
    {
        // Arrange
        MurmurHash3x64_128 hasher = new();

        // Act
        byte[] hash = hasher.GetCurrentHash();

        // Assert
        hash.Should().Equal(MurmurHash3x64_128.Hash([]));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(100)]
    public void MatchOneShotWhenAppendingInFixedChunks(int chunkSize)
    {
        // Arrange
        byte[] data = TestData.Bytes(1003);
        MurmurHash3x64_128 hasher = new(42);

        // Act
        for (int offset = 0; offset < data.Length; offset += chunkSize)
        {
            hasher.Append(data.AsSpan(offset, Math.Min(chunkSize, data.Length - offset)));
        }

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(data, 42));
    }

    [Fact]
    public void MatchOneShotWhenAppendingInRandomChunks()
    {
        // Arrange
        byte[] data = TestData.Bytes(5000);
        Random random = new(42);
        MurmurHash3x64_128 hasher = new();

        // Act
        int offset = 0;
        while (offset < data.Length)
        {
            int size = Math.Min(random.Next(0, 40), data.Length - offset);
            hasher.Append(data.AsSpan(offset, size));
            offset += size;
        }

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(data));
    }

    [Theory]
    [MemberData(nameof(PatternLengths))]
    public void MatchOneShotWhenAppendingOnceForEveryLength(int length)
    {
        // Arrange
        MurmurHash3x64_128 hasher = new(42);

        // Act
        hasher.Append(Pattern.AsSpan(0, length));

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(Pattern[..length], 42));
    }

    public static TheoryData<int> PatternLengths() => new(Enumerable.Range(0, Pattern.Length + 1));

    [Fact]
    public void IgnoreStalePendingBytesInTheTail()
    {
        // Arrange
        // 15 + 1 fills and flushes the pending block, leaving its old bytes behind; the 2-byte tail must ignore them.
        MurmurHash3x64_128 hasher = new();

        // Act
        hasher.Append(Pattern.AsSpan(0, 15));
        hasher.Append(Pattern.AsSpan(15, 1));
        hasher.Append(Pattern.AsSpan(16, 2));

        // Assert
        Hex(hasher.GetCurrentHash()).Should().Be("9E5F2E48DA90B244F61BCD23380AC584");
    }

    [Fact]
    public void IgnoreEmptyAppends()
    {
        // Arrange
        MurmurHash3x64_128 hasher = new();

        // Act
        hasher.Append([]);
        hasher.Append(Pattern.AsSpan(0, 9));
        hasher.Append([]);

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(Pattern[..9]));
    }

    [Fact]
    public void ReturnSameHashWhenGetCurrentHashIsCalledTwice()
    {
        // Arrange
        MurmurHash3x64_128 hasher = new();
        hasher.Append(Pattern.AsSpan(0, 20));

        // Act
        byte[] first = hasher.GetCurrentHash();
        byte[] second = hasher.GetCurrentHash();

        // Assert
        second.Should().Equal(first);
        first.Should().Equal(MurmurHash3x64_128.Hash(Pattern[..20]));
    }

    [Fact]
    public void ContinueAccumulatingAfterGetCurrentHash()
    {
        // Arrange
        MurmurHash3x64_128 hasher = new();
        hasher.Append(Pattern.AsSpan(0, 20));
        hasher.GetCurrentHash();

        // Act
        hasher.Append(Pattern.AsSpan(20, 13));

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(Pattern[..33]));
    }

    [Fact]
    public void RestoreSeededStateOnReset()
    {
        // Arrange
        MurmurHash3x64_128 hasher = new(42);
        hasher.Append(Pattern.AsSpan(0, 20));

        // Act
        hasher.Reset();
        hasher.Append(Pattern.AsSpan(0, 20));

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(Pattern[..20], 42));
    }

    [Fact]
    public void RestoreSeededStateOnResetAfterReadingTheHash()
    {
        // Arrange
        MurmurHash3x64_128 hasher = new(42);
        hasher.Append(Pattern.AsSpan(0, 45));
        hasher.GetCurrentHash();

        // Act
        hasher.Reset();
        hasher.Append(Pattern.AsSpan(0, 9));

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x64_128.Hash(Pattern[..9], 42));
    }
}
