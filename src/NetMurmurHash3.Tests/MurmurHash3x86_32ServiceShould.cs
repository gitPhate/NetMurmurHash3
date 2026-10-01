using FluentAssertions;
using NetMurmurHash3.Tests.Support;
using System.Text;
using static NetMurmurHash3.Tests.Support.ReferenceData;

namespace NetMurmurHash3.Tests;

public class MurmurHash3x86_32ServiceShould
{
    [Theory]
    [InlineData("", "00000000")]
    [InlineData("hello", "47FA8B24")]
    [InlineData("The quick brown fox jumps over the lazy dog", "23F74F2E")]
    public void MatchReferenceForAsciiStrings(string input, string expectedHex)
    {
        // Arrange
        byte[] data = Encoding.ASCII.GetBytes(input);

        // Act
        byte[] hash = MurmurHash3x86_32.Hash(data);

        // Assert
        Hex(hash).Should().Be(expectedHex);
    }

    [Fact]
    public void MatchReferenceWithSeed()
    {
        // Arrange
        byte[] data = Encoding.ASCII.GetBytes("hello");

        // Act
        byte[] hash = MurmurHash3x86_32.Hash(data, 42);

        // Assert
        Hex(hash).Should().Be("E1D2DBE2");
    }

    [Fact]
    public void MatchReferenceWithSeedAcrossBlocksAndTail()
    {
        // Arrange
        byte[] data = Pattern[..43];

        // Act
        byte[] hash = MurmurHash3x86_32.Hash(data, 42);

        // Assert
        Hex(hash).Should().Be("F011335C");
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
    public void MatchReferenceForBlockAndTailLengths(int length, string expectedHex)
    {
        // Arrange
        byte[] data = Pattern[..length];

        // Act
        byte[] hash = MurmurHash3x86_32.Hash(data);

        // Assert
        Hex(hash).Should().Be(expectedHex);
    }

    [Fact]
    public void ReturnLittleEndianReadingOfHashAsUInt32()
    {
        // Arrange
        byte[] data = Encoding.ASCII.GetBytes("hello");

        // Act
        uint hash = MurmurHash3x86_32.HashToUInt32(data);

        // Assert
        hash.Should().Be(0x248BFA47U);
    }

    [Fact]
    public void MatchJeremyEspressoReadmeExample()
    {
        // Arrange
        byte[] data = Encoding.UTF8.GetBytes("Hello World!");

        // Act
        uint hash = MurmurHash3x86_32.HashToUInt32(data, 420);

        // Assert
        hash.Should().Be(1535517821U);
    }

    [Fact]
    public void ReturnSameUInt32FromIncrementalAndOneShot()
    {
        // Arrange
        MurmurHash3x86_32 hasher = new(42);
        hasher.Append(Pattern.AsSpan(0, 6));
        hasher.Append(Pattern.AsSpan(6, 37));

        // Act
        uint incremental = hasher.GetCurrentHashAsUInt32();

        // Assert
        incremental.Should().Be(MurmurHash3x86_32.HashToUInt32(Pattern[..43], 42));
    }

    [Fact]
    public void WriteFourBytesIntoDestination()
    {
        // Arrange
        byte[] data = Pattern[..33];
        byte[] destination = new byte[8];

        // Act
        int written = MurmurHash3x86_32.Hash(data, destination, 42);

        // Assert
        written.Should().Be(4);
        destination.Take(4).Should().Equal(MurmurHash3x86_32.Hash(data, 42));
    }

    [Fact]
    public void LeaveBytesBeyondTheHashUntouchedInDestination()
    {
        // Arrange
        byte[] destination = Enumerable.Repeat((byte)0xAA, 8).ToArray();

        // Act
        MurmurHash3x86_32.Hash(Pattern[..33], destination, 42);

        // Assert
        destination.Skip(4).Should().AllBeEquivalentTo((byte)0xAA);
    }

    [Fact]
    public void ThrowWhenHashingIntoShortDestination()
    {
        // Arrange
        byte[] destination = new byte[3];

        // Act
        Action act = () => MurmurHash3x86_32.Hash(Pattern, destination);

        // Assert
        act.Should().Throw<ArgumentException>().WithParameterName("destination");
    }

    [Fact]
    public void ReturnFalseWhenTryHashingIntoShortDestination()
    {
        // Arrange
        byte[] destination = new byte[3];

        // Act
        bool result = MurmurHash3x86_32.TryHash(Pattern, destination, out int written);

        // Assert
        result.Should().BeFalse();
        written.Should().Be(0);
    }

    [Fact]
    public void WriteNothingWhenTryHashingIntoShortDestination()
    {
        // Arrange
        byte[] destination = new byte[3];

        // Act
        MurmurHash3x86_32.TryHash(Pattern, destination, out _);

        // Assert
        destination.Should().OnlyContain(b => b == 0);
    }

    [Fact]
    public void TryHashToTheSameBytesAsHash()
    {
        // Arrange
        byte[] destination = new byte[4];

        // Act
        bool result = MurmurHash3x86_32.TryHash(Pattern, destination, out int written, 42);

        // Assert
        result.Should().BeTrue();
        written.Should().Be(4);
        destination.Should().Equal(MurmurHash3x86_32.Hash(Pattern, 42));
    }

    [Fact]
    public void NotAllocateWhenHashingIntoDestination()
    {
        // Arrange
        byte[] data = TestData.Bytes(100);
        byte[] destination = new byte[4];
        MurmurHash3x86_32.Hash(data, destination);
        long before = GC.GetAllocatedBytesForCurrentThread();

        // Act
        MurmurHash3x86_32.Hash(data, destination);

        // Assert
        (GC.GetAllocatedBytesForCurrentThread() - before).Should().Be(0);
    }

    [Fact]
    public void AllocateOnlyTheResultArrayWhenHashing()
    {
        // Arrange
        byte[] data = TestData.Bytes(100);
        MurmurHash3x86_32.Hash(data);
        long before = GC.GetAllocatedBytesForCurrentThread();
        byte[] array = new byte[4];
        long arrayAllocated = GC.GetAllocatedBytesForCurrentThread() - before;
        before = GC.GetAllocatedBytesForCurrentThread();

        // Act
        byte[] hash = MurmurHash3x86_32.Hash(data);
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
        MurmurHash3x86_32 hasher = new();

        // Act
        byte[] hash = hasher.GetCurrentHash();

        // Assert
        hash.Should().Equal(MurmurHash3x86_32.Hash([]));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(100)]
    public void MatchOneShotWhenAppendingInFixedChunks(int chunkSize)
    {
        // Arrange
        byte[] data = TestData.Bytes(1003);
        MurmurHash3x86_32 hasher = new(42);

        // Act
        for (int offset = 0; offset < data.Length; offset += chunkSize)
        {
            hasher.Append(data.AsSpan(offset, Math.Min(chunkSize, data.Length - offset)));
        }

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(data, 42));
    }

    [Fact]
    public void MatchOneShotWhenAppendingInRandomChunks()
    {
        // Arrange
        byte[] data = TestData.Bytes(5000);
        Random random = new(42);
        MurmurHash3x86_32 hasher = new();

        // Act
        int offset = 0;
        while (offset < data.Length)
        {
            int size = Math.Min(random.Next(0, 10), data.Length - offset);
            hasher.Append(data.AsSpan(offset, size));
            offset += size;
        }

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(data));
    }

    [Theory]
    [MemberData(nameof(PatternLengths))]
    public void MatchOneShotWhenAppendingOnceForEveryLength(int length)
    {
        // Arrange
        MurmurHash3x86_32 hasher = new(42);

        // Act
        hasher.Append(Pattern.AsSpan(0, length));

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(Pattern[..length], 42));
    }

    public static TheoryData<int> PatternLengths() => new(Enumerable.Range(0, Pattern.Length + 1));

    [Fact]
    public void IgnoreStalePendingBytesInTheTail()
    {
        // Arrange
        // 3 + 1 fills and flushes the pending block, leaving its old bytes behind; the 2-byte tail must ignore them.
        MurmurHash3x86_32 hasher = new();

        // Act
        hasher.Append(Pattern.AsSpan(0, 3));
        hasher.Append(Pattern.AsSpan(3, 1));
        hasher.Append(Pattern.AsSpan(4, 2));

        // Assert
        Hex(hasher.GetCurrentHash()).Should().Be("D582CC73");
    }

    [Fact]
    public void IgnoreEmptyAppends()
    {
        // Arrange
        MurmurHash3x86_32 hasher = new();

        // Act
        hasher.Append([]);
        hasher.Append(Pattern.AsSpan(0, 5));
        hasher.Append([]);

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(Pattern[..5]));
    }

    [Fact]
    public void ReturnSameHashWhenGetCurrentHashIsCalledTwice()
    {
        // Arrange
        MurmurHash3x86_32 hasher = new();
        hasher.Append(Pattern.AsSpan(0, 6));

        // Act
        byte[] first = hasher.GetCurrentHash();
        byte[] second = hasher.GetCurrentHash();

        // Assert
        second.Should().Equal(first);
        first.Should().Equal(MurmurHash3x86_32.Hash(Pattern[..6]));
    }

    [Fact]
    public void ContinueAccumulatingAfterGetCurrentHash()
    {
        // Arrange
        MurmurHash3x86_32 hasher = new();
        hasher.Append(Pattern.AsSpan(0, 6));
        hasher.GetCurrentHash();

        // Act
        hasher.Append(Pattern.AsSpan(6, 27));

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(Pattern[..33]));
    }

    [Fact]
    public void RestoreSeededStateOnReset()
    {
        // Arrange
        MurmurHash3x86_32 hasher = new(42);
        hasher.Append(Pattern.AsSpan(0, 7));

        // Act
        hasher.Reset();
        hasher.Append(Pattern.AsSpan(0, 7));

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(Pattern[..7], 42));
    }

    [Fact]
    public void RestoreSeededStateOnResetAfterReadingTheHash()
    {
        // Arrange
        MurmurHash3x86_32 hasher = new(42);
        hasher.Append(Pattern.AsSpan(0, 43));
        hasher.GetCurrentHash();

        // Act
        hasher.Reset();
        hasher.Append(Pattern.AsSpan(0, 5));

        // Assert
        hasher.GetCurrentHash().Should().Equal(MurmurHash3x86_32.Hash(Pattern[..5], 42));
    }
}
