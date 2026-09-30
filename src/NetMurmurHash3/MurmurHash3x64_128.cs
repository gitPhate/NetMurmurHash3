using System.Buffers.Binary;
using System.IO.Hashing;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NetMurmurHash3;

/// <summary>
/// Incremental MurmurHash3 x64_128 (default seed 0). Output is h1 then h2, each little-endian, matching the reference byte order.
/// </summary>
/// <remarks>
/// The total length is mixed in as 64 bits. The reference takes an <c>int</c> length, so results match it for inputs up to
/// <see cref="int.MaxValue"/> bytes; longer incremental inputs have no reference counterpart.
/// </remarks>
public sealed class MurmurHash3x64_128 : NonCryptographicHashAlgorithm
{
    private const int HashSize = 16;
    private const int BlockSize = 16;

    private const ulong C1 = 0x87c37b91114253d5UL;
    private const ulong C2 = 0x4cf5ad432745937fUL;

    private BlockBuffer _pending;
    private int _pendingCount;
    private ulong _h1;
    private ulong _h2;
    private ulong _length;
    private readonly uint _seed;

    public MurmurHash3x64_128(uint seed = 0) : base(HashSize)
    {
        _seed = seed;
        Reset();
    }

    public static byte[] Hash(ReadOnlySpan<byte> source, uint seed = 0)
    {
        byte[] hash = new byte[HashSize];
        BinaryPrimitives.WriteUInt128LittleEndian(hash, HashCore(source, seed));
        return hash;
    }

    /// <exception cref="ArgumentException"><paramref name="destination"/> is shorter than 16 bytes.</exception>
    public static int Hash(ReadOnlySpan<byte> source, Span<byte> destination, uint seed = 0)
    {
        if (!TryHash(source, destination, out int bytesWritten, seed))
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }

        return bytesWritten;
    }

    public static bool TryHash(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten, uint seed = 0)
    {
        if (destination.Length < HashSize)
        {
            bytesWritten = 0;
            return false;
        }

        BinaryPrimitives.WriteUInt128LittleEndian(destination, HashCore(source, seed));
        bytesWritten = HashSize;
        return true;
    }

    /// <summary>Returns h2 as the upper and h1 as the lower 64 bits, so writing it little-endian yields the <see cref="Hash(ReadOnlySpan{byte}, uint)"/> bytes.</summary>
    public static UInt128 HashToUInt128(ReadOnlySpan<byte> source, uint seed = 0) => HashCore(source, seed);

    public override void Append(ReadOnlySpan<byte> data)
    {
        _length += (ulong)data.Length;

        if (_pendingCount > 0)
        {
            int take = Math.Min(BlockSize - _pendingCount, data.Length);
            data.Slice(0, take).CopyTo(_pending[_pendingCount..]);
            _pendingCount += take;
            data = data.Slice(take);

            if (_pendingCount < BlockSize)
            {
                return;
            }

            MixBlocks(_pending, ref _h1, ref _h2);
            _pendingCount = 0;
        }

        int blocksLength = data.Length & ~(BlockSize - 1);
        MixBlocks(data.Slice(0, blocksLength), ref _h1, ref _h2);
        data = data.Slice(blocksLength);

        data.CopyTo(_pending);
        _pendingCount = data.Length;
    }

    public override void Reset()
    {
        _pendingCount = 0;
        _h1 = _seed;
        _h2 = _seed;
        _length = 0;
    }

    /// <summary>Returns h2 as the upper and h1 as the lower 64 bits, so writing it little-endian yields the <see cref="NonCryptographicHashAlgorithm.GetCurrentHash()"/> bytes.</summary>
    public UInt128 GetCurrentHashAsUInt128() => Finish(_h1, _h2, _pending[.._pendingCount], _length);

    protected override void GetCurrentHashCore(Span<byte> destination) =>
        BinaryPrimitives.WriteUInt128LittleEndian(destination, GetCurrentHashAsUInt128());

    private static UInt128 HashCore(ReadOnlySpan<byte> source, uint seed)
    {
        ulong h1 = seed;
        ulong h2 = seed;
        int blocksLength = source.Length & ~(BlockSize - 1);
        MixBlocks(source.Slice(0, blocksLength), ref h1, ref h2);

        return Finish(h1, h2, source.Slice(blocksLength), (ulong)source.Length);
    }

    private static UInt128 Finish(ulong h1, ulong h2, ReadOnlySpan<byte> tail, ulong length)
    {
        // Zero padding reproduces the reference's byte-by-byte tail assembly.
        BlockBuffer padded = default;
        tail.CopyTo(padded);
        ulong k1 = BinaryPrimitives.ReadUInt64LittleEndian(padded);
        ulong k2 = BinaryPrimitives.ReadUInt64LittleEndian(padded[8..]);

        // MixK1(0) == MixK2(0) == 0, so absent tail lanes are no-ops and need no branch.
        h2 ^= MixK2(k2);
        h1 ^= MixK1(k1);

        h1 ^= length;
        h2 ^= length;
        h1 += h2;
        h2 += h1;
        h1 = FMix(h1);
        h2 = FMix(h2);
        h1 += h2;
        h2 += h1;

        return new UInt128(h2, h1);
    }

    // Works on locals so the JIT keeps the state in registers for the whole loop instead of round-tripping through fields.
    private static void MixBlocks(ReadOnlySpan<byte> blocks, ref ulong h1State, ref ulong h2State)
    {
        ulong h1 = h1State;
        ulong h2 = h2State;

        ref byte block = ref MemoryMarshal.GetReference(blocks);
        ref byte end = ref Unsafe.Add(ref block, blocks.Length & ~(BlockSize - 1));

        while (Unsafe.IsAddressLessThan(ref block, ref end))
        {
            ulong k1 = Unsafe.ReadUnaligned<ulong>(ref block);
            ulong k2 = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref block, 8));
            if (!BitConverter.IsLittleEndian)
            {
                k1 = BinaryPrimitives.ReverseEndianness(k1);
                k2 = BinaryPrimitives.ReverseEndianness(k2);
            }

            h1 ^= MixK1(k1);
            h1 = BitOperations.RotateLeft(h1, 27);
            h1 += h2;
            h1 = h1 * 5 + 0x52dce729;

            h2 ^= MixK2(k2);
            h2 = BitOperations.RotateLeft(h2, 31);
            h2 += h1;
            h2 = h2 * 5 + 0x38495ab5;

            block = ref Unsafe.Add(ref block, BlockSize);
        }

        h1State = h1;
        h2State = h2;
    }

    private static ulong MixK1(ulong k1) => BitOperations.RotateLeft(k1 * C1, 31) * C2;

    private static ulong MixK2(ulong k2) => BitOperations.RotateLeft(k2 * C2, 33) * C1;

    private static ulong FMix(ulong k)
    {
        k ^= k >> 33;
        k *= 0xff51afd7ed558ccdUL;
        k ^= k >> 33;
        k *= 0xc4ceb9fe1a85ec53UL;
        k ^= k >> 33;
        return k;
    }

    [InlineArray(BlockSize)]
    private struct BlockBuffer
    {
        private byte _element0;
    }
}
