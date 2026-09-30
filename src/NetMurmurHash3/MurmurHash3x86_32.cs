using System.Buffers.Binary;
using System.IO.Hashing;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NetMurmurHash3;

/// <summary>
/// Incremental MurmurHash3 x86_32 (default seed 0). Output is h1 little-endian, matching the reference byte order.
/// </summary>
/// <remarks>
/// The total length is mixed in as its low 32 bits. The reference takes an <c>int</c> length, so results match it for inputs up to
/// <see cref="int.MaxValue"/> bytes; longer incremental inputs have no reference counterpart.
/// </remarks>
public sealed class MurmurHash3x86_32 : NonCryptographicHashAlgorithm
{
    private const int HashSize = 4;
    private const int BlockSize = 4;

    private const uint C1 = 0xcc9e2d51U;
    private const uint C2 = 0x1b873593U;

    private BlockBuffer _pending;
    private int _pendingCount;
    private uint _h1;
    private ulong _length;
    private readonly uint _seed;

    public MurmurHash3x86_32(uint seed = 0) : base(HashSize)
    {
        _seed = seed;
        Reset();
    }

    public static byte[] Hash(ReadOnlySpan<byte> source, uint seed = 0)
    {
        byte[] hash = new byte[HashSize];
        BinaryPrimitives.WriteUInt32LittleEndian(hash, HashCore(source, seed));
        return hash;
    }

    /// <exception cref="ArgumentException"><paramref name="destination"/> is shorter than 4 bytes.</exception>
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

        BinaryPrimitives.WriteUInt32LittleEndian(destination, HashCore(source, seed));
        bytesWritten = HashSize;
        return true;
    }

    /// <summary>Returns h1, the value the reference writes to its output; writing it little-endian yields the <see cref="Hash(ReadOnlySpan{byte}, uint)"/> bytes.</summary>
    public static uint HashToUInt32(ReadOnlySpan<byte> source, uint seed = 0) => HashCore(source, seed);

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

            MixBlocks(_pending, ref _h1);
            _pendingCount = 0;
        }

        int blocksLength = data.Length & ~(BlockSize - 1);
        MixBlocks(data.Slice(0, blocksLength), ref _h1);
        data = data.Slice(blocksLength);

        data.CopyTo(_pending);
        _pendingCount = data.Length;
    }

    public override void Reset()
    {
        _pendingCount = 0;
        _h1 = _seed;
        _length = 0;
    }

    /// <summary>Returns h1; writing it little-endian yields the <see cref="NonCryptographicHashAlgorithm.GetCurrentHash()"/> bytes.</summary>
    public uint GetCurrentHashAsUInt32() => Finish(_h1, ref _pending[0], _pendingCount, _length);

    protected override void GetCurrentHashCore(Span<byte> destination) =>
        BinaryPrimitives.WriteUInt32LittleEndian(destination, GetCurrentHashAsUInt32());

    // Refs instead of Slice and indexing: the bounds checks and their throw paths cost more than the hashing on short inputs.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint HashCore(ReadOnlySpan<byte> source, uint seed)
    {
        uint h1 = seed;
        MixBlocks(source, ref h1);

        int blocksLength = source.Length & ~(BlockSize - 1);
        ref byte tail = ref Unsafe.Add(ref MemoryMarshal.GetReference(source), blocksLength);
        return Finish(h1, ref tail, source.Length - blocksLength, (ulong)source.Length);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Finish(uint h1, ref byte tail, int tailLength, ulong length)
    {
        // The tail is at most 3 bytes, so assembling it byte by byte is cheaper than zero-padding a block. Mixing only a
        // non-empty tail keeps MixK1's two multiplies off the critical path when the input is a whole number of blocks.
        if (tailLength > 0)
        {
            uint k1 = tail;
            if (tailLength > 1)
            {
                k1 ^= (uint)Unsafe.Add(ref tail, 1) << 8;
            }

            if (tailLength > 2)
            {
                k1 ^= (uint)Unsafe.Add(ref tail, 2) << 16;
            }

            h1 ^= MixK1(k1);
        }

        h1 ^= (uint)length;
        return FMix(h1);
    }

    // Mixes only the whole blocks; a trailing partial block is ignored.
    // Works on a local so the JIT keeps the state in a register for the whole loop instead of round-tripping through a field.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void MixBlocks(ReadOnlySpan<byte> blocks, ref uint h1State)
    {
        uint h1 = h1State;

        ref byte block = ref MemoryMarshal.GetReference(blocks);
        ref byte end = ref Unsafe.Add(ref block, blocks.Length & ~(BlockSize - 1));

        while (Unsafe.IsAddressLessThan(ref block, ref end))
        {
            uint k1 = Unsafe.ReadUnaligned<uint>(ref block);
            if (!BitConverter.IsLittleEndian)
            {
                k1 = BinaryPrimitives.ReverseEndianness(k1);
            }

            h1 ^= MixK1(k1);
            h1 = BitOperations.RotateLeft(h1, 13);
            h1 = h1 * 5 + 0xe6546b64;

            block = ref Unsafe.Add(ref block, BlockSize);
        }

        h1State = h1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint MixK1(uint k1) => BitOperations.RotateLeft(k1 * C1, 15) * C2;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint FMix(uint h)
    {
        h ^= h >> 16;
        h *= 0x85ebca6bU;
        h ^= h >> 13;
        h *= 0xc2b2ae35U;
        h ^= h >> 16;
        return h;
    }

    [InlineArray(BlockSize)]
    private struct BlockBuffer
    {
        private byte _element0;
    }
}
