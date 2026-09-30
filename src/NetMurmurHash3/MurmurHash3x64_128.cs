using System.Buffers.Binary;
using System.IO.Hashing;
using System.Numerics;

namespace NetMurmurHash3;

/// <summary>
/// Incremental MurmurHash3 x64_128 (default seed 0). Output is h1 then h2, each little-endian, matching the reference byte order.
/// </summary>
public sealed class MurmurHash3x64_128 : NonCryptographicHashAlgorithm
{
    private new const int HashLengthInBytes = 16;

    private const ulong C1 = 0x87c37b91114253d5UL;
    private const ulong C2 = 0x4cf5ad432745937fUL;

    private readonly byte[] _pending = new byte[HashLengthInBytes];
    private int _pendingCount;
    private ulong _h1;
    private ulong _h2;
    private ulong _length;
    private readonly uint _seed;

    public MurmurHash3x64_128(uint seed = 0) : base(HashLengthInBytes)
    {
        _seed = seed;
        Reset();
    }

    public static byte[] Hash(ReadOnlySpan<byte> data, uint seed = 0)
    {
        ulong h1 = seed;
        ulong h2 = seed;
        int blocksLength = data.Length & ~(HashLengthInBytes - 1);
        MixBlocks(data.Slice(0, blocksLength), ref h1, ref h2);

        byte[] hash = new byte[HashLengthInBytes];
        Finish(h1, h2, data.Slice(blocksLength), (ulong)data.Length, hash);
        return hash;
    }

    public override void Append(ReadOnlySpan<byte> data)
    {
        _length += (ulong)data.Length;

        if (_pendingCount > 0)
        {
            int take = Math.Min(HashLengthInBytes - _pendingCount, data.Length);
            data.Slice(0, take).CopyTo(_pending.AsSpan(_pendingCount));
            _pendingCount += take;
            data = data.Slice(take);

            if (_pendingCount < HashLengthInBytes)
            {
                return;
            }

            MixBlocks(_pending, ref _h1, ref _h2);
            _pendingCount = 0;
        }

        int blocksLength = data.Length & ~(HashLengthInBytes - 1);
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

    protected override void GetCurrentHashCore(Span<byte> destination) =>
        Finish(_h1, _h2, _pending.AsSpan(0, _pendingCount), _length, destination);

    private static void Finish(ulong h1, ulong h2, ReadOnlySpan<byte> tail, ulong length, Span<byte> destination)
    {
        ulong k1 = 0;
        ulong k2 = 0;
        for (int i = tail.Length - 1; i >= 8; i--)
        {
            k2 = (k2 << 8) | tail[i];
        }
        for (int i = Math.Min(tail.Length, 8) - 1; i >= 0; i--)
        {
            k1 = (k1 << 8) | tail[i];
        }

        if (tail.Length > 8)
        {
            h2 ^= MixK2(k2);
        }
        if (tail.Length > 0)
        {
            h1 ^= MixK1(k1);
        }

        h1 ^= length;
        h2 ^= length;
        h1 += h2;
        h2 += h1;
        h1 = FMix(h1);
        h2 = FMix(h2);
        h1 += h2;
        h2 += h1;

        BinaryPrimitives.WriteUInt64LittleEndian(destination, h1);
        BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(8), h2);
    }

    // Works on locals so the JIT keeps the state in registers for the whole loop instead of round-tripping through fields.
    private static void MixBlocks(ReadOnlySpan<byte> blocks, ref ulong h1State, ref ulong h2State)
    {
        ulong h1 = h1State;
        ulong h2 = h2State;

        while (blocks.Length >= HashLengthInBytes)
        {
            ulong k1 = BinaryPrimitives.ReadUInt64LittleEndian(blocks);
            ulong k2 = BinaryPrimitives.ReadUInt64LittleEndian(blocks.Slice(8));

            h1 ^= MixK1(k1);
            h1 = BitOperations.RotateLeft(h1, 27);
            h1 += h2;
            h1 = h1 * 5 + 0x52dce729;

            h2 ^= MixK2(k2);
            h2 = BitOperations.RotateLeft(h2, 31);
            h2 += h1;
            h2 = h2 * 5 + 0x38495ab5;

            blocks = blocks.Slice(HashLengthInBytes);
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
}
