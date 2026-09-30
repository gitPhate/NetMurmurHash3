using System.Buffers.Binary;
using System.IO.Hashing;
using System.Numerics;

namespace NetMurmurHash3;

/// <summary>
/// Incremental MurmurHash3 x64_128 (default seed 0). Output is h1 then h2, each little-endian, matching the reference byte order.
/// </summary>
public sealed class MurmurHash3x64 : NonCryptographicHashAlgorithm
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

    public MurmurHash3x64(uint seed = 0) : base(HashLengthInBytes)
    {
        _seed = seed;
        Reset();
    }

    public static byte[] Hash(ReadOnlySpan<byte> data, uint seed = 0)
    {
        MurmurHash3x64 hasher = new(seed);
        hasher.Append(data);
        return hasher.GetCurrentHash();
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

            MixBlock(_pending);
            _pendingCount = 0;
        }

        while (data.Length >= HashLengthInBytes)
        {
            MixBlock(data);
            data = data.Slice(HashLengthInBytes);
        }

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

    protected override void GetCurrentHashCore(Span<byte> destination)
    {
        ulong h1 = _h1;
        ulong h2 = _h2;
        ReadOnlySpan<byte> tail = _pending.AsSpan(0, _pendingCount);

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

        h1 ^= _length;
        h2 ^= _length;
        h1 += h2;
        h2 += h1;
        h1 = FMix(h1);
        h2 = FMix(h2);
        h1 += h2;
        h2 += h1;

        BinaryPrimitives.WriteUInt64LittleEndian(destination, h1);
        BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(8), h2);
    }

    private void MixBlock(ReadOnlySpan<byte> block)
    {
        ulong k1 = BinaryPrimitives.ReadUInt64LittleEndian(block);
        ulong k2 = BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(8));

        _h1 ^= MixK1(k1);
        _h1 = BitOperations.RotateLeft(_h1, 27);
        _h1 += _h2;
        _h1 = _h1 * 5 + 0x52dce729;

        _h2 ^= MixK2(k2);
        _h2 = BitOperations.RotateLeft(_h2, 31);
        _h2 += _h1;
        _h2 = _h2 * 5 + 0x38495ab5;
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
