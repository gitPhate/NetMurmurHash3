namespace NetMurmurHash3.Tests.Support;

public static class ReferenceData
{
    /// <summary>Pattern bytes whose prefixes are hashed in the tests; expected values were generated with the Python mmh3 package.</summary>
    public static readonly byte[] Pattern = Enumerable.Range(0, 64).Select(i => (byte)((i * 31 + 7) & 0xFF)).ToArray();

    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes);
}
