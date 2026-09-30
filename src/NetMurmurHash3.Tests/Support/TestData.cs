namespace NetMurmurHash3.Tests.Support
{
    public static class TestData
    {
        public static byte[] Bytes(int length, int seed = 1)
        {
            byte[] bytes = new byte[length];
            new Random(seed).NextBytes(bytes);
            return bytes;
        }
    }
}
