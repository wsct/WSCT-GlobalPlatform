using WSCT.Helpers;

namespace WSCT.GlobalPlatform
{
    public record AID(byte[] Aid)
    {
        public static AID ParseWithLength(Span<byte> data)
        {
            if (data.Length == 0)
            {
                throw new GlobalPlatformException($"{nameof(data)} can't be empty");
            }

            if (data.Length < 1 + data[0])
            {
                throw new GlobalPlatformException($"{nameof(data)} length must be at least {1 + data[0]} but is {data.Length} [{data.ToHexa()}]");
            }

            return new AID(data.Slice(1, data[0]).ToArray());
        }
    }
}
