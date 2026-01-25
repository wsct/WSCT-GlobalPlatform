using WSCT.Helpers;

namespace WSCT.GlobalPlatform
{
    /// <summary>
    /// Application Identifier.
    /// </summary>
    public record AID(byte[] Aid)
    {
        /// <summary>
        /// Parse the AID from the response data sent by the card.
        /// </summary>
        /// <param name="data">Response data.</param>
        /// <returns>AID.</returns>
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

        #region >>> Object

        /// <inheritdoc/>
        public override string ToString()
        {
            return Aid.ToHexa();
        }

        #endregion
    }
}
