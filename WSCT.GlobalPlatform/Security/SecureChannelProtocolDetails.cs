namespace WSCT.GlobalPlatform.Security
{
    public record SecureChannelProtocolDetails(
        byte Identifier,
        byte Options)
    {
        public static SecureChannelProtocolDetails Create(Span<byte> scpBytes)
        {
            if (scpBytes.Length != 2)
            {
                throw new ArgumentOutOfRangeException(nameof(scpBytes), "Should be 2 bytes long");
            }

            return new SecureChannelProtocolDetails(scpBytes[0], scpBytes[1]);
        }

        #region >> Object

        /// <inheritdoc />
        public override string ToString()
        {
            return $"SCP{Identifier:X2}.i={Options:X2}";
        }

        #endregion
    }
}
