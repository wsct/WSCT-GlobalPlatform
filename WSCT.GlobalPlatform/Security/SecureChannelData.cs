using WSCT.Helpers;

namespace WSCT.GlobalPlatform.Security
{
    /// <summary>
    /// The data used to manage a secure channel.
    /// </summary>
    public class SecureChannelData
    {
        #region >> Properties (input of INITIALIZE UPDATE)

        public SecureChannelProtocolDetails ScpDetails { get; private set; }
        public byte KeyVersion { get; init; }
        public byte KeyIdentifier { get; init; }
        public byte[] HostChallenge { get; init; }

        #endregion

        #region >> Properties (output of INITIALIZE UPDATE)

        public byte[]? KeyDiversificationData { get; private set; }
        public byte[]? KeyInformation { get; private set; }
        public byte[]? CardChallenge { get; private set; }
        public byte[]? CardCryptogram { get; private set; }

        #endregion

        #region >> Properties * Keys

        public Keys? Keys { get; set; }

        public SessionKeys? SessionKeys { get; set; }

        #endregion

        #region >> Properties (input of EXTERNAL AUTHENTICATE)

        public SecurityLevel SecurityLevel { get; set; }
        public byte[]? HostCryptogram { get; private set; }

        #endregion

        #region >> Properties (SCPxx specifics)

        public ISecureChannelSpecifics? Specifics { get; set; }

        #endregion

        public SecureChannelData(SecureChannelProtocolDetails scp, byte keyVersion, byte keyIdentifier, Span<byte> hostChallenge)
        {
            ScpDetails = scp;
            KeyVersion = keyVersion;
            KeyIdentifier = keyIdentifier;
            HostChallenge = hostChallenge.ToArray();
        }

        public SecureChannelData ParseHostCryptogram(Span<byte> hostCryptogram)
        {
            HostCryptogram = hostCryptogram.ToArray();

            return this;
        }

        public SecureChannelData ParseInitializeUpdateResponse(Span<byte> udr)
        {
            KeyDiversificationData = udr[..10].ToArray();
            KeyInformation = udr[10..12].ToArray();
            CardChallenge = udr[12..20].ToArray();
            CardCryptogram = udr[20..28].ToArray();

            return this;
        }

        #region >> Object

        /// <inheritdoc />
        public override string ToString()
        {
            return $"[{ScpDetails}] [Key Version:{KeyVersion:X2}, Identifier:{KeyIdentifier:X2}] " +
                $"[DiversificationData:{KeyDiversificationData.ToHexa()}] [KeyInformation:{KeyInformation.ToHexa()}] " +
                $"[CardChallenge:{CardChallenge.ToHexa()}] [CardCryptogram:{CardCryptogram.ToHexa()}]  (" +
                $"[Keys {Keys}] [Session {SessionKeys}]";
        }

        #endregion
    }
}
