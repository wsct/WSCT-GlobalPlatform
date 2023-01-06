using WSCT.GlobalPlatform.Security;
using WSCT.Helpers.BasicEncodingRules;

namespace WSCT.GlobalPlatform
{
    public class CardData
    {
        public byte[]? GlobalPlatformVersion { get; private set; }
        public IList<SecureChannelProtocolDetails>? SupportedScps { get; private set; }
        public byte[]? CardIdentificationScheme { get; private set; }
        public byte[]? CardConfigurationDetails { get; private set; }
        public byte[]? CardDetails { get; private set; }
        public byte[]? ApplicationTag7 { get; private set; }
        public byte[]? ApplicationTag8 { get; private set; }

        #region >> Static Methods

        public static CardData Create(byte[] cardDataBytes)
        {
            return new CardData().Parse(cardDataBytes);
        }

        #endregion

        #region >> Private Methods

        private CardData Parse(byte[] cardDataBytes)
        {
            var tlvCardDataBytes = new TlvData(cardDataBytes);

            var tlvCardData73 = tlvCardDataBytes
                .GetTag(0x73)
                ?? throw new GlobalPlatformException("Tag 73 is missing");

            var applicationTag0 = tlvCardData73
                .GetTag((uint)CardDataTag.ApplicationTag0)
                ?? throw new GlobalPlatformException("Application tag 0 is missing");

            GlobalPlatformVersion = applicationTag0
                .GetTag(0x06).Value
                .AsSpan(7)
                .ToArray();

            var applicationTag3 = tlvCardData73
                .GetTag((uint)CardDataTag.ApplicationTag3)
                ?? throw new GlobalPlatformException("Application tag 3 is missing");

            CardIdentificationScheme = applicationTag3.GetTag(0x06).Value.AsSpan().ToArray();

            var applicationTag4 = tlvCardData73
                .GetTag((uint)CardDataTag.ApplicationTag4)
                ?? throw new GlobalPlatformException("Application tag 4 is missing");

            var secureChannelProtocols = applicationTag4.GetTags(0x06);
            SupportedScps = secureChannelProtocols
                .Select(scp => SecureChannelProtocolDetails.Create(scp.Value.AsSpan(7)))
                .ToArray();

            CardConfigurationDetails = tlvCardData73
                .GetTag((uint)CardDataTag.ApplicationTag5)
                ?.Value
                ?? Array.Empty<byte>();

            CardDetails = tlvCardData73
                .GetTag((uint)CardDataTag.ApplicationTag6)
                ?.Value
                ?? Array.Empty<byte>();

            ApplicationTag7 = tlvCardData73
                .GetTag((uint)CardDataTag.ApplicationTag7)
                ?.Value
                ?? Array.Empty<byte>();

            ApplicationTag8 = tlvCardData73
                .GetTag((uint)CardDataTag.ApplicationTag8)
                ?.Value
                ?? Array.Empty<byte>();

            return this;
        }

        #endregion
    }
}
