using WSCT.Helpers.BasicEncodingRules;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    /// <summary>
    /// The GET STATUS command is used to retrieve Issuer Security Domain, Executable Load File, Executable Module,
    /// Application or Security Domain Life Cycle status information according to a given match/search criteria.
    /// </summary>
    public class GetStatusCommand : CommandAPDU
    {
        public GetStatusCommand(Subset subset, Span<byte> applicationAid, Occurrence occurrence,
            ResponseFormat responseFormat)
            : base(0x80, 0xF2, (byte)subset, (byte)((byte)occurrence | (byte)responseFormat), 0x00)
        {
            Udc = new TlvData(0x4F, (uint)applicationAid.Length, applicationAid.ToArray()).ToByteArray();
        }

        public enum Subset : byte
        {
            IssuerSecurityDomain = 0x80,
            ApplicationAndSupplementarySecurityDomains = 0x40,
            ExecutableLoadFiles = 0x20,
            ExecutableLoadFilesAndTheirModules = 0x10
        }

        public enum Occurrence : byte
        {
            /// <summary>
            /// Get first or all occurrence(s)
            /// </summary>
            FirstOrAll = 0x00,
            /// <summary>
            /// Get next occurrence(s)
            /// </summary>
            Next = 0x01
        }

        public enum ResponseFormat : byte
        {
            /// <summary>
            /// Raw format is deprecated since GP 2.2
            /// </summary>
            Deprecated = 0x00,
            /// <summary>
            /// Available since GP 2.2 or Amendment A of GP 2.1.1
            /// </summary>
            Tlv = 0x02
        }
    }
}
