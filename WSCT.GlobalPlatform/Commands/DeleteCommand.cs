using WSCT.Helpers.BasicEncodingRules;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    /// <summary>
    /// The DELETE command is used to delete a uniquely identifiable object such as an Executable Load File,
    /// an Application, an Executable Load File and its related Applications or a key
    /// </summary>
    public class DeleteCommand : CommandAPDU
    {
        public DeleteCommand(byte[] parameters)
            : base(0x80, 0xE4, 0x00, 0x80, (uint)parameters.Length, parameters, 0x00)
        {
        }

        public DeleteCommand(Span<byte> aid, bool deleteRelated = true)
            : base(0x80, 0xE4, 0x00, deleteRelated ? (byte)0x80 : (byte)0x00, 0x00)
        {
            Udc = new TlvData(0x4F, (uint)aid.Length, aid.ToArray()).ToByteArray();
        }

        public DeleteCommand(Span<byte> aid, Span<byte> tokenIssuerId, Span<byte> cardImageNumber, Span<byte> applicationProviderIdentifier, Span<byte> tokenIdentifierNumber, Span<byte> deleteToken, bool deleteRelated)
            : base(0x80, 0xE4, 0x00, deleteRelated ? (byte)0x80 : (byte)0x00, 0x00)
        {
            var tlvData = new TlvData();
            tlvData.InnerTlvs.Add(new TlvData(0x4F, (uint)aid.Length, aid.ToArray()));

            var tlvSignature = new TlvData(0xB6, 0x00, Array.Empty<byte>());

            AddWhenNotEmpty(tlvSignature, 0x42, tokenIssuerId);
            AddWhenNotEmpty(tlvSignature, 0x45, cardImageNumber);
            AddWhenNotEmpty(tlvSignature, 0x5F20, applicationProviderIdentifier);
            AddWhenNotEmpty(tlvSignature, 0x93, tokenIdentifierNumber);

            if (tlvSignature.InnerTlvs.Any())
            {
                tlvData.InnerTlvs.Add(tlvSignature);
            }

            AddWhenNotEmpty(tlvData, 0x9E, deleteToken);
        }

        #region >> Private Methods

        private static void AddWhenNotEmpty(TlvData tlv, uint tag, Span<byte> data)
        {
            if (data.IsEmpty is false)
            {
                tlv.InnerTlvs.Add(new TlvData(tag, (uint)data.Length, data.ToArray()));
            }
        }

        #endregion
    }
}
