using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    public class InstallForLoadCommand : CommandAPDU
    {
        public InstallForLoadCommand(byte[] parameters)
            : base(0x80, 0xE6, 0x02, 0x00, (uint)parameters.Length, parameters, 0x00)
        {
        }

        public InstallForLoadCommand(Span<byte> loadFileAid, Span<byte> securityDomainAid, Span<byte> loadFileDataBlockHash, Span<byte> loadParameters, Span<byte> loadToken)
            : base(0x80, 0xE6, 0x02, 0x00, 0x00)
        {
            Udc = new byte[1 + loadFileAid.Length + 1 + securityDomainAid.Length + 3];

            var cursor = Udc.AsSpan();

            cursor[0] = (byte)loadFileAid.Length;
            cursor = cursor[1..];
            loadFileAid.CopyTo(cursor);
            cursor = cursor[loadFileAid.Length..];

            cursor[0] = (byte)securityDomainAid.Length;
            cursor = cursor[1..];
            securityDomainAid.CopyTo(cursor);
            cursor = cursor[securityDomainAid.Length..];

            cursor[0] = (byte)loadFileDataBlockHash.Length;
            cursor = cursor[1..];
            loadFileDataBlockHash.CopyTo(cursor);
            cursor = cursor[loadFileDataBlockHash.Length..];

            cursor[0] = (byte)loadParameters.Length;
            cursor = cursor[1..];
            loadParameters.CopyTo(cursor);
            cursor = cursor[loadParameters.Length..];

            cursor[0] = (byte)loadToken.Length;
            cursor = cursor[1..];
            loadToken.CopyTo(cursor);
        }
    }
}
