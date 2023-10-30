using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    public class InstallForInstallCommand : CommandAPDU
    {
        public InstallForInstallCommand(byte[] parameters)
            : base(0x80, 0xE6, 0x04, 0x00, (uint)parameters.Length, parameters, 0x00)
        {
        }

        public InstallForInstallCommand(Span<byte> loadFileAid, Span<byte> moduleAid, Span<byte> applicationAid, Span<byte> privileges, Span<byte> installParameters, Span<byte> installToken)
            : base(0x80, 0xE6, 0x04, 0x00, 0x00)
        {
            Udc = new byte[1 + loadFileAid.Length + 1 + moduleAid.Length + 1 + applicationAid.Length + 1 + privileges.Length + 1 + installParameters.Length + 1 + installToken.Length];

            var cursor = Udc.AsSpan();

            cursor[0] = (byte)loadFileAid.Length;
            cursor = cursor[1..];
            loadFileAid.CopyTo(cursor);
            cursor = cursor[loadFileAid.Length..];

            cursor[0] = (byte)moduleAid.Length;
            cursor = cursor[1..];
            moduleAid.CopyTo(cursor);
            cursor = cursor[moduleAid.Length..];

            cursor[0] = (byte)applicationAid.Length;
            cursor = cursor[1..];
            applicationAid.CopyTo(cursor);
            cursor = cursor[applicationAid.Length..];

            cursor[0] = (byte)privileges.Length;
            cursor = cursor[1..];
            privileges.CopyTo(cursor);
            cursor = cursor[privileges.Length..];

            cursor[0] = (byte)installParameters.Length;
            cursor = cursor[1..];
            installParameters.CopyTo(cursor);
            cursor = cursor[installParameters.Length..];

            cursor[0] = (byte)installToken.Length;
            cursor = cursor[1..];
            installToken.CopyTo(cursor);
        }
    }
}
