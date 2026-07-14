using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands;

/// <summary>
/// The INSTALL [for install] command is used to install an application on the card.
/// </summary>
/// <remarks>
/// The INSTALL command is issued to a Security Domain to initiate or perform the various steps required for 
/// Card Content management.
/// </remarks>
public class InstallForInstallCommand : CommandAPDU
{
    public InstallForInstallCommand(byte[] parameters)
        : base(0x80, 0xE6, 0x04, 0x00, (uint)parameters.Length, parameters, 0x00)
    {
    }

    public InstallForInstallCommand(Span<byte> loadFileAid, Span<byte> moduleAid, Span<byte> applicationAid, Span<byte> privileges, Span<byte> installParameters, Span<byte> installToken)
        : base(0x80, 0xE6, 0x04, 0x00, 0x00)
    {
        Udc = [
            (byte)loadFileAid.Length,
            ..loadFileAid,
            (byte)moduleAid.Length,
            ..moduleAid,
            (byte)applicationAid.Length,
            ..applicationAid,
            (byte)privileges.Length,
            ..privileges,
            (byte)installParameters.Length,
            ..installParameters,
            (byte)installToken.Length,
            ..installToken
        ];
    }
}
