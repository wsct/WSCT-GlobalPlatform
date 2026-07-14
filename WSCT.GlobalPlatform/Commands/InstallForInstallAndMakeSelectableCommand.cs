using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands;

/// <summary>
/// The INSTALL [for install and make selectable] command is used to install an application on the card and 
/// make it selectable.
/// </summary>
/// <remarks>
/// The INSTALL command is issued to a Security Domain to initiate or perform the various steps required for 
/// Card Content management.
/// </remarks>
public class InstallForInstallAndMakeSelectableCommand : CommandAPDU
{
    // new CommandAPDU(0x84, 0xE6, 0x02, 0x00, Lc, UDC, 0x00)
    public InstallForInstallAndMakeSelectableCommand(byte[] parameters)
        : base(0x80, 0xE6, 0x0C, 0x00, (uint)parameters.Length, parameters, 0x00)
    {
    }

    public InstallForInstallAndMakeSelectableCommand(Span<byte> loadFileAid, Span<byte> moduleAid, Span<byte> applicationAid, Span<byte> privileges, Span<byte> installParameters, Span<byte> installToken)
        : base(0x80, 0xE6, 0x0C, 0x00, 0x00)
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
