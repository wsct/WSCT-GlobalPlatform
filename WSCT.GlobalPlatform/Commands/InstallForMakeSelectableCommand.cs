using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands;

/// <summary>
/// The INSTALL [for make selectable] command is used to make an installed application selectable.
/// </summary>
/// <remarks>
/// The INSTALL command is issued to a Security Domain to initiate or perform the various steps required for 
/// Card Content management.
/// </remarks>
public class InstallForMakeSelectableCommand : CommandAPDU
{
    public InstallForMakeSelectableCommand(byte[] parameters)
        : base(0x80, 0xE6, 0x08, 0x00, (uint)parameters.Length, parameters, 0x00)
    {
    }

    public InstallForMakeSelectableCommand(Span<byte> applicationAid, Span<byte> privileges, Span<byte> installParameters, Span<byte> installToken)
        : base(0x80, 0xE6, 0x08, 0x00, 0x00)
    {
        Udc = [
            0x00, 0x00,
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
