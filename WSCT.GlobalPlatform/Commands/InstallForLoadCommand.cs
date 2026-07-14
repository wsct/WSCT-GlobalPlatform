using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands;

/// <summary>
/// The INSTALL [for load] command is used to load an application on the card.
/// </summary>
/// <remarks>
/// The INSTALL command is issued to a Security Domain to initiate or perform the various steps required for 
/// Card Content management.
/// </remarks>
public class InstallForLoadCommand : CommandAPDU
{
    public InstallForLoadCommand(byte[] parameters)
        : base(0x80, 0xE6, 0x02, 0x00, (uint)parameters.Length, parameters, 0x00)
    {
    }

    public InstallForLoadCommand(Span<byte> loadFileAid, Span<byte> securityDomainAid, Span<byte> loadFileDataBlockHash, Span<byte> loadParameters, Span<byte> loadToken)
        : base(0x80, 0xE6, 0x02, 0x00, 0x00)
    {
        Udc = [
            (byte)loadFileAid.Length,
            ..loadFileAid,
            (byte)securityDomainAid.Length,
            ..securityDomainAid,
            (byte)loadFileDataBlockHash.Length,
            ..loadFileDataBlockHash,
            (byte)loadParameters.Length,
            ..loadParameters,
            (byte)loadToken.Length,
            ..loadToken
        ];
    }
}
