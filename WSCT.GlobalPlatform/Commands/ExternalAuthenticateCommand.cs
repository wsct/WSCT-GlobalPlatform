using WSCT.GlobalPlatform.Security;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands;

/// <summary>
/// The EXTERNAL AUTHENTICATE command is used by the card, during explicit initiation of a Secure Channel,
/// to authenticate the host and to determine the level of security required for all subsequent commands.
/// </summary>
public class ExternalAuthenticateCommand : CommandAPDU
{
    // new CommandAPDU(0x84, 0x82, securityLevel, 0x00, 0x10, hostAuthenticationCryptogram);
    public ExternalAuthenticateCommand(SecurityLevel securityLevel, byte[] hostAuthenticationCryptogram)
        : base(0x84, 0x82, (byte)securityLevel, 0x00, (uint)hostAuthenticationCryptogram.Length, hostAuthenticationCryptogram)
    {
    }
}
