using WSCT.GlobalPlatform.Security;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    public class ExternalAuthenticateCommand : CommandAPDU
    {
        // new CommandAPDU(0x84, 0x82, securityLevel, 0x00, 0x10, hostAuthenticationCryptogram);
        public ExternalAuthenticateCommand(SecurityLevel securityLevel, byte[] hostAuthenticationCryptogram)
            : base(0x84, 0x82, (byte)securityLevel, 0x00, (uint)hostAuthenticationCryptogram.Length, hostAuthenticationCryptogram)
        {
        }
    }
}
