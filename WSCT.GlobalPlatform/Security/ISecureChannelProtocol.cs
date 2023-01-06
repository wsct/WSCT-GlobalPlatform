using WSCT.GlobalPlatform.Commands;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Security
{
    public interface ISecureChannelProtocol
    {
        bool AuthenticateCard(SecureChannelData scpData);

        SessionKeys GenerateSessionKeys(SecureChannelData scpData);

        ExternalAuthenticateCommand Wrap(ExternalAuthenticateCommand externalAuthenticate, SecureChannelData scpData);

        CommandAPDU Wrap(CommandAPDU cApdu, SecureChannelData scpData);
    }
}
