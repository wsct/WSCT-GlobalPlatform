using WSCT.GlobalPlatform.Commands;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Security
{
    /// <summary>
    /// Secure channel protocol.
    /// </summary>
    public interface ISecureChannelProtocol
    {
        /// <summary>
        /// Executes the card authentication.
        /// </summary>
        /// <param name="scpData"></param>
        /// <returns></returns>
        bool AuthenticateCard(SecureChannelData scpData);

        /// <summary>
        /// Generates the session keys.
        /// </summary>
        /// <param name="scpData"></param>
        /// <returns></returns>
        SessionKeys GenerateSessionKeys(SecureChannelData scpData);

        /// <summary>
        /// Wraps the external authenticate command.
        /// </summary>
        /// <param name="externalAuthenticate"></param>
        /// <param name="scpData"></param>
        /// <returns></returns>
        ExternalAuthenticateCommand Wrap(ExternalAuthenticateCommand externalAuthenticate, SecureChannelData scpData);

        /// <summary>
        /// Wraps the command APDU.
        /// </summary>
        /// <param name="cApdu"></param>
        /// <param name="scpData"></param>
        /// <returns></returns>
        CommandAPDU Wrap(CommandAPDU cApdu, SecureChannelData scpData);
    }
}
