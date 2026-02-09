using WSCT.GlobalPlatform.Commands;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Security;

/// <summary>
/// Secure channel protocol.
/// </summary>
public interface ISecureChannelProtocol
{
    /// <summary>
    /// Executes the card authentication.
    /// </summary>
    /// <returns></returns>
    bool AuthenticateCard();

    /// <summary>
    /// Generates the session keys.
    /// </summary>
    /// <returns></returns>
    SessionKeys GenerateSessionKeys();

    /// <summary>
    /// Wraps the external authenticate command.
    /// </summary>
    /// <param name="externalAuthenticate"></param>
    /// <returns></returns>
    ExternalAuthenticateCommand Wrap(ExternalAuthenticateCommand externalAuthenticate);

    /// <summary>
    /// Wraps the command APDU.
    /// </summary>
    /// <param name="cApdu"></param>
    /// <returns></returns>
    CommandAPDU Wrap(CommandAPDU cApdu);
}
