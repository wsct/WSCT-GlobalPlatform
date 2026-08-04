using WSCT.Helpers;

namespace WSCT.GlobalPlatform.Security;

/// <summary>
/// The data used to manage a secure channel.
/// </summary>
public abstract class SecureChannelData
{

    #region >> Properties (input of INITIALIZE UPDATE)

    public SecureChannelProtocolDetails ScpDetails { get; private set; }
    public byte KeyVersion { get; init; }
    public byte KeyIdentifier { get; init; }
    public byte[] HostChallenge { get; init; }

    #endregion

    #region >> Properties (output of INITIALIZE UPDATE)

    public byte[]? KeyDiversificationData { get; protected set; }
    public byte[]? KeyInformation { get; protected set; }
    public byte[]? CardChallenge { get; protected set; }
    public byte[]? CardCryptogram { get; protected set; }

    #endregion

    #region >> Properties * Keys

    public Keys? Keys { get; set; }

    public SessionKeys? SessionKeys { get; set; }

    #endregion

    #region >> Properties (input of EXTERNAL AUTHENTICATE)

    public SecurityLevel SecurityLevel { get; set; }
    public byte[]? HostCryptogram { get; private set; }

    #endregion

    /// <summary>
    /// Initializes a new instance of the <see cref="SecureChannelData"/> class.
    /// </summary>
    /// <param name="scp">The SCP details</param>
    /// <param name="keyVersion">Key version</param>
    /// <param name="keyIdentifier">Key identifier</param>
    /// <param name="hostChallenge">Host challenge</param>
    public SecureChannelData(SecureChannelProtocolDetails scp, byte keyVersion, byte keyIdentifier, Span<byte> hostChallenge)
    {
        ScpDetails = scp;
        KeyVersion = keyVersion;
        KeyIdentifier = keyIdentifier;
        HostChallenge = hostChallenge.ToArray();
    }

    public SecureChannelData ParseHostCryptogram(Span<byte> hostCryptogram)
    {
        HostCryptogram = hostCryptogram.ToArray();

        return this;
    }

    abstract public SecureChannelData ParseInitializeUpdateResponse(Span<byte> udr);

    #region >> Object

    /// <inheritdoc />
    public override string ToString()
    {
        return $"[{ScpDetails}] [Key Version:{KeyVersion:X2}, Identifier:{KeyIdentifier:X2}] " +
            $"[DiversificationData:{KeyDiversificationData.ToHexa()}] [KeyInformation:{KeyInformation.ToHexa()}] " +
            $"[CardChallenge:{CardChallenge.ToHexa()}] [CardCryptogram:{CardCryptogram.ToHexa()}]  (" +
            $"[Keys {Keys}] [Session {SessionKeys}]";
    }

    #endregion
}
