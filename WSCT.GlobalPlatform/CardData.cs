using WSCT.GlobalPlatform.Security;
using WSCT.Helpers.BasicEncodingRules;

namespace WSCT.GlobalPlatform;

/// <summary>
/// Card data as returned by the <see cref="GlobalPlatformCard.ProcessGetCardData"/> command.
/// </summary>
public class CardData
{
    /// <summary>
    /// Global Platform ver sion.
    /// </summary>
    public byte[]? GlobalPlatformVersion { get; private set; }

    /// <summary>
    /// Supported SCPs.
    /// </summary>
    public IList<SecureChannelProtocolDetails> SupportedScps { get; private set; } = [];

    /// <summary>
    /// Card identification scheme.
    /// </summary>
    public byte[]? CardIdentificationScheme { get; private set; }

    /// <summary>
    /// Card configuration details.
    /// </summary>
    public byte[]? CardConfigurationDetails { get; private set; }

    /// <summary>
    /// Card details.
    /// </summary>
    public byte[]? CardDetails { get; private set; }

    /// <summary>
    /// Application tag 7.
    /// </summary>
    public byte[]? ApplicationTag7 { get; private set; }

    /// <summary>
    /// Application tag 8.
    /// </summary>
    public byte[]? ApplicationTag8 { get; private set; }

    #region >> Static Methods

    /// <summary>
    /// Creates a <see cref="CardData"/> instance from the card data bytes.
    /// </summary>
    /// <param name="cardDataBytes">Card data bytes.</param>
    /// <returns>A <see cref="CardData"/> instance.</returns>
    public static CardData Create(byte[] cardDataBytes)
    {
        return new CardData().Parse(cardDataBytes);
    }

    #endregion

    #region >> Private Methods

    private CardData Parse(byte[] cardDataBytes)
    {
        var tlvCardDataBytes = new TlvData(cardDataBytes);

        var tlvCardData73 = tlvCardDataBytes
            .GetTag(0x73)
            ?? throw new GlobalPlatformException("Tag 73 is missing");

        var applicationTag0 = tlvCardData73
            .GetTag((uint)CardDataTag.ApplicationTag0)
            ?? throw new GlobalPlatformException("Application tag 0 is missing");

        GlobalPlatformVersion = applicationTag0
            .GetTag(0x06).Value
            .AsSpan(7)
            .ToArray();

        var applicationTag3 = tlvCardData73
            .GetTag((uint)CardDataTag.ApplicationTag3)
            ?? throw new GlobalPlatformException("Application tag 3 is missing");

        CardIdentificationScheme = [.. applicationTag3.GetTag(0x06).Value];

        var applicationTag4 = tlvCardData73
            .GetTag((uint)CardDataTag.ApplicationTag4)
            ?? throw new GlobalPlatformException("Application tag 4 is missing");

        var secureChannelProtocols = applicationTag4.GetTags(0x06);
        SupportedScps = secureChannelProtocols
            .Select(scp => SecureChannelProtocolDetails.Create(scp.Value.AsSpan(7)))
            .ToArray();

        CardConfigurationDetails = tlvCardData73
            .GetTag((uint)CardDataTag.ApplicationTag5)
            ?.Value
            ?? [];

        CardDetails = tlvCardData73
            .GetTag((uint)CardDataTag.ApplicationTag6)
            ?.Value
            ?? [];

        ApplicationTag7 = tlvCardData73
            .GetTag((uint)CardDataTag.ApplicationTag7)
            ?.Value
            ?? [];

        ApplicationTag8 = tlvCardData73
            .GetTag((uint)CardDataTag.ApplicationTag8)
            ?.Value
            ?? [];

        return this;
    }

    #endregion
}
