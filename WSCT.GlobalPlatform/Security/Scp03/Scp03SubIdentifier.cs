namespace WSCT.GlobalPlatform.Security.Scp03;

/// <summary>
/// Options identifier for SCP03.
/// </summary>
public class Scp03SubIdentifier(byte subIdentifier)
{
    private readonly byte _subIdentifier = subIdentifier;

    /// <summary>"Random card challenge" or "Pseudo-random card challenge"</summary>
    public bool UseRandomCardChallenge => (_subIdentifier & 0x01) != 0x00;

    /// <summary>"R-MAC support" or "No R-MAC support"</summary>
    public bool UseRMacSupport => (_subIdentifier & 0x02) != 0x00;

    /// <summary>"R-ENCRYPTION support" or "No R-ENCRYPTION support"</summary>
    public bool UseREncryptionSupport => (_subIdentifier & 0x04) != 0x00;

    /// <summary>"C-MAC on unmodified APDU" or "C-MAC on modified APDU"</summary>
    public bool UseCMacOnUnmodifiedApdu => (_subIdentifier & 0x10) != 0x00;
}
