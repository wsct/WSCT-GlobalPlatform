namespace WSCT.GlobalPlatform.Security.Scp02;

public class Scp03SubIdentifier(byte subIdentifier)
{
    private readonly byte _subIdentifier = subIdentifier;


    private bool AreLowerNibbleBitsSet(byte data, byte mask) => (data & mask) == mask;
    private bool AreUpperNibbleBitsSet(byte data, byte mask) => AreLowerNibbleBitsSet((byte)(data >> 4),  mask);

    public bool UseS16Mode => AreLowerNibbleBitsSet(_subIdentifier, 0b1);
    public bool UsePseudoRandomCardChallenge => AreUpperNibbleBitsSet(_subIdentifier, 0b1);
    public bool UseInitiationModeExplicit => (_subIdentifier & 0x04) != 0x00;
    /// <summary>"ICV set to MAC over AID" or "ICV set to zero"</summary>
    public bool UseIcvSetToMacOverAid => (_subIdentifier & 0x08) != 0x00;
    /// <summary>"ICV encryption for C-MAC session" or "No ICV encryption"</summary>
    public bool UseIcvEncryptionForCMacSession => (_subIdentifier & 0x10) != 0x00;
    /// <summary>"R-MAC support" or "No R-MAC support"</summary>
    public bool UseREncSupport => AreUpperNibbleBitsSet(_subIdentifier, 0b10);
    /// <summary>"R-MAC support" or "No R-MAC support"</summary>
    public bool UseRMacSupport => AreUpperNibbleBitsSet(_subIdentifier, 0b11);

}