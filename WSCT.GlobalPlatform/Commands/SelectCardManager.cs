using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands;

/// <summary>
/// Selects the GlobalPlatform card manager.
/// </summary>
public class SelectCardManager : CommandAPDU
{
    /// <summary>
    /// Create a SELECT command to select the default card manager.
    /// </summary>
    /// <remarks>
    /// 00 A4 04 00 00
    /// </remarks>
    public SelectCardManager()
        : base(0x00, 0xA4, 0x04, 0x00, 0x00)
    {
    }

    /// <summary>
    /// Create a SELECT command to select the card manager by AID.
    /// </summary>
    /// <param name="aid">The AID of the card manager to select.</param>
    /// 00 A4 04 Lc AID 00
    public SelectCardManager(byte[] aid)
        : base(0x00, 0xA4, 0x04, 0x00, (byte)aid.Length, aid, 0x00)
    {
    }
}
