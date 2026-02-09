namespace WSCT.GlobalPlatform.Security;

/// <summary>
/// Constants used by the GlobalPlatform card.
/// </summary>
internal class Constants
{
    /// <summary>
    /// CMAC derivation.
    /// </summary>
    public static byte[] CMacDerivation = [0x01, 0x01];
    /// <summary>
    /// Encryption derivation.
    /// </summary>
    public static byte[] EncDerivation = [0x01, 0x82];
    /// <summary>
    /// Decryption derivation.
    /// </summary>
    public static byte[] DekDerivation = [0x01, 0x81];
    /// <summary>
    /// Response MAC derivation.
    /// </summary>
    public static byte[] RMacDerivation = [0x01, 0x02];
    /// <summary>
    /// Initial Chaining Vector.
    /// </summary>
    public static byte[] ICV = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    /// <summary>
    /// Padding.
    /// </summary>
    public static byte[] Padding = [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
}
