namespace WSCT.GlobalPlatform.Security
{
    /// <summary>
    /// Security level flags of the secure channel.
    /// </summary>
    [Flags]
    public enum SecurityLevel : byte
    {
        /// <summary>
        /// No security.
        /// </summary>
        NoSecurity = 0x00,
        /// <summary>
        /// C-MAC is used.
        /// </summary>
        CMac = 0b0000_0001,
        /// <summary>
        /// CDecryption is used.
        /// </summary>
        CDecryption = 0b0000_0010,
        /// <summary>
        /// R-MAC is used.
        /// </summary>
        RMac = 0b0001_0000,
        /// <summary>
        /// R-ENCRYPTION is used.
        /// </summary>
        REncryption = 0b0010_0000
    }
}
