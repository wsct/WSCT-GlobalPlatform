namespace WSCT.GlobalPlatform.Security
{
    [Flags]
    public enum SecurityLevel : byte
    {
        NoSecurity = 0x00,
        CMac = 0b0000_0001,
        CDecryption = 0b0000_0010,
        RMac = 0b0001_0000,
        REncryption = 0b0010_0000
    }
}
