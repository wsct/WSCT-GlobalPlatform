namespace WSCT.GlobalPlatform.Security
{
    internal class Constants
    {
        public static byte[] CMacDerivation = new byte[] { 0x01, 0x01 };
        public static byte[] EncDerivation = new byte[] { 0x01, 0x82 };
        public static byte[] DekDerivation = new byte[] { 0x01, 0x81 };
        public static byte[] RMacDerivation = new byte[] { 0x01, 0x02 };
        public static byte[] ICV = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        public static byte[] Padding = new byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    }
}
