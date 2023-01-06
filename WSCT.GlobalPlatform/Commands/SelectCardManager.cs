using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    public class SelectCardManager : CommandAPDU
    {
        // 00 A4 04 00 00
        public SelectCardManager()
            : base(0x00, 0xA4, 0x04, 0x00, 0x00)
        {
        }

        // 00 A4 04 Lc AID 00
        public SelectCardManager(byte[] aid)
            : base(0x00, 0xA4, 0x04, 0x00, (byte)aid.Length, aid, 0x00)
        {
        }
    }
}
