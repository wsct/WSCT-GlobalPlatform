using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    public class GetCardDataCommand : CommandAPDU
    {
        public GetCardDataCommand() : base(0x00, 0xCA, 0x00, 0x66, 0x00)
        {
        }
    }
}
