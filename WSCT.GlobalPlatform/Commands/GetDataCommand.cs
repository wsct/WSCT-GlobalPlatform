using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    public class GetDataCommand : CommandAPDU
    {
        public GetDataCommand(ushort tag)
            : base(0x80, 0xCA, (byte)(tag / 0x0100), (byte)(tag % 0x0100), 0x00)
        {
        }

        public GetDataCommand(int tag) : this((ushort)tag)
        {
        }
    }
}
