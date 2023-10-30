using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    public class LoadCommand : CommandAPDU
    {
        public LoadCommand(bool lastBlock, byte blockNumber, byte[] loadData)
            : base(0x80, 0xE8, lastBlock ? (byte)0x80 : (byte)0x00, blockNumber, (uint)loadData.Length, loadData, 0x00)
        {
        }
    }
}
