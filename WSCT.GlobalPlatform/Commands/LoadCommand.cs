using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    /// <summary>
    /// The LOAD command is used to load data into the card.
    /// </summary>
    /// <remarks>
    /// The LOAD command must be preceded by an INSTALL [for load] command.
    /// </remarks>
    public class LoadCommand : CommandAPDU
    {
        public LoadCommand(bool lastBlock, byte blockNumber, byte[] loadData)
            : base(0x80, 0xE8, lastBlock ? (byte)0x80 : (byte)0x00, blockNumber, (uint)loadData.Length, loadData, 0x00)
        {
        }
    }
}
