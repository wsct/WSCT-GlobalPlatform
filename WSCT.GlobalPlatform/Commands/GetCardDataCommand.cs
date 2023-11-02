using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    /// <summary>
    /// GET DATA command to retrieve the tag '66': Card Data (or Security Domain Management Data)
    /// </summary>
    public class GetCardDataCommand : GetDataCommand
    {
        public GetCardDataCommand()
            : base(0x66)
        {
        }
    }
}
