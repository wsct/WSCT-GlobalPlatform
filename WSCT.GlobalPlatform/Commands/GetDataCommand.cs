using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    /// <summary>
    /// The GET DATA command is used to retrieve either a single data object, which may be constructed, or a set of data
    /// objects. Reference control parameters P1 and P2 coding is used to define the specific data object tag
    /// </summary>
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
