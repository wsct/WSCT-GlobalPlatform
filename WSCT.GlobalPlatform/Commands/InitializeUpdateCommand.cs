using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Commands
{
    public class InitializeUpdateCommand : CommandAPDU
    {
        // 80 50 <KeyVersion> <KeyIndex> 08 <HostChallenge> 00
        public InitializeUpdateCommand(byte keySetVersion, byte keyIndex, byte[] hostChallenge)
            : base(0x80, 0x50, keySetVersion, keyIndex, 0x08, hostChallenge, 0x00)
        {
        }
    }
}
