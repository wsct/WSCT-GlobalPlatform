namespace WSCT.GlobalPlatform.Security.Scp01
{
    public class Scp01Specifics(byte subIdentifier) : ISecureChannelSpecifics
    {
        public byte[] LastCMac { get; set; } = [.. Constants.ICV];

        public Scp01SubIdentifier SubIdentifier { get; set; } = new Scp01SubIdentifier(subIdentifier);
    }
}
