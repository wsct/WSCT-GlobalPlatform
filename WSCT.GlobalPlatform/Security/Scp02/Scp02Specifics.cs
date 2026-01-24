namespace WSCT.GlobalPlatform.Security.Scp02
{
    public class Scp02Specifics(byte subIdentifier) : ISecureChannelSpecifics
    {
        public byte[] LastCMac { get; set; } = [.. Constants.ICV];

        public Scp02SubIdentifier SubIdentifier { get; set; } = new Scp02SubIdentifier(subIdentifier);
    }
}
