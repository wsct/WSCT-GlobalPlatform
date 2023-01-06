namespace WSCT.GlobalPlatform.Security.Scp02
{
    public class Scp02Specifics : ISecureChannelSpecifics
    {
        public Scp02Specifics(byte subIdentifier)
        {
            LastCMac = Constants.ICV.ToArray();
            SubIdentifier = new Scp02SubIdentifier(subIdentifier);
        }

        public byte[] LastCMac { get; set; }

        public Scp02SubIdentifier SubIdentifier { get; set; }
    }
}
