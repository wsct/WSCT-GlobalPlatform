namespace WSCT.GlobalPlatform.Security.Scp01
{
    public class Scp01Specifics : ISecureChannelSpecifics
    {
        public Scp01Specifics(byte subIdentifier)
        {
            LastCMac = Constants.ICV.ToArray();
            SubIdentifier = new Scp01SubIdentifier(subIdentifier);
        }

        public byte[] LastCMac { get; set; }

        public Scp01SubIdentifier SubIdentifier { get; set; }
    }
}
