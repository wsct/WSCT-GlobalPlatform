namespace WSCT.GlobalPlatform.Security.Scp01
{
    public class Scp01SubIdentifier
    {
        private readonly byte _subIdentifier;

        public Scp01SubIdentifier(byte subIdentifier)
        {
            _subIdentifier = subIdentifier;
        }

        // TODO Externalize in Scp01 (factory?)
        /// <summary>"3 Secure Channel Keys" or "1 Secure Channel base key"</summary>
        public bool UseThreeKeys => (_subIdentifier & 0x01) != 0x00;
        /// <summary>"Initiation mode explicit" or "Initiation mode implicit"</summary>
        public bool UseInitiationModeExplicit => (_subIdentifier & 0x04) != 0x00;
        /// <summary>"ICV encryption for C-MAC session" or "No ICV encryption"</summary>
        public bool UseIcvEncryptionForCMacSession => (_subIdentifier & 0x10) != 0x00;
    }
}
