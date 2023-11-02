namespace WSCT.GlobalPlatform.Security.Scp02
{
    public class Scp02SubIdentifier
    {
        private readonly byte _subIdentifier;

        public Scp02SubIdentifier(byte subIdentifier)
        {
            _subIdentifier = subIdentifier;
        }

        // TODO Externalize in Scp02 (factory?)
        /// <summary>"3 Secure Channel Keys" or "1 Secure Channel base key"</summary>
        public bool UseThreeKeys => (_subIdentifier & 0x01) != 0x00;
        /// <summary>"C-MAC on unmodified APDU" or "C-MAC on modified APDU"</summary>
        public bool UseCMacOnUnmodifiedApdu => (_subIdentifier & 0x02) != 0x00;
        /// <summary>"Initiation mode explicit" or "Initiation mode implicit"</summary>
        public bool UseInitiationModeExplicit => (_subIdentifier & 0x04) != 0x00;
        /// <summary>"ICV set to MAC over AID" or "ICV set to zero"</summary>
        public bool UseIcvSetToMacOverAid => (_subIdentifier & 0x08) != 0x00;
        /// <summary>"ICV encryption for C-MAC session" or "No ICV encryption"</summary>
        public bool UseIcvEncryptionForCMacSession => (_subIdentifier & 0x10) != 0x00;
        /// <summary>"R-MAC support" or "No R-MAC support"</summary>
        public bool UseRMacSupport => (_subIdentifier & 0x20) != 0x00;
        /// <summary>"Well-known pseudo-random algorithm (card challenge)" or "Unspecified card challenge generation method"</summary>
        public bool UseWellKnownPseudoRandom => (_subIdentifier & 0x40) != 0x00;
    }
}
