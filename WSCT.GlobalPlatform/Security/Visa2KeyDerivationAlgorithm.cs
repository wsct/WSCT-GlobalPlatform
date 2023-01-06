using WSCT.GlobalPlatform.Security.Cryptography;

namespace WSCT.GlobalPlatform.Security
{
    internal class Visa2KeyDerivationAlgorithm : IKeyDerivationAlgorithm
    {
        public Keys Generate(byte[] baseKeyDiversificationData, byte[] masterKey)
        {
            /*
			Key Diversification data VISA 2
			KDCAUTH/ENC xxh xxh || IC serial number || F0h 01h ||xxh xxh || IC serial number
			||0Fh 01h
			KDCMAC xxh xxh || IC serial number || F0h 02h ||xxh xxh || IC serial number
			|| 0Fh 02h
			KDCKEK xxh xxh || IC serial number || F0h 03h || xxh xxh || IC serial number
			|| 0Fh 03h

			xxh xxh is the last (rightmost) two bytes of the Card Manager AID.
			IC Serial Number is taken from the CPLC data.
			*/

            // ENC
            var keyDiversificationData = new byte[16];
            Array.Copy(baseKeyDiversificationData, 0, keyDiversificationData, 0, 2);
            Array.Copy(baseKeyDiversificationData, 4, keyDiversificationData, 2, 4);
            keyDiversificationData[6] = 0xF0;
            keyDiversificationData[7] = 0x01;
            Array.Copy(baseKeyDiversificationData, 0, keyDiversificationData, 8, 2);
            Array.Copy(baseKeyDiversificationData, 4, keyDiversificationData, 10, 4);
            keyDiversificationData[14] = 0x0F;
            keyDiversificationData[15] = 0x01;

            var encStream = keyDiversificationData
                .EncryptTripleDesEcb(masterKey, Constants.ICV);
            var enc = encStream.ToArray();

            // MAC
            keyDiversificationData[6] = 0xF0;
            keyDiversificationData[7] = 0x02;
            keyDiversificationData[14] = 0x0F;
            keyDiversificationData[15] = 0x02;

            var macStream = keyDiversificationData
                .EncryptTripleDesEcb(masterKey, Constants.ICV);
            var mac = macStream.ToArray();

            // DEK
            keyDiversificationData[6] = 0xF0;
            keyDiversificationData[7] = 0x03;
            keyDiversificationData[14] = 0x0F;
            keyDiversificationData[15] = 0x03;

            var dekStream = keyDiversificationData
                .EncryptTripleDesEcb(masterKey, Constants.ICV);
            var dek = dekStream.ToArray();

            return new Keys(enc, mac, dek);
        }
    }

}
