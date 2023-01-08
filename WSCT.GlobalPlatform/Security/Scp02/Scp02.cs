using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform.Security.Cryptography;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Security.Scp02
{
    public class Scp02 : ISecureChannelProtocol
    {
        public Scp02(SecureChannelData scpData)
        {
            scpData.Specifics = new Scp02Specifics(scpData.ScpDetails.Options);
        }

        public bool AuthenticateCard(SecureChannelData scpData)
        {
            var cardCryptogram = Scp02Algorithms
                .GenerateCardCryptogram(scpData.SessionKeys.Enc, scpData.CardChallenge, scpData.HostChallenge);

            var cardAuthenticationResult = cardCryptogram.SequenceEqual(cardCryptogram);

            var hostCryptogram = Scp02Algorithms
                .GenerateHostCryptogram(scpData.SessionKeys.Enc, scpData.CardChallenge, scpData.HostChallenge);

            scpData.ParseHostCryptogram(hostCryptogram);

            return cardAuthenticationResult;
        }

        public SessionKeys GenerateSessionKeys(SecureChannelData scpData)
        {
            var scpSpecifics = (Scp02Specifics)scpData.Specifics;

            if (scpSpecifics.SubIdentifier.UseThreeKeys)
            {
                return Scp02Algorithms
                    .GenerateSessionKeys(scpData.Keys, scpData.CardChallenge.AsSpan(0, 2).ToArray());
            }
            else
            {
                // TODO
                throw new NotImplementedException("1 Secure Channel base key not yet implemented");
            }
        }

        public ExternalAuthenticateCommand Wrap(ExternalAuthenticateCommand cApdu, SecureChannelData scpData)
        {
            /*
			The Secure Channel mandates the use of a MAC on the EXTERNAL AUTHENTICATE command. Depending on
			the Session Security Level defined in the initiation of the Secure Channel, all other commands within the Secure
			Channel may require secure messaging and as such the use of a C-MAC.
			*/

            /* For the EXTERNAL AUTHENTICATE command, the ICV is set to binary zeroes */
            var scpSpecifics = (Scp02Specifics)scpData.Specifics;
            scpSpecifics.LastCMac = Constants.ICV;

            cApdu.Cla |= 0x04;
            cApdu.Lc += 8;

            var mac = Scp02Algorithms
                .GenerateCMac(scpData.SessionKeys.CMac, scpSpecifics.LastCMac, cApdu.BinaryCommand);

            scpSpecifics.LastCMac = mac;

            var udc = new byte[cApdu.Lc];
            Array.Copy(cApdu.Udc, 0, udc, 0, cApdu.Lc - 8);
            Array.Copy(mac, 0, udc, udc.Length - 8, 8);

            cApdu.Udc = udc;

            return cApdu;
        }

        public CommandAPDU Wrap(CommandAPDU cApdu, SecureChannelData scpData)
        {
            if ((scpData.SecurityLevel & SecurityLevel.CMac) != 0)
            {
                cApdu = WrapForCMac(cApdu, scpData);
            }

            if ((scpData.SecurityLevel & SecurityLevel.CDecryption) != 0)
            {
                cApdu = WrapForCDec(cApdu, scpData);
            }

            return cApdu;
        }

        private CommandAPDU WrapForCMac(CommandAPDU cApdu, SecureChannelData scpData)
        {
            var scpSpecifics = (Scp02Specifics)scpData.Specifics;

            if ((scpData.SecurityLevel & SecurityLevel.CMac) == 0)
            {
                return cApdu;
            }

            if (cApdu.HasLc is false)
            {
                cApdu.Udc = Array.Empty<byte>();
            }

            if (scpSpecifics.SubIdentifier.UseCMacOnUnmodifiedApdu is false)
            {
                cApdu.Cla |= 0x04;
                cApdu.Lc += 8;
            }

            // Save Le state and remove it from the C-APDU (C-MAC does not use it)
            bool initiallyHasLe = cApdu.HasLe;
            uint le = 0;
            if (initiallyHasLe)
            {
                le = cApdu.Le;
                cApdu.HasLe = false;
            }

            byte[] iv;
            if (scpSpecifics.SubIdentifier.UseIcvEncryptionforCMacSession)
            {
                // IV is obtained by encrypting LastCMac using first half of CMac session Key and LastCMac itself as the IV
                iv = scpSpecifics.LastCMac
                   .EncryptDesEcb(scpData.SessionKeys.CMac.AsSpan(0, 8).ToArray(), scpSpecifics.LastCMac);
            }
            else
            {
                iv = Constants.ICV;
            }

            // Calculate the C-APDU C-MAC
            var mac = Scp02Algorithms
                .GenerateCMac(scpData.SessionKeys.CMac, iv, cApdu.BinaryCommand);

            scpSpecifics.LastCMac = mac;

            // Store C-MAC in last bytes of the UDC
            var udc = new byte[cApdu.Lc];
            Array.Copy(cApdu.Udc, 0, udc, 0, cApdu.Lc - 8);
            Array.Copy(mac, 0, udc, udc.Length - 8, 8);

            cApdu.Udc = udc;

            // Restore Le state
            if (initiallyHasLe)
            {
                cApdu.Le = le;
            }

            if (scpSpecifics.SubIdentifier.UseCMacOnUnmodifiedApdu is true)
            {
                cApdu.Cla |= 0x04;
                cApdu.Lc += 8;
            }

            return cApdu;
        }

        private CommandAPDU WrapForCDec(CommandAPDU cApdu, SecureChannelData scpData)
        {
            if ((scpData.SecurityLevel & SecurityLevel.CDecryption) == 0)
            {
                return cApdu;
            }

            var dataLength = cApdu.HasLc ? (int)cApdu.Lc : 0;
            if (dataLength == 0)
            {
                return cApdu;
            }

            // Isolate clear text data and CMAC
            var macLength = (scpData.SecurityLevel & SecurityLevel.CMac) == 0 ? 0 : 8;
            dataLength -= macLength;

            var udc = cApdu.Udc.AsSpan();
            var data = cApdu.Udc.AsSpan(0, dataLength);
            var mac = cApdu.Udc.AsSpan(udc.Length - macLength);

            // Encrypt the padded clear text data
            var encryptedData = data
                .PadDataForDes()
                .EncryptTripleDesCbc(scpData.SessionKeys.Enc, Constants.ICV);

            // UDC = encrypted data | CMAC
            cApdu.Udc = new byte[encryptedData.Length + macLength];
            encryptedData.CopyTo(cApdu.Udc, 0);
            mac.CopyTo(cApdu.Udc.AsSpan(encryptedData.Length));

            return cApdu;
        }
    }
}
