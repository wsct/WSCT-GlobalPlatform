using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform.Security.Cryptography;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Security.Scp01
{
    internal class Scp01 : ISecureChannelProtocol
    {
        public Scp01(SecureChannelData scpData)
        {
            scpData.Specifics = new Scp01Specifics(scpData.ScpDetails.Options);
        }

        public bool AuthenticateCard(SecureChannelData scpData)
        {
            var cardCryptogram = Scp01Algorithms
                .GenerateCardCryptogram(scpData.SessionKeys.Enc, scpData.CardChallenge, scpData.HostChallenge);

            var cardAuthenticationResult = cardCryptogram.SequenceEqual(scpData.CardCryptogram);

            var hostCryptogram = Scp01Algorithms
                .GenerateHostCryptogram(scpData.SessionKeys.Enc, scpData.CardChallenge, scpData.HostChallenge);

            scpData.ParseHostCryptogram(hostCryptogram);

            return cardAuthenticationResult;
        }

        public SessionKeys GenerateSessionKeys(SecureChannelData scpData)
        {
            var scpSpecifics = (Scp01Specifics)scpData.Specifics;

            if (scpSpecifics.SubIdentifier.UseThreeKeys)
            {
                return Scp01Algorithms
                    .GenerateSessionKeys(scpData.Keys, scpData.CardChallenge, scpData.HostChallenge);
            }

            throw new NotImplementedException("Only 3 Secure Channel base keys is supported by SCP 01");
        }

        public ExternalAuthenticateCommand Wrap(ExternalAuthenticateCommand cApdu, SecureChannelData scpData)
        {
            /*
			The Secure Channel mandates the use of a MAC on the EXTERNAL AUTHENTICATE command. Depending on
			the Session Security Level defined in the initiation of the Secure Channel, all other commands within the Secure
			Channel may require secure messaging and as such the use of a C-MAC.
			*/

            /* For the EXTERNAL AUTHENTICATE command, the ICV is set to binary zeroes */
            var scpSpecifics = (Scp01Specifics)scpData.Specifics;
            scpSpecifics.LastCMac = Constants.ICV;

            cApdu.Cla |= 0x04;
            cApdu.Lc += 8;

            var mac = Scp01Algorithms
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

            // TODO Check if ENC is needed

            return cApdu;
        }

        private CommandAPDU WrapForCMac(CommandAPDU cApdu, SecureChannelData scpData)
        {
            var scpSpecifics = (Scp01Specifics)scpData.Specifics;

            if ((scpData.SecurityLevel & SecurityLevel.CMac) != 0)
            {
                if (cApdu.HasLc is false)
                {
                    cApdu.Udc = Array.Empty<byte>();
                }

                cApdu.Cla |= 0x04;
                cApdu.Lc += 8;

                // Save Le state and remove it from the C-APDU (C-MAC does not use it)
                var initiallyHasLe = cApdu.HasLe;
                uint le = 0;
                if (initiallyHasLe)
                {
                    le = cApdu.Le;
                    cApdu.HasLe = false;
                }

                byte[] iv;
                if (scpSpecifics.SubIdentifier.UseIcvEncryptionForCMacSession)
                {
                    // D.1.5 ICV Encryption
                    // As an enhancement to the C-MAC mechanism, the ICV is encrypted before being applied to the calculation of the
                    // next C-MAC. The encryption mechanism used is triple DES with the C-MAC session key. The first ICV of a
                    // session, used to generate the C-MAC on the EXTERNAL AUTHENTICATE command, is not encrypted.
                    iv = scpSpecifics.LastCMac
                       .EncryptTripleDesEcb(scpData.SessionKeys.CMac, scpSpecifics.LastCMac);
                }
                else
                {
                    iv = scpSpecifics.LastCMac;
                }

                // Calculate the C-APDU C-MAC
                var mac = Scp01Algorithms
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
            }

            return cApdu;
        }
    }
}
