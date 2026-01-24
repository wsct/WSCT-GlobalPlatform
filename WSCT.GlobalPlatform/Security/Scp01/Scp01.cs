using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform.Security.Cryptography;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Security.Scp01
{
    internal class Scp01 : ISecureChannelProtocol
    {
        /// <summary>
        /// Instance shared with the <see cref="GlobalPlatformCard"/> instance.
        /// </summary>
        private readonly SecureChannelData _scpData;

        public Scp01(SecureChannelData scpData)
        {
            GlobalPlatformException.ThrowIfNull(scpData);

            _scpData = scpData;
            _scpData.Specifics = new Scp01Specifics(_scpData.ScpDetails.Options);
        }

        /// <inheritdoc />
        public bool AuthenticateCard()
        {
            GlobalPlatformException.ThrowIfNull(_scpData.SessionKeys);
            GlobalPlatformException.ThrowIfNull(_scpData.CardChallenge, "Card challenge missing: Call ProcessInitializeUpdate(...) first");
            GlobalPlatformException.ThrowIfNull(_scpData.HostChallenge, "Host challenge missing: Call ProcessInitializeUpdate(...) first");
            GlobalPlatformException.ThrowIfNull(_scpData.CardCryptogram, "Card cryptogram missing: Call ProcessInitializeUpdate(...) first");

            var cardCryptogram = Scp01Algorithms
                .GenerateCardCryptogram(_scpData.SessionKeys.Enc, _scpData.CardChallenge, _scpData.HostChallenge);

            var cardAuthenticationResult = cardCryptogram.SequenceEqual(_scpData.CardCryptogram);

            var hostCryptogram = Scp01Algorithms
                .GenerateHostCryptogram(_scpData.SessionKeys.Enc, _scpData.CardChallenge, _scpData.HostChallenge);

            _scpData.ParseHostCryptogram(hostCryptogram);

            return cardAuthenticationResult;
        }

        /// <inheritdoc />
        public SessionKeys GenerateSessionKeys()
        {
            GlobalPlatformException.ThrowIfNull(_scpData.Specifics);

            var scpSpecifics = (Scp01Specifics)_scpData.Specifics;

            GlobalPlatformException.ThrowIfNull(_scpData.Keys);
            GlobalPlatformException.ThrowIfNull(_scpData.CardChallenge, "Card challenge missing: Call ProcessInitializeUpdate(...) first");
            GlobalPlatformException.ThrowIfNull(_scpData.HostChallenge, "Host challenge missing: Call ProcessInitializeUpdate(...) first");

            if (scpSpecifics.SubIdentifier.UseThreeKeys)
            {
                return Scp01Algorithms
                    .GenerateSessionKeys(_scpData.Keys, _scpData.CardChallenge, _scpData.HostChallenge);
            }

            throw new NotImplementedException("Only 3 Secure Channel base keys is supported by SCP 01");
        }

        /// <inheritdoc />
        public ExternalAuthenticateCommand Wrap(ExternalAuthenticateCommand cApdu)
        {
            /*
			The Secure Channel mandates the use of a MAC on the EXTERNAL AUTHENTICATE command. Depending on
			the Session Security Level defined in the initiation of the Secure Channel, all other commands within the Secure
			Channel may require secure messaging and as such the use of a C-MAC.
			*/

            /* For the EXTERNAL AUTHENTICATE command, the ICV is set to binary zeroes */

            GlobalPlatformException.ThrowIfNull(_scpData.Specifics);
            GlobalPlatformException.ThrowIfNull(_scpData.SessionKeys);

            var scpSpecifics = (Scp01Specifics)_scpData.Specifics;
            scpSpecifics.LastCMac = Constants.ICV;

            cApdu.Cla |= 0x04;
            cApdu.Lc += 8;

            var mac = Scp01Algorithms
                .GenerateCMac(_scpData.SessionKeys.CMac, scpSpecifics.LastCMac, cApdu.BinaryCommand);

            scpSpecifics.LastCMac = mac;

            var udc = new byte[cApdu.Lc];
            Array.Copy(cApdu.Udc, 0, udc, 0, cApdu.Lc - 8);
            Array.Copy(mac, 0, udc, udc.Length - 8, 8);

            cApdu.Udc = udc;

            return cApdu;
        }

        /// <inheritdoc />
        public CommandAPDU Wrap(CommandAPDU cApdu)
        {
            if ((_scpData.SecurityLevel & SecurityLevel.CMac) != 0)
            {
                cApdu = WrapForCMac(cApdu);
            }

            if ((_scpData.SecurityLevel & SecurityLevel.CDecryption) != 0)
            {
                cApdu = WrapForCDec(cApdu);
            }

            return cApdu;
        }

        private CommandAPDU WrapForCMac(CommandAPDU cApdu)
        {
            GlobalPlatformException.ThrowIfNull(_scpData.Specifics);
            GlobalPlatformException.ThrowIfNull(_scpData.SessionKeys);

            var scpSpecifics = (Scp01Specifics)_scpData.Specifics;

            if ((_scpData.SecurityLevel & SecurityLevel.CMac) != 0)
            {
                if (cApdu.HasLc is false)
                {
                    cApdu.Udc = [];
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
                       .EncryptTripleDesEcb(_scpData.SessionKeys.CMac, scpSpecifics.LastCMac);
                }
                else
                {
                    iv = scpSpecifics.LastCMac;
                }

                // Calculate the C-APDU C-MAC
                var mac = Scp01Algorithms
                    .GenerateCMac(_scpData.SessionKeys.CMac, iv, cApdu.BinaryCommand);

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

        private CommandAPDU WrapForCDec(CommandAPDU cApdu)
        {
            GlobalPlatformException.ThrowIfNull(_scpData.SessionKeys);

            if ((_scpData.SecurityLevel & SecurityLevel.CDecryption) == 0)
            {
                return cApdu;
            }

            if (cApdu.HasLc is false)
            {
                return cApdu;
            }

            // Isolate UDC and CMAC
            var macLength = (_scpData.SecurityLevel & SecurityLevel.CMac) == 0 ? 0 : 8;
            var originalLc = cApdu.Udc.Length - macLength;

            var originalUdc = cApdu.Udc.AsSpan(0, originalLc);
            var mac = cApdu.Udc.AsSpan(originalLc);

            // Build the original Lc UDC bytes
            var originalLcUdc = new byte[1 + originalLc].AsSpan();

            originalLcUdc[0] = (byte)originalLc;
            originalUdc.CopyTo(originalLcUdc[1..]);

            // Encrypt the padded clear text data
            var encryptedData = originalLcUdc
                .PadDataForDes()
                .EncryptTripleDesCbc(_scpData.SessionKeys.Enc, Constants.ICV);

            // Final APDU data = encrypted data | CMAC
            cApdu.Udc = new byte[encryptedData.Length + macLength];
            encryptedData.CopyTo(cApdu.Udc, 0);
            mac.CopyTo(cApdu.Udc.AsSpan(encryptedData.Length));

            return cApdu;
        }
    }
}
