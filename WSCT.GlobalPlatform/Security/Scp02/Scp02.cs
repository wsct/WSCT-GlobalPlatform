using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform.Security.Cryptography;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Security.Scp02;

internal class Scp02 : ISecureChannelProtocol
{
    /// <summary>
    /// Instance shared with the <see cref="GlobalPlatformCard"/> instance.
    /// </summary>
    private readonly SecureChannelData _scpData;
    private byte[] _lastCMac = [.. Constants.ICV];

    public Scp02SubIdentifier SubIdentifier { get; init; }

    public Scp02(SecureChannelData scpData)
    {
        GlobalPlatformException.ThrowIfNull(scpData);

        _scpData = scpData;

        SubIdentifier = new Scp02SubIdentifier(scpData.ScpDetails.Options);
    }

    /// <inheritdoc />
    public bool AuthenticateCard()
    {
        GlobalPlatformException.ThrowIfNull(_scpData.SessionKeys, "Session keys missing: Call GenerateSessionKeys(...) first");
        GlobalPlatformException.ThrowIfNull(_scpData.CardChallenge, "Card challenge missing: Call ProcessInitializeUpdate(...) first");
        GlobalPlatformException.ThrowIfNull(_scpData.HostChallenge, "Host challenge missing: Call ProcessInitializeUpdate(...) first");
        GlobalPlatformException.ThrowIfNull(_scpData.CardCryptogram, "Card cryptogram missing: Call ProcessInitializeUpdate(...) first");

        var cardCryptogram = Scp02Algorithms
            .GenerateCardCryptogram(_scpData.SessionKeys.Enc, _scpData.CardChallenge, _scpData.HostChallenge);

        var cardAuthenticationResult = cardCryptogram.SequenceEqual(_scpData.CardCryptogram);

        var hostCryptogram = Scp02Algorithms
            .GenerateHostCryptogram(_scpData.SessionKeys.Enc, _scpData.CardChallenge, _scpData.HostChallenge);

        _scpData.ParseHostCryptogram(hostCryptogram);

        return cardAuthenticationResult;
    }

    /// <inheritdoc />
    public SessionKeys GenerateSessionKeys()
    {
        GlobalPlatformException.ThrowIfNull(_scpData.Keys);
        GlobalPlatformException.ThrowIfNull(_scpData.CardChallenge, "Card challenge missing: Call ProcessInitializeUpdate(...) first");

        if (SubIdentifier.UseThreeKeys)
        {
            return Scp02Algorithms
                .GenerateSessionKeys(_scpData.Keys, _scpData.CardChallenge[0..2]);
        }
        else
        {
            // TODO
            throw new NotImplementedException("1 Secure Channel base key not yet implemented");
        }
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

        GlobalPlatformException.ThrowIfNull(_scpData.SessionKeys);

        _lastCMac = Constants.ICV;

        cApdu.Cla |= 0x04;
        cApdu.Lc += 8;

        var mac = Scp02Algorithms
            .GenerateCMac(_scpData.SessionKeys.CMac, _lastCMac, cApdu.BinaryCommand);

        _lastCMac = mac;

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
        GlobalPlatformException.ThrowIfNull(_scpData.SessionKeys);

        if ((_scpData.SecurityLevel & SecurityLevel.CMac) == 0)
        {
            return cApdu;
        }

        if (cApdu.HasLc is false)
        {
            cApdu.Udc = [];
        }

        if (SubIdentifier.UseCMacOnUnmodifiedApdu is false)
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
        if (SubIdentifier.UseIcvEncryptionForCMacSession)
        {
            // IV is obtained by encrypting LastCMac using first half of CMac session Key and LastCMac itself as the IV
            iv = _lastCMac
               .EncryptDesEcb(_scpData.SessionKeys.CMac.AsSpan(0, 8).ToArray(), _lastCMac);
        }
        else
        {
            iv = _lastCMac;
        }

        // Calculate the C-APDU C-MAC
        var mac = Scp02Algorithms
            .GenerateCMac(_scpData.SessionKeys.CMac, iv, cApdu.BinaryCommand);

        _lastCMac = mac;

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

        if (SubIdentifier.UseCMacOnUnmodifiedApdu is true)
        {
            cApdu.Cla |= 0x04;
            cApdu.Lc += 8;
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

        var dataLength = cApdu.HasLc ? (int)cApdu.Lc : 0;
        if (dataLength == 0)
        {
            return cApdu;
        }

        // Isolate clear text data and CMAC
        var macLength = (_scpData.SecurityLevel & SecurityLevel.CMac) == 0 ? 0 : 8;
        dataLength -= macLength;

        var udc = cApdu.Udc.AsSpan();
        var data = cApdu.Udc.AsSpan(0, dataLength);
        var mac = cApdu.Udc.AsSpan(udc.Length - macLength);

        // Encrypt the padded clear text data
        var encryptedData = data
            .PadDataForDes()
            .EncryptTripleDesCbc(_scpData.SessionKeys.Enc, Constants.ICV);

        // UDC = encrypted data | CMAC
        cApdu.Udc = new byte[encryptedData.Length + macLength];
        encryptedData.CopyTo(cApdu.Udc, 0);
        mac.CopyTo(cApdu.Udc.AsSpan(encryptedData.Length));

        return cApdu;
    }
}
