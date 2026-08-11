using WSCT.GlobalPlatform.Commands;
using WSCT.GlobalPlatform.Security.Cryptography;
using WSCT.ISO7816;

namespace WSCT.GlobalPlatform.Security.Scp03;

internal class Scp03 : ISecureChannelProtocol
{
    private readonly SecureChannelData _scpData;
    private byte[] _lastCMac = new byte[16];
    private long _encryptionCounter = 0;

    public Scp03SubIdentifier SubIdentifier { get; init; }

    public Scp03(SecureChannelData scpData)
    {
        GlobalPlatformException.ThrowIfNull(scpData);

        _scpData = scpData;
        SubIdentifier = new Scp03SubIdentifier(scpData.ScpDetails.Options);
    }

    /// <inheritdoc />
    public bool AuthenticateCard()
    {
        GlobalPlatformException.ThrowIfNull(_scpData.SessionKeys, "Session keys missing: Call GenerateSessionKeys(...) first");
        GlobalPlatformException.ThrowIfNull(_scpData.CardChallenge, "Card challenge missing: Call ProcessInitializeUpdate(...) first");
        GlobalPlatformException.ThrowIfNull(_scpData.HostChallenge, "Host challenge missing: Call ProcessInitializeUpdate(...) first");
        GlobalPlatformException.ThrowIfNull(_scpData.CardCryptogram, "Card cryptogram missing: Call ProcessInitializeUpdate(...) first");

        var cardCryptogram = Scp03Algorithms.GenerateCardCryptogram(_scpData.SessionKeys.CMac, _scpData.HostChallenge, _scpData.CardChallenge, 8);
        var cardAuthenticationResult = cardCryptogram.SequenceEqual(_scpData.CardCryptogram);

        var hostCryptogram = Scp03Algorithms.GenerateHostCryptogram(_scpData.SessionKeys.CMac, _scpData.HostChallenge, _scpData.CardChallenge, 8);
        _scpData.ParseHostCryptogram(hostCryptogram);

        return cardAuthenticationResult;
    }

    /// <inheritdoc />
    public SessionKeys GenerateSessionKeys()
    {
        GlobalPlatformException.ThrowIfNull(_scpData.Keys);
        GlobalPlatformException.ThrowIfNull(_scpData.CardChallenge, "Card challenge missing: Call ProcessInitializeUpdate(...) first");
        GlobalPlatformException.ThrowIfNull(_scpData.HostChallenge, "Host challenge missing: Call ProcessInitializeUpdate(...) first");

        return Scp03Algorithms.GenerateSessionKeys(_scpData.Keys, _scpData.HostChallenge, _scpData.CardChallenge);
    }

    /// <inheritdoc />
    public ExternalAuthenticateCommand Wrap(ExternalAuthenticateCommand cApdu)
    {
        GlobalPlatformException.ThrowIfNull(_scpData.SessionKeys);

        _lastCMac = new byte[16]; // Last MAC / ICV is 16-byte long and is set to 0 for EXTERNAL AUTHENTICATION

        cApdu.Cla |= 0x04;
        cApdu.Lc += 8;

        var mac = Scp03Algorithms.GenerateCMac(_scpData.SessionKeys.CMac, _lastCMac, cApdu.BinaryCommand);

        _lastCMac = mac;

        var udc = new byte[cApdu.Lc];
        Array.Copy(cApdu.Udc, 0, udc, 0, cApdu.Lc - 8);
        Array.Copy(mac[..8], 0, udc, udc.Length - 8, 8);

        cApdu.Udc = udc;

        return cApdu;
    }

    /// <inheritdoc />
    public CommandAPDU Wrap(CommandAPDU cApdu)
    {
        if ((_scpData.SecurityLevel & SecurityLevel.CDecryption) != 0)
        {
            cApdu = WrapForCDec(cApdu);
        }

        if ((_scpData.SecurityLevel & SecurityLevel.CMac) != 0)
        {
            cApdu = WrapForCMac(cApdu);
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

        cApdu.Cla |= 0x04;
        cApdu.Lc = (uint)(cApdu.Udc.Length + 8);

        bool initiallyHasLe = cApdu.HasLe;
        uint le = 0;
        if (initiallyHasLe)
        {
            le = cApdu.Le;
            cApdu.HasLe = false;
        }

        var mac = Scp03Algorithms.GenerateCMac(_scpData.SessionKeys.CMac, _lastCMac, cApdu.BinaryCommand);

        _lastCMac = mac;

        var udc = new byte[cApdu.Udc.Length + 8];
        Array.Copy(cApdu.Udc, 0, udc, 0, cApdu.Udc.Length);
        Array.Copy(mac[..8], 0, udc, cApdu.Udc.Length, 8);

        cApdu.Udc = udc;
        cApdu.Lc = (uint)cApdu.Udc.Length;

        if (initiallyHasLe)
        {
            cApdu.Le = le;
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

        // From the GP specification: No encryption shall be applied to a command where there is no command data field. In this case, the encryption counter shall still be incremented as described above
        _encryptionCounter++;

        if (cApdu.HasLc is false || cApdu.Udc.Length == 0)
        {
            return cApdu;
        }

        // From the GP specification:
        // - The encryption counter’s binary value shall be left padded with zeroes to form a full block.
        // - This block shall be encrypted with S-ENC to produce the ICV for command encryption.
        var counterBytes = new byte[16];
        counterBytes[^1] = (byte)(_encryptionCounter & 0xFF);
        counterBytes[^2] = (byte)((_encryptionCounter >> 8) & 0xFF);
        counterBytes[^3] = (byte)((_encryptionCounter >> 16) & 0xFF);
        counterBytes[^4] = (byte)((_encryptionCounter >> 24) & 0xFF);
        var icv = counterBytes.EncryptAesEcb(_scpData.SessionKeys.Enc);

        var encryptedData = cApdu.Udc
            .PadDataForAes()
            .EncryptAesCbc(_scpData.SessionKeys.Enc, icv);

        cApdu.Udc = encryptedData;
        cApdu.Lc = (uint)cApdu.Udc.Length;

        return cApdu;
    }
}
