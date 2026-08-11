using WSCT.GlobalPlatform.Security.Cryptography;

namespace WSCT.GlobalPlatform.Security.Scp03;

internal class Scp03Algorithms
{
    public static SessionKeys GenerateSessionKeys(Keys keys, byte[] hostChallenge, byte[] cardChallenge)
    {
        var enc = GenerateSessionKey(keys.Enc, 0x04, hostChallenge, cardChallenge);
        var cmac = GenerateSessionKey(keys.Mac, 0x06, hostChallenge, cardChallenge);
        var rmac = GenerateSessionKey(keys.Mac, 0x07, hostChallenge, cardChallenge);

        return new SessionKeys(cmac, rmac, enc, []);
    }

    /// <summary>
    /// Generates a session key using the provided master key, label, context, and desired key length in bytes.
    /// </summary>
    /// <remarks>
    /// Reference: GPC_2.3_D_SCP03v1.2_PublicRelease.pdf §4.1.5.</br>
    /// </remarks>
    /// <param name="masterKey"></param>
    /// <param name="label">1-byte derivation constant</param>
    /// <param name="context">Concatenation of host and card challenges</param>
    /// <param name="keyLengthInBytes"></param>
    /// <returns></returns>
    public static byte[] GenerateSessionKey(byte[] masterKey, byte constant, ReadOnlySpan<byte> hostChallenge, ReadOnlySpan<byte> cardChallenge)
    {
        var keyLength = masterKey.Length;

        var derivationData = new byte[16 + hostChallenge.Length + cardChallenge.Length];

        // A 12 - byte “label” consisting of 11 bytes with value '00' followed by a 1 - byte derivation constant as defined below.
        derivationData[11] = constant;
        // A 1-byte “separation indicator” with value '00'.
        derivationData[12] = 0x00;
        // A 2 - byte integer “L” specifying the length in bits of the derived data (value '0040', '0080', '00C0', or '0100').
        derivationData[13] = 00;
        derivationData[14] = (byte)(keyLength * 8);
        // A 1 - byte counter “i” as specified in the KDF (which may take the values '01' or '02'; value '02' is used when “L” takes the values '00C0' and '0100', i.e.when the PRF of the KDF is to be called twice to generate enough derived data).
        derivationData[15] = 0x01;
        // The “context” parameter of the KDF. Its content is further specified in the sections below applying the data derivation scheme.
        hostChallenge.CopyTo(derivationData.AsSpan(16));
        cardChallenge.CopyTo(derivationData.AsSpan(16 + hostChallenge.Length));

        var cmac = derivationData.GenerateAesCmac(masterKey);

        return cmac;
    }

    public static byte[] GenerateCardCryptogram(byte[] sessionMacKey, byte[] hostChallenge, byte[] cardChallenge, byte sMode)
    {
        var data = new byte[32];
        // 11 zero bytes
        data[11] = 0x00; // Label: card authentication cryptogram generation
        data[12] = 0x00; // Separator
        data[13] = 0x00;
        data[14] = (byte)(sMode * 8); // Derived data length based on S8/16 Mode
        data[15] = 0x01; // counter “i” as specified in the KDF

        Array.Copy(hostChallenge, 0, data, 16, hostChallenge.Length);
        Array.Copy(cardChallenge, 0, data, 16 + sMode, cardChallenge.Length);

        var cmac = data.GenerateAesCmac(sessionMacKey);
        return cmac[..sMode];
    }

    public static byte[] GenerateHostCryptogram(byte[] sessionMacKey, byte[] hostChallenge, byte[] cardChallenge, byte sMode)
    {
        var data = new byte[32];
        // 11 zero bytes
        data[11] = 0x01; // Label: host authentication cryptogram generation
        data[12] = 0x00; // Separator
        data[13] = 0x00;
        data[14] = (byte)(sMode * 8); // Derived data length based on S8/16 Mode
        data[15] = 0x01; // counter “i” as specified in the KDF

        Array.Copy(hostChallenge, 0, data, 16, hostChallenge.Length);
        Array.Copy(cardChallenge, 0, data, 16 + sMode, cardChallenge.Length);

        var cmac = data.GenerateAesCmac(sessionMacKey);
        return cmac[..sMode];
    }

    public static byte[] GenerateCMac(byte[] sessionMacKey, byte[] chainingIcv, byte[] message)
    {
        byte[] data = [.. chainingIcv, .. message];

        var cmac = data.GenerateAesCmac(sessionMacKey);
        return cmac;
    }
}
