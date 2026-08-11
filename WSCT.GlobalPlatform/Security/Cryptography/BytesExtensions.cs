using System.Security.Cryptography;

namespace WSCT.GlobalPlatform.Security.Cryptography;

internal static class BytesExtensions
{
    #region >> EncryptDes *

    /// <summary>
    /// Encrypts the <paramref name="input"/> using <paramref name="des"/> instance.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="des">DES instance.</param>
    /// <returns>Encrypted data.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public static byte[] EncryptDes(this byte[] input, DES des)
    {
        _ = input ?? throw new ArgumentNullException(nameof(input));
        _ = des ?? throw new ArgumentNullException(nameof(des));

        using var encryptor = des.CreateEncryptor();

        return encryptor.TransformFinalBlock(input, 0, input.Length);
    }

    /// <summary>
    /// Encrypts the <paramref name="input"/> using DES-CBC algorithm with <paramref name="key"/> and <paramref name="iv"/>.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="key">DES key.</param>
    /// <param name="iv">Initialization vector.</param>
    /// <returns>Encrypted data.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public static byte[] EncryptDesCbc(this byte[] input, byte[] key, byte[] iv)
    {
        _ = key ?? throw new ArgumentNullException(nameof(key));
        _ = iv ?? throw new ArgumentNullException(nameof(iv));

        using var des = DES.Create();
        des.Key = key;
        des.IV = iv;
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.None;

        return input.EncryptDes(des);
    }

    /// <summary>
    /// Encrypts the <paramref name="input"/> using DES-ECB algorithm with <paramref name="key"/> and <paramref name="iv"/>.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="key">DES key.</param>
    /// <param name="iv">Initialization vector.</param>
    /// <returns>Encrypted data.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public static byte[] EncryptDesEcb(this byte[] input, byte[] key, byte[] iv)
    {
        _ = key ?? throw new ArgumentNullException(nameof(key));
        _ = iv ?? throw new ArgumentNullException(nameof(iv));

        using var des = DES.Create();
        des.Key = key;
        des.IV = iv;
        des.Mode = CipherMode.ECB;
        des.Padding = PaddingMode.None;

        return input.EncryptDes(des);
    }

    #endregion

    #region >> EncryptTripleDes *

    /// <summary>
    /// Encrypts the <paramref name="input"/> using <paramref name="tripleDes"/> instance.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="tripleDes">3DES instance.</param>
    /// <returns>Encrypted data.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public static byte[] EncryptTripleDes(this byte[] input, TripleDES tripleDes)
    {
        _ = input ?? throw new ArgumentNullException(nameof(input));
        _ = tripleDes ?? throw new ArgumentNullException(nameof(tripleDes));

        using var encryptor = tripleDes.CreateEncryptor();

        return encryptor.TransformFinalBlock(input, 0, input.Length);
    }

    /// <summary>
    /// Encrypts the <paramref name="input"/> using 3DES-CBC algorithm with <paramref name="key"/> and <paramref name="iv"/>.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="key">3DES key.</param>
    /// <param name="iv">Initialization vector.</param>
    /// <returns>Encrypted data.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public static byte[] EncryptTripleDesCbc(this byte[] input, byte[] key, byte[] iv)
    {
        _ = key ?? throw new ArgumentNullException(nameof(key));
        _ = iv ?? throw new ArgumentNullException(nameof(iv));

        using var tripleDes = TripleDES.Create();
        tripleDes.Key = key;
        tripleDes.IV = iv;
        tripleDes.Mode = CipherMode.CBC;
        tripleDes.Padding = PaddingMode.None;

        return input.EncryptTripleDes(tripleDes);
    }

    /// <summary>
    /// Encrypts the <paramref name="input"/> using 3DES-ECB algorithm with <paramref name="key"/> and <paramref name="iv"/>.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="key">3DES key.</param>
    /// <param name="iv">Initialization vector.</param>
    /// <returns>Encrypted data.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public static byte[] EncryptTripleDesEcb(this byte[] input, byte[] key, byte[] iv)
    {
        _ = key ?? throw new ArgumentNullException(nameof(key));
        _ = iv ?? throw new ArgumentNullException(nameof(iv));

        using var tripleDes = TripleDES.Create();
        tripleDes.Key = key;
        tripleDes.IV = iv;
        tripleDes.Mode = CipherMode.ECB;
        tripleDes.Padding = PaddingMode.None;

        return input.EncryptTripleDes(tripleDes);
    }

    #endregion

    #region >> GenerateDesMac *

    /// <summary>
    /// Computes the MAC of <paramref name="inputCount"/> bytes of <paramref name="input"/> from <paramref name="inputOffset"/> using <paramref name="des"/> instance.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="des">DES instance.</param>
    /// <param name="inputOffset">Initial offset in <paramref name="input"/>.</param>
    /// <param name="inputCount">Number of bytes to use to compute the MAC from<paramref name="inputOffset"/>.</param>
    /// <returns>MAC value.</returns>
    public static byte[] GenerateDesMac(this byte[] input, DES des, int inputOffset, int inputCount)
    {
        using var encryptor = des.CreateEncryptor();

        var mac = new byte[8];
        des.IV.CopyTo(mac, 0);

        for (var i = 0; i < (inputCount - inputOffset) / 8; i++)
        {
            _ = encryptor.TransformBlock(input, inputOffset + 8 * i, 8, mac, 0);
        }

        return mac;
    }

    /// <summary>
    /// Computes the MAC of <paramref name="inputCount"/> bytes of <paramref name="input"/> from <paramref name="inputOffset"/> using DES-CBC with <paramref name="key"/> and <paramref name="iv"/>.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="key">DES key.</param>
    /// <param name="iv">Initialization vector.</param>
    /// <param name="inputOffset">Initial offset in <paramref name="input"/>.</param>
    /// <param name="inputCount">Number of bytes to use to compute the MAC from<paramref name="inputOffset"/>.</param>
    /// <returns>MAC value.</returns>
    public static byte[] GenerateDesMacCbc(this byte[] input, byte[] key, byte[] iv, int inputOffset, int inputCount)
    {
        using var des = DES.Create();
        des.Key = key;
        des.IV = iv;
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.None;

        return input.GenerateDesMac(des, inputOffset, inputCount);
    }

    /// <summary>
    /// Computes the MAC of <paramref name="inputCount"/> bytes of <paramref name="input"/> from <paramref name="inputOffset"/> using DES-ECB with <paramref name="key"/> and <paramref name="iv"/>.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="key">DES key.</param>
    /// <param name="iv">Initialization vector.</param>
    /// <param name="inputOffset">Initial offset in <paramref name="input"/>.</param>
    /// <param name="inputCount">Number of bytes to use to compute the MAC from<paramref name="inputOffset"/>.</param>
    /// <returns>MAC value.</returns>
    public static byte[] GenerateDesMacEcb(this byte[] input, byte[] key, byte[] iv, int inputOffset, int inputCount)
    {
        using var des = DES.Create();
        des.Key = key;
        des.IV = iv;
        des.Mode = CipherMode.ECB;
        des.Padding = PaddingMode.None;

        return input.GenerateDesMac(des, inputOffset, inputCount);
    }

    #endregion

    #region >> GenerateTripleDesMac *

    /// <summary>
    /// Computes the MAC of <paramref name="inputCount"/> bytes of <paramref name="input"/> from <paramref name="inputOffset"/> using <paramref name="tripleDES"/> instance.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="tripleDes">3DES instance.</param>
    /// <param name="inputOffset">Initial offset in <paramref name="input"/>.</param>
    /// <param name="inputCount">Number of bytes to use to compute the MAC from<paramref name="inputOffset"/>.</param>
    /// <returns>MAC value.</returns>
    public static byte[] GenerateTripleDesMac(this byte[] input, TripleDES tripleDes, int inputOffset, int inputCount)
    {
        _ = tripleDes ?? throw new ArgumentNullException(nameof(tripleDes));

        using var encryptor = tripleDes.CreateEncryptor();

        var mac = new byte[8];
        tripleDes.IV.CopyTo(mac, 0);

        for (var i = 0; i < (inputCount - inputOffset) / 8; i++)
        {
            _ = encryptor.TransformBlock(input, inputOffset + 8 * i, 8, mac, 0);
        }

        return mac;
    }


    /// <summary>
    /// Computes the MAC of <paramref name="input"/> using 3DES-CBC with <paramref name="key"/> and <paramref name="iv"/>.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="key">3DES key.</param>
    /// <param name="iv">Initialization vector.</param>
    /// <returns>MAC value.</returns>
    public static byte[] GenerateTripleDesMacCbc(this byte[] input, byte[] key, byte[] iv)
    {
        return input.GenerateTripleDesMacCbc(key, iv, 0, input.Length);
    }

    /// <summary>
    /// Computes the MAC of <paramref name="inputCount"/> bytes of <paramref name="input"/> from <paramref name="inputOffset"/> using 3DES-CBC with <paramref name="key"/> and <paramref name="iv"/>.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="key">3DES key.</param>
    /// <param name="iv">Initialization vector.</param>
    /// <param name="inputOffset">Initial offset in <paramref name="input"/>.</param>
    /// <param name="inputCount">Number of bytes to use to compute the MAC from<paramref name="inputOffset"/>.</param>
    /// <returns>MAC value.</returns>
    public static byte[] GenerateTripleDesMacCbc(this byte[] input, byte[] key, byte[] iv, int inputOffset, int inputCount)
    {
        _ = key ?? throw new ArgumentNullException(nameof(key));
        _ = iv ?? throw new ArgumentNullException(nameof(iv));

        using var tripleDes = TripleDES.Create();
        tripleDes.Key = key;
        tripleDes.IV = iv;
        tripleDes.Mode = CipherMode.CBC;
        tripleDes.Padding = PaddingMode.None;

        return input.GenerateTripleDesMac(tripleDes, inputOffset, inputCount);
    }

    /// <summary>
    /// Computes the MAC of <paramref name="input"/> using 3DES-ECB with <paramref name="key"/> and <paramref name="iv"/>.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="key">3DES key.</param>
    /// <param name="iv">Initialization vector.</param>
    /// <returns>MAC value.</returns>
    public static byte[] GenerateTripleDesMacEcb(this byte[] input, byte[] key, byte[] iv)
    {
        return input.GenerateTripleDesMacEcb(key, iv, 0, input.Length);
    }

    /// <summary>
    /// Computes the MAC of <paramref name="inputCount"/> bytes of <paramref name="input"/> from <paramref name="inputOffset"/> using 3DES-ECB with <paramref name="key"/> and <paramref name="iv"/>.
    /// </summary>
    /// <param name="input">Clear text data.</param>
    /// <param name="key">3DES key.</param>
    /// <param name="iv">Initialization vector.</param>
    /// <param name="inputOffset">Initial offset in <paramref name="input"/>.</param>
    /// <param name="inputCount">Number of bytes to use to compute the MAC from<paramref name="inputOffset"/>.</param>
    /// <returns>MAC value.</returns>
    public static byte[] GenerateTripleDesMacEcb(this byte[] input, byte[] key, byte[] iv, int inputOffset, int inputCount)
    {
        _ = key ?? throw new ArgumentNullException(nameof(key));
        _ = iv ?? throw new ArgumentNullException(nameof(iv));

        using var tripleDes = TripleDES.Create();
        tripleDes.Key = key;
        tripleDes.IV = iv;
        tripleDes.Mode = CipherMode.ECB;
        tripleDes.Padding = PaddingMode.None;

        return input.GenerateTripleDesMac(tripleDes, inputOffset, inputCount);
    }

    #endregion

    #region >> PadDataForDes

    /// <summary>
    /// Returns a new array consisting of <paramref name="input"/> bytes and a DES padding ('80 00 ... 00') up to multiple of 8 bytes.
    /// </summary>
    /// <param name="input">Input data to be padded.</param>
    /// <returns>The padded data.</returns>
    public static byte[] PadDataForDes(this byte[] input)
    {
        return input.AsSpan()
            .PadDataForDes();
    }

    /// <summary>
    /// Returns a new array consisting of <paramref name="input"/> bytes and a DES padding ('80 00 ... 00') up to multiple of 8 bytes.
    /// </summary>
    /// <param name="input">Input data to be padded.</param>
    /// <returns>The padded data.</returns>
    public static byte[] PadDataForDes(this Span<byte> input)
    {
        var lastInputBlockLength = input.Length % 8;

        var output = new byte[8 * (input.Length / 8 + 1)];
        input.CopyTo(output);
        Array.Copy(Constants.Padding, 0, output, input.Length, 8 - lastInputBlockLength);

        return output;
    }

    #endregion

    #region >> PadDataForDes

    /// <summary>
    /// Returns a new array consisting of <paramref name="input"/> bytes and AES padding ('80 00 ... 00') up to multiple of 16 bytes.
    /// </summary>
    /// <param name="input">Input data to be padded.</param>
    /// <returns>The padded data.</returns>
    public static byte[] PadDataForAes(this byte[] input)
    {
        return input.AsSpan()
            .PadDataForAes();
    }

    /// <summary>
    /// Returns a new array consisting of <paramref name="input"/> bytes and AES padding ('80 00 ... 00') up to multiple of 16 bytes.
    /// </summary>
    /// <param name="input">Input data to be padded.</param>
    /// <returns>The padded data.</returns>
    public static byte[] PadDataForAes(this Span<byte> input)
    {
        var lastInputBlockLength = input.Length % 16;

        var output = new byte[16 * (input.Length / 16 + 1)];
        input.CopyTo(output);
        Array.Copy(Constants.AesPadding, 0, output, input.Length, 16 - lastInputBlockLength);

        return output;
    }

    #endregion

    #region >> EncryptAes *

    /// <summary>
    /// Encrypts <paramref name="input"/> using AES-CBC with <paramref name="key"/> and <paramref name="iv"/>.
    /// </summary>
    public static byte[] EncryptAesCbc(this byte[] input, byte[] key, byte[] iv)
    {
        _ = input ?? throw new ArgumentNullException(nameof(input));
        _ = key ?? throw new ArgumentNullException(nameof(key));
        _ = iv ?? throw new ArgumentNullException(nameof(iv));

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(input, 0, input.Length);
    }

    /// <summary>
    /// Encrypts <paramref name="input"/> using AES-ECB with <paramref name="key"/>.
    /// </summary>
    public static byte[] EncryptAesEcb(this byte[] input, byte[] key)
    {
        _ = input ?? throw new ArgumentNullException(nameof(input));
        _ = key ?? throw new ArgumentNullException(nameof(key));

        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(input, 0, input.Length);
    }

    #endregion

    #region >> GenerateAesCmac

    /// <summary>
    /// Generates AES-CMAC (NIST SP 800-38B) over <paramref name="inputCount"/> bytes from <paramref name="inputOffset"/> using <paramref name="key"/>.
    /// </summary>
    public static byte[] GenerateAesCmac(this byte[] input, byte[] key)
    {
        _ = input ?? throw new ArgumentNullException(nameof(input));
        _ = key ?? throw new ArgumentNullException(nameof(key));

        // Subkey Generation
        // 1. Let L = CIPHK(0b).
        var L = new byte[16].EncryptAesEcb(key);
        // 2. If MSB1(L) = 0, then K1 = L << 1; Else K1 = (L << 1) ⊕ Rb;
        var k1 = LeftShiftOneBit(L);
        if ((L[0] & 0x80) != 0)
        {
            k1[15] ^= 0x87; // R_128 = 0^120 10000111
        }
        // 3. If MSB1(K1) = 0, then K2 = K1 << 1; Else K2 = (K1 << 1) ⊕ Rb;
        var k2 = LeftShiftOneBit(k1);
        if ((k1[0] & 0x80) != 0)
        {
            k2[15] ^= 0x87;
        }

        // MAC Generation
        var inputCount = input.Length;
        // 2. If Mlen = 0, let n = 1; else, let n = Mlen/b. 
        var blockCount = (inputCount + 15) / 16;

        if (blockCount == 0)
        {
            blockCount = 1;
        }

        bool isCompleteBlock = (inputCount > 0) && (inputCount % 16 == 0);

        byte[] lastBlock = new byte[16];
        if (isCompleteBlock)
        {
            Array.Copy(input, (blockCount - 1) * 16, lastBlock, 0, 16);
            XorBlock(lastBlock, k1);
        }
        else
        {
            int rem = inputCount % 16;
            if (rem > 0)
            {
                Array.Copy(input, (blockCount - 1) * 16, lastBlock, 0, rem);
            }
            lastBlock[rem] = 0x80;
            XorBlock(lastBlock, k2);
        }

        byte[] X = new byte[16];
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        using var encryptor = aes.CreateEncryptor();

        // For i = 1 to n, let Ci = CIPHK(Ci-1 ⊕ Mi). 
        byte[] block = new byte[16];
        for (int i = 0; i < blockCount - 1; i++)
        {
            Array.Copy(input, i * 16, block, 0, 16);
            XorBlock(X, block);
            X = encryptor.TransformFinalBlock(X, 0, 16);
        }

        XorBlock(X, lastBlock);
        return encryptor.TransformFinalBlock(X, 0, 16);
    }

    private static byte[] LeftShiftOneBit(ReadOnlySpan<byte> input)
    {
        byte[] output = new byte[input.Length];
        byte carry = 0;
        for (int i = input.Length - 1; i >= 0; i--)
        {
            ushort val = (ushort)((input[i] << 1) | carry);
            output[i] = (byte)(val & 0xFF);
            carry = (byte)((val >> 8) & 0x01);
        }
        return output;
    }

    private static void XorBlock(Span<byte> target, byte[] operand)
    {
        for (int i = 0; i < target.Length; i++)
        {
            target[i] ^= operand[i];
        }
    }

    #endregion
}

